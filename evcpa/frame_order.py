"""将多帧协议解析结果汇总为充电订单分析。"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from evcpa.models import AnalysisResult, FieldItem
from evcpa.multi_order import (
    build_multi_order_choice,
    combine_filter,
    order_matches_filter,
)

# 心跳等链路帧：计入帧数，不参与订单字段汇总
_LINK_FRAMES = {"0x03", "0x04", "0x0C", "0x8C", "0x0005"}

_ORDER_FRAME_HINTS = {
    "0x13",
    "0x15",
    "0x17",
    "0x19",
    "0x21",
    "0x31",
    "0x32",
    "0x33",
    "0x34",
    "0x35",
    "0x36",
    "0x3B",
    "0x3D",
    "0x40",
    "0x41",
    "0x42",
    "0x06",
    "0x07",
    "0x08",
    "0x09",
    "0x84",
    "0x85",
    "0x86",
    "0x87",
    "0x88",
    "0x4000",
    "0x4001",
    "0x4002",
    "0x4003",
    "0x4004",
    "0x4006",
    "0x4007",
}

_BILL_FRAMES = {"0x3D", "0x3B", "0x08", "0x4006"}
_START_FRAMES = {"0x34", "0x31", "0x33", "0x06", "0x86", "0x04", "0x84", "0x4000", "0x4001"}
_STOP_FRAMES = {"0x36", "0x35", "0x19", "0x07", "0x87", "0x05", "0x85", "0x4002", "0x4003"}
_REALTIME_FRAMES = {"0x13", "0x09", "0x2002", "0x4004"}


def _order_duration_text(start: Any, end: Any) -> str:
    """由起止时间估算充电时长。"""
    if not start or not end or start == "-" or end == "-":
        return "-"
    from datetime import datetime
    import re

    def _parse(v: Any) -> datetime | None:
        s = str(v).strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return datetime.strptime(s[:19], fmt)
            except ValueError:
                continue
        m = re.match(r"(\d{4})年(\d{1,2})月(\d{1,2})日\s+(\d{2}:\d{2}:\d{2})", s)
        if m:
            try:
                return datetime.strptime(
                    f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d} {m.group(4)}",
                    "%Y-%m-%d %H:%M:%S",
                )
            except ValueError:
                return None
        return None

    a, b = _parse(start), _parse(end)
    if not a or not b:
        return "-"
    sec = int((b - a).total_seconds())
    if sec < 0:
        return "-"
    return f"约 {round(sec / 60)} 分钟（{sec} 秒）"


def _field_map(result: AnalysisResult) -> dict[str, FieldItem]:
    return {f.name: f for f in result.fields}


def _get(fmap: dict[str, FieldItem], *names: str) -> Any:
    for n in names:
        if n in fmap and fmap[n].value not in (None, "", "-"):
            return fmap[n].value
    return None


def _get_meaning(fmap: dict[str, FieldItem], *names: str) -> str | None:
    for n in names:
        if n in fmap and fmap[n].meaning:
            return str(fmap[n].meaning)
    return None


def _ft(result: AnalysisResult) -> str:
    return (result.frame_type or "").upper()


def is_order_related(result: AnalysisResult) -> bool:
    ft = _ft(result)
    if ft in {x.upper() for x in _ORDER_FRAME_HINTS}:
        return True
    fmap = _field_map(result)
    return any(k in fmap for k in ("trade_no", "charge_energy", "soc", "stop_reason", "start_way"))


def has_order_signal(results: list[AnalysisResult]) -> bool:
    useful = [r for r in results if _ft(r) not in {x.upper() for x in _LINK_FRAMES}]
    if not useful:
        return False
    if len(useful) == 1:
        return is_order_related(useful[0]) or _ft(useful[0]) in {x.upper() for x in _BILL_FRAMES}
    return any(is_order_related(r) for r in useful)


def _empty_order() -> dict[str, Any]:
    return {
        "trade_no": None,
        "pile": None,
        "gun": None,
        "start_way": None,
        "stop_reason": None,
        "vin": None,
        "card": None,
        "start_time": None,
        "end_time": None,
        "bill_energy": None,
        "bill_money": None,
        "socs": [],
        "volts": [],
        "currs": [],
        "powers": [],
        "energies": [],
        "moneys": [],
        "frame_count": 0,
        "last_slots": {},
        "locked_slots": set(),
        "series_issues": [],
        "saw_charging_status": False,
        "saw_start_frame": False,
    }


def _valid_trade_no(tn: Any) -> str:
    if tn is None:
        return ""
    s = str(tn).strip()
    if not s or s == "-":
        return ""
    if set(s) <= {"0"}:
        return ""
    return s


def _absorb(order: dict[str, Any], r: AnalysisResult) -> None:
    fmap = _field_map(r)
    ft = _ft(r)
    order["frame_count"] += 1

    tn = _valid_trade_no(_get(fmap, "trade_no", "txn_id"))
    if tn:
        order["trade_no"] = tn
    order["pile"] = order["pile"] or _get(fmap, "pile_code", "device_id")
    g = _get(fmap, "gun_no")
    if g is not None:
        order["gun"] = g

    if ft in {x.upper() for x in _START_FRAMES} or not order["start_way"]:
        if ft == "0X34":
            order["start_way"] = order["start_way"] or "APP远程启机"
        elif ft == "0X31":
            order["start_way"] = order["start_way"] or (
                _get_meaning(fmap, "start_way") or "桩端申请启机"
            )
        else:
            sw = _get_meaning(fmap, "start_way", "charge_way", "txn_flag")
            if sw and sw not in {"0", "0x00", "无"} and "交易标识" not in sw:
                order["start_way"] = sw
            else:
                raw_sw = _get(fmap, "start_way", "txn_flag")
                if raw_sw not in (None, 0, "0", "0x00"):
                    order["start_way"] = order["start_way"] or str(raw_sw)

    if ft in {x.upper() for x in _STOP_FRAMES} or not order["stop_reason"]:
        sr = _get_meaning(fmap, "stop_reason", "fail_reason")
        if sr and sr not in {"无"}:
            order["stop_reason"] = sr
        elif isinstance(_get(fmap, "stop_reason"), int) and _get(fmap, "stop_reason") != 0:
            code = int(_get(fmap, "stop_reason"))
            order["stop_reason"] = sr or f"停止原因 0x{code:02X}"

    order["vin"] = order["vin"] or _get(fmap, "vin")
    if order["vin"] in (None, "未上报", ""):
        order["vin"] = None
    order["card"] = order["card"] or _get(fmap, "logic_card", "physical_card", "card_no", "account_or_card")
    order["start_time"] = order["start_time"] or _get(fmap, "start_time", "txn_time")
    et = _get(fmap, "end_time")
    if et:
        order["end_time"] = et

    soc = _get(fmap, "soc")
    if isinstance(soc, (int, float)) and ft in {x.upper() for x in _REALTIME_FRAMES | _BILL_FRAMES}:
        order["socs"].append(int(soc))
    for name in ("soc_start", "soc_end", "start_soc", "end_soc"):
        v = _get(fmap, name)
        if isinstance(v, (int, float)):
            order["socs"].append(int(v))

    volt = _get(fmap, "output_voltage")
    if isinstance(volt, (int, float)) and ft in {x.upper() for x in _REALTIME_FRAMES}:
        order["volts"].append(float(volt))
    curr = _get(fmap, "output_current")
    if isinstance(curr, (int, float)) and ft in {x.upper() for x in _REALTIME_FRAMES}:
        order["currs"].append(float(curr))
        if order["volts"]:
            order["powers"].append(round(order["volts"][-1] * float(curr) / 1000.0, 3))
    pwr = _get(fmap, "output_power")
    if isinstance(pwr, (int, float)):
        order["powers"].append(float(pwr))

    energy = _get(fmap, "charge_energy", "total_energy", "loss_energy")
    money = _get(fmap, "charged_amount", "charge_money", "total_money")

    def _sane_kwh(v: Any) -> bool:
        return isinstance(v, (int, float)) and 0 < float(v) < 500

    def _sane_money(v: Any) -> bool:
        return isinstance(v, (int, float)) and 0 <= float(v) < 5000

    if ft in {x.upper() for x in _BILL_FRAMES}:
        # 0x3B 旧版布局与 V1.7 0x3D 不完全一致，异常值则回退过程采样
        if _sane_kwh(energy):
            order["bill_energy"] = float(energy)
        if _sane_money(money) and float(money) > 0:
            order["bill_money"] = float(money)
    elif ft in {x.upper() for x in _REALTIME_FRAMES}:
        if isinstance(energy, (int, float)) and float(energy) >= 0:
            e = float(energy)
            if order["energies"] and e + 1e-6 < order["energies"][-1]:
                order["series_issues"].append(
                    f"过程总电量回落：{order['energies'][-1]} → {e} kWh（{ft}）"
                )
            order["energies"].append(e)
        if isinstance(money, (int, float)) and float(money) >= 0:
            order["moneys"].append(float(money))
        # 分时槽位：tou_*_energy / slot_*_energy
        slots: dict[str, float] = {}
        for name, item in fmap.items():
            if not name.endswith("_energy"):
                continue
            if not (name.startswith("tou_") or name.startswith("slot_")):
                continue
            if name.endswith("_price") or name == "slot_energy_sum":
                continue
            val = item.value if hasattr(item, "value") else item
            try:
                slots[name] = float(val)
            except (TypeError, ValueError):
                continue
        if slots:
            prev = order.get("last_slots") or {}
            locked: set[str] = order.get("locked_slots") or set()
            growing = {
                k for k, v in slots.items() if k in prev and v > prev[k] + 1e-6
            }
            total_up = bool(order["energies"] and len(order["energies"]) >= 2 and order["energies"][-1] > order["energies"][-2] + 1e-6)
            for k in locked:
                if k in slots and k in prev and abs(slots[k] - prev[k]) > 1e-6:
                    order["series_issues"].append(
                        f"非所属时段分时“{k}”变动：{prev[k]} → {slots[k]} kWh"
                    )
            for k, v in slots.items():
                if k in prev and v + 1e-6 < prev[k]:
                    order["series_issues"].append(
                        f"分时“{k}”回落：{prev[k]} → {v} kWh"
                    )
            if total_up or growing:
                for k, pv in prev.items():
                    if k in growing:
                        continue
                    if pv > 1e-6:
                        locked.add(k)
            order["locked_slots"] = locked
            order["last_slots"] = slots

        # 枪口充电中
        for name, item in fmap.items():
            if "status" not in name:
                continue
            meaning = ""
            if hasattr(item, "meaning") and item.meaning:
                meaning = str(item.meaning)
            val = item.value if hasattr(item, "value") else item
            if meaning in {"充电中", "操作中"} or val == 2:
                order["saw_charging_status"] = True

    if ft in {x.upper() for x in _START_FRAMES}:
        order["saw_start_frame"] = True

    if not order["start_way"]:
        tf = _get_meaning(fmap, "txn_flag")
        if tf and "交易标识" not in tf:
            order["start_way"] = tf


def aggregate_frame_order(
    results: list[AnalysisResult],
    *,
    meta: dict[str, Any] | None = None,
    service_id: str | None = None,
    trade_no: str | None = None,
) -> dict[str, Any]:
    """多帧解析结果 → charging_report；多流水号时按订单分组汇总。

    未指定 service_id/trade_no 且识别到多笔订单时，返回 multi_order_choice 提示用户筛选。
    """
    meta = meta or {}
    filter_id = combine_filter(service_id, trade_no)
    protocol = results[0].protocol.value if results else "unknown"
    protocol_name = results[0].protocol_name if results else "未知"

    link_count = sum(1 for r in results if _ft(r) in {x.upper() for x in _LINK_FRAMES})
    useful = [r for r in results if _ft(r) not in {x.upper() for x in _LINK_FRAMES}]

    # 按流水号分组；无流水号的实时帧先挂到 pending，再按枪号贴近账单
    by_trade: dict[str, dict[str, Any]] = {}
    unassigned: list[AnalysisResult] = []

    for r in useful:
        fmap = _field_map(r)
        tn_s = _valid_trade_no(_get(fmap, "trade_no", "txn_id"))
        if tn_s:
            if tn_s not in by_trade:
                by_trade[tn_s] = _empty_order()
            _absorb(by_trade[tn_s], r)
        else:
            unassigned.append(r)

    # 无流水号帧：按枪号并入已有订单，否则单独一笔
    for r in unassigned:
        fmap = _field_map(r)
        gun = _get(fmap, "gun_no")
        target = None
        if gun is not None:
            for od in by_trade.values():
                if od.get("gun") == gun and _valid_trade_no(od.get("trade_no")):
                    target = od
                    break
        if target is None and len(by_trade) == 1:
            target = next(iter(by_trade.values()))
        if target is None:
            # 无有效流水号且无法归属：跳过纯 BMS/杂项，避免空订单
            ft = _ft(r)
            if ft not in {x.upper() for x in _REALTIME_FRAMES | _BILL_FRAMES | _START_FRAMES | _STOP_FRAMES}:
                continue
            key = f"__gun_{gun}" if gun is not None else "__unknown"
            if key not in by_trade:
                by_trade[key] = _empty_order()
            target = by_trade[key]
        _absorb(target, r)

    orders = []
    for key, od in by_trade.items():
        if not od["trade_no"] and key.startswith("__"):
            od["trade_no"] = "-"
        if od["bill_energy"] is None and od["energies"]:
            od["bill_energy"] = max(od["energies"])
        if od["bill_money"] is None and od["moneys"]:
            od["bill_money"] = max(od["moneys"])
        # 丢弃无流水号、无电量的空壳
        if not _valid_trade_no(od.get("trade_no")) and not od.get("bill_energy"):
            continue
        orders.append(od)

    # 稳定排序：真实流水号、有电量优先
    orders.sort(
        key=lambda o: (
            0 if _valid_trade_no(o.get("trade_no")) else 1,
            0 if (o.get("bill_energy") or 0) > 0 else 1,
            str(o.get("trade_no") or ""),
        )
    )

    pile = meta.get("pile") or next((o.get("pile") for o in orders if o.get("pile")), None)

    # 多订单且未指定筛选：先展示服务ID/流水号，提示用户选择后再解析
    if len(orders) > 1 and not filter_id:
        choice_orders = [
            {
                "trade_no": o.get("trade_no"),
                "service_id": o.get("service_id"),
                "gun": o.get("gun"),
                "energy": o.get("bill_energy"),
                "money": o.get("bill_money"),
                "start_way": o.get("start_way"),
                "stop_reason": o.get("stop_reason"),
            }
            for o in orders
        ]
        return build_multi_order_choice(
            choice_orders,
            protocol=protocol,
            protocol_name=protocol_name,
            pile=pile,
        )

    if filter_id:
        filtered = [o for o in orders if order_matches_filter(o, filter_id)]
        if not filtered:
            return {
                "mode": "charging_report",
                "protocol": protocol,
                "protocol_name": protocol_name,
                "confidence": 0.2,
                "valid": False,
                "summary": f"未找到服务ID/流水号 = {filter_id} 的订单，请确认填写是否正确。",
                "conclusion": f"未找到服务ID/流水号 = {filter_id} 的充电订单。",
                "verdict": "综合判断：筛选条件下无匹配订单，请核对服务ID或流水号。",
                "result_points": [
                    f"1. 已按服务ID/流水号「{filter_id}」筛选多帧报文。",
                    f"2. 共识别到 {len(orders)} 笔订单，但无一匹配该筛选条件。",
                    "3. 请核对输入，或留空后查看全部订单列表。",
                ],
                "report_text": (
                    "充电订单分析报告（协议抓包/多帧）\n\n"
                    f"筛选条件：服务ID/流水号 = {filter_id}\n\n"
                    "未找到匹配订单。"
                ),
                "fields": [
                    {"name": "筛选条件", "value": filter_id},
                    {"name": "报文内订单笔数", "value": str(len(orders))},
                    {"name": "匹配结果", "value": "无"},
                ],
                "warnings": [
                    {
                        "code": "SERVICE_NOT_FOUND",
                        "level": "warn",
                        "message": f"未找到服务ID/流水号 {filter_id}",
                    }
                ],
                "extras": {
                    "filtered": True,
                    "filter_id": filter_id,
                    "order_count": 0,
                    "orders": [
                        {
                            "trade_no": o.get("trade_no"),
                            "gun": o.get("gun"),
                            "energy": o.get("bill_energy"),
                            "money": o.get("bill_money"),
                        }
                        for o in orders
                    ],
                },
            }
        orders = filtered

    warnings: list[dict[str, Any]] = []
    for r in results:
        for w in r.warnings:
            if w.level == "error":
                warnings.append(
                    {"code": w.code, "level": w.level, "message": f"[{r.frame_type}] {w.message}"}
                )

    frame_brief = []
    type_counter: dict[str, int] = defaultdict(int)
    for r in results:
        ft = r.frame_type or "?"
        fn = r.frame_type_name or ft
        type_counter[f"{fn}（{ft}）"] += 1
    for name, cnt in sorted(type_counter.items(), key=lambda x: -x[1])[:20]:
        frame_brief.append(f"{name} ×{cnt}")

    points = [
        f"1. 共提取并解析 {len(results)} 帧（链路心跳 {link_count} 帧已计入但未参与业务汇总）。",
        f"2. 识别到 {len(orders)} 笔订单/会话；协议：{protocol_name}。",
    ]
    if meta.get("pile"):
        points.append(f"3. 日志桩号：{meta['pile']}。")

    for i, od in enumerate(orders, 1):
        prefix = f"订单{i}" if len(orders) > 1 else "订单"
        points.append(
            f"{3 + i}. {prefix} {od['trade_no'] or '-'}：枪{od['gun'] if od['gun'] is not None else '-'}，"
            f"电量 {od['bill_energy'] if od['bill_energy'] is not None else '-'} kWh，"
            f"费用 {od['bill_money'] if od['bill_money'] is not None else '-'} 元"
            + (f"，结束：{od['stop_reason']}" if od["stop_reason"] else "")
            + "。"
        )

    primary = next(
        (
            o
            for o in orders
            if (o.get("bill_energy") or 0) > 0 and _valid_trade_no(o.get("trade_no"))
        ),
        next((o for o in orders if _valid_trade_no(o.get("trade_no"))), orders[0] if orders else _empty_order()),
    )
    fields: list[dict[str, Any]] = [
        {"name": "充电桩编号", "value": primary.get("pile") or meta.get("pile") or "-"},
        {"name": "枪口号", "value": f"{primary['gun']} 枪" if primary.get("gun") is not None else "-"},
        {"name": "订单流水号", "value": primary.get("trade_no") or "-"},
        {"name": "启动时间", "value": primary.get("start_time") or "-"},
        {"name": "结束时间", "value": primary.get("end_time") or "-"},
        {
            "name": "充电时长",
            "value": _order_duration_text(primary.get("start_time"), primary.get("end_time")),
        },
        {
            "name": "实际充电电量",
            "value": f"{primary['bill_energy']} kWh" if primary.get("bill_energy") is not None else "-",
        },
        {
            "name": "费用合计",
            "value": f"{primary['bill_money']} 元" if primary.get("bill_money") is not None else "-",
        },
        {"name": "设备结束原因", "value": primary.get("stop_reason") or "-"},
        {"name": "启动方式", "value": primary.get("start_way") or next((o.get("start_way") for o in orders if o.get("start_way")), None) or "-"},
        {"name": "解析帧数", "value": str(len(results))},
        {"name": "订单笔数", "value": str(len(orders))},
        {"name": "帧类型统计", "value": "；".join(frame_brief) if frame_brief else "-"},
    ]
    for i, od in enumerate(orders, 1):
        prefix = f"订单{i}" if len(orders) > 1 else "订单"
        fields.extend(
            [
                {"name": f"{prefix}流水号", "value": od["trade_no"] or "-"},
                {"name": f"{prefix}枪口", "value": f"{od['gun']} 枪" if od["gun"] is not None else "-"},
                {"name": f"{prefix}启动方式", "value": od["start_way"] or "-"},
                {"name": f"{prefix}开始时间", "value": od["start_time"] or "-"},
                {"name": f"{prefix}结束时间", "value": od["end_time"] or "-"},
                {
                    "name": f"{prefix}电量",
                    "value": f"{od['bill_energy']} kWh" if od["bill_energy"] is not None else "-",
                },
                {
                    "name": f"{prefix}费用",
                    "value": f"{od['bill_money']} 元" if od["bill_money"] is not None else "-",
                },
                {"name": f"{prefix}结束原因", "value": od["stop_reason"] or "-"},
                {
                    "name": f"{prefix}SOC",
                    "value": f"{min(od['socs'])}% ~ {max(od['socs'])}%" if od["socs"] else "-",
                },
                {
                    "name": f"{prefix}电压",
                    "value": f"{min(od['volts']):.1f} ~ {max(od['volts']):.1f} V" if od["volts"] else "-",
                },
                {
                    "name": f"{prefix}电流",
                    "value": f"{min(od['currs']):.1f} ~ {max(od['currs']):.1f} A" if od["currs"] else "-",
                },
                {"name": f"{prefix}VIN", "value": od["vin"] or "-"},
            ]
        )

    has_bill = any(o.get("bill_energy") is not None for o in orders)
    valid = has_bill or any(o.get("trade_no") and o["trade_no"] != "-" for o in orders)

    # 过程电量递增 / 非所属时段固化 / 启动校验（协议多帧）
    series_issues: list[str] = []
    for od in orders:
        series_issues.extend(list(od.get("series_issues") or [])[:5])
    start_bits: list[str] = []
    start_ok_proto = True
    if primary.get("saw_start_frame") or primary.get("start_way"):
        start_bits.append("有启动相关帧/启动方式")
    else:
        start_bits.append("未见启动帧")
        start_ok_proto = False
    if primary.get("saw_charging_status"):
        start_bits.append("枪口进入充电中")
    else:
        # 仅有电量/电流也可侧面证明启动成功
        if primary.get("currs") or primary.get("volts") or primary.get("energies"):
            start_bits.append("有电流/电压/电量过程数据（侧面证明已启动）")
        else:
            start_bits.append("未见枪口 CHARGING/充电中状态")
            start_ok_proto = False
    if primary.get("currs") or primary.get("volts"):
        start_bits.append("有电流或电压上报")
    else:
        start_bits.append("无电流/电压上报")
        start_ok_proto = False
    if primary.get("energies"):
        start_bits.append("有电量过程上报")
    else:
        start_bits.append("无电量过程上报")
        start_ok_proto = False
    start_msg = ("启动校验通过：" if start_ok_proto else "启动校验异常：") + "；".join(start_bits)

    fields.insert(
        -1 if fields else 0,
        {"name": "启动校验", "value": "通过" if start_ok_proto else "异常"},
    )
    fields.insert(
        -1 if fields else 0,
        {"name": "启动校验说明", "value": start_msg},
    )
    fields.insert(
        -1 if fields else 0,
        {
            "name": "过程电量序列校验",
            "value": "异常" if series_issues else "通过",
        },
    )
    if series_issues:
        fields.append({"name": "过程电量序列异常", "value": "；".join(series_issues[:3])})
        for msg in series_issues[:5]:
            warnings.append({"code": "ENERGY_SERIES", "level": "warn", "message": msg})
        valid = False
        points.append(f"{len(points) + 1}. 过程电量序列异常：" + "；".join(series_issues[:2]))
    if not start_ok_proto:
        warnings.append({"code": "START_FAIL", "level": "warn", "message": start_msg})
        valid = False
        points.append(f"{len(points) + 1}. {start_msg}")
    else:
        points.append(f"{len(points) + 1}. {start_msg}")

    if series_issues or not start_ok_proto:
        bits = []
        if not start_ok_proto:
            bits.append("启动校验未通过")
        if series_issues:
            bits.append("过程电量序列异常")
        verdict = (
            f"综合判断：{'、'.join(bits)}，请复核后再确认。\n"
            "需到设备上核实相关数据，请设备方协助排查。"
        )
        valid = False
    elif has_bill:
        verdict = f"综合判断：已从协议抓包日志还原 {len(orders)} 笔订单的过程与结算字段。"
    elif orders:
        verdict = (
            "综合判断：已解析多帧过程数据，但结算账单不完整，请复核。\n"
            "需到设备上核实相关数据，请设备方协助排查。"
        )
        valid = False
    else:
        verdict = (
            "综合判断：未识别到有效订单帧。\n"
            "需到设备上核实相关数据，请设备方协助排查。"
        )
        valid = False

    report_lines = [
        "充电订单分析报告（协议抓包/多帧）",
        "",
        f"协议：{protocol_name}",
        f"解析帧数：{len(results)}（心跳 {link_count}）",
        f"订单笔数：{len(orders)}",
        "",
        "【结论要点】",
        *points,
        "",
        verdict,
        "",
        "【汇总字段】",
    ]
    for f in fields:
        report_lines.append(f"{f['name']}：{f['value']}")

    # 帧明细：优先列出业务帧，心跳只给统计
    frame_dicts = []
    for r in useful:
        d = r.to_pretty_dict()
        frame_dicts.append(
            {
                "protocol": d.get("protocol"),
                "protocol_name": d.get("protocol_name"),
                "frame_type": d.get("frame_type"),
                "frame_type_name": d.get("frame_type_name"),
                "direction": d.get("direction"),
                "valid": d.get("valid"),
                "summary": d.get("summary"),
                "fields": d.get("fields"),
                "warnings": d.get("warnings"),
                "raw_hex": d.get("raw_hex"),
            }
        )

    return {
        "mode": "charging_report",
        "protocol": protocol,
        "protocol_name": protocol_name,
        "confidence": 0.92 if valid else 0.7,
        "frame_type": None,
        "frame_type_name": f"多帧订单（{len(results)} 帧 / {len(orders)} 笔）",
        "direction": None,
        "valid": valid,
        "summary": "\n".join(points + ["", verdict]),
        "conclusion": points[0] if points else "多帧订单分析",
        "verdict": verdict,
        "result_points": points,
        "report_text": "\n".join(report_lines),
        "fields": fields,
        "warnings": warnings,
        "raw_hex": None,
        "raw_json": None,
        "extras": {
            "source": "protocol_frames",
            "frame_count": len(results),
            "link_frame_count": link_count,
            "order_count": len(orders),
            "filtered": bool(filter_id),
            "filter_id": filter_id,
            "orders": [
                {
                    "trade_no": o["trade_no"],
                    "gun": o["gun"],
                    "energy": o["bill_energy"],
                    "money": o["bill_money"],
                    "stop_reason": o["stop_reason"],
                    "start_way": o["start_way"],
                }
                for o in orders
            ],
            "frames": frame_dicts[:80],  # 避免超大响应；业务帧优先已过滤心跳
            "frame_type_stats": dict(type_counter),
        },
    }
