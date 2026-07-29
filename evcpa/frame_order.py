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
        "start_result": None,
        "start_fail_reason": None,
        "stop_reason": None,
        "stop_code": None,
        "vin": None,
        "card": None,
        "balance": None,
        "start_time": None,
        "end_time": None,
        "bill_energy": None,
        "bill_money": None,
        "process_energy": None,
        "meter_start": None,
        "meter_end": None,
        "has_bill_frame": False,
        "has_remote_stop": False,
        "saw_stop_frame": False,
        "bill_tou": {},
        "socs": [],
        "volts": [],
        "currs": [],
        "powers": [],
        "temps": [],
        "energies": [],
        "moneys": [],
        "frame_count": 0,
        "sample_count": 0,
        "last_slots": {},
        "locked_slots": set(),
        "series_issues": [],
        "saw_charging_status": False,
        "saw_start_frame": False,
        "log_start_ts": None,
        "log_end_ts": None,
        "charge_peak_ts": None,
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
    log_ts = (r.extras or {}).get("log_ts")
    if isinstance(log_ts, str) and log_ts.strip():
        log_ts = log_ts.strip()[:26]
    else:
        log_ts = None

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
            if log_ts and not order["start_time"]:
                order["start_time"] = log_ts[:19]
        elif ft == "0X31":
            order["start_way"] = order["start_way"] or (
                _get_meaning(fmap, "start_way") or "桩端申请启机"
            )
        elif ft == "0X33":
            order["saw_start_frame"] = True
            sr = _get(fmap, "start_result")
            sm = _get_meaning(fmap, "start_result")
            if sm:
                order["start_result"] = sm
            elif sr is not None:
                order["start_result"] = "成功" if str(sr) in {"1", "0x01"} or sr == 1 else "失败"
            fr = _get_meaning(fmap, "fail_reason")
            if fr and fr not in {"无"}:
                order["start_fail_reason"] = fr
            if log_ts and not order["start_time"]:
                order["start_time"] = log_ts[:19]
        else:
            sw = _get_meaning(fmap, "start_way", "charge_way", "txn_flag")
            if sw and sw not in {"0", "0x00", "无"} and "交易标识" not in sw:
                order["start_way"] = sw
            else:
                raw_sw = _get(fmap, "start_way", "txn_flag")
                if raw_sw not in (None, 0, "0", "0x00"):
                    order["start_way"] = order["start_way"] or str(raw_sw)

    # 启动余额（0x34 等）
    bal = _get(fmap, "balance")
    if isinstance(bal, (int, float)) and order.get("balance") is None:
        order["balance"] = float(bal)

    if ft in {x.upper() for x in _STOP_FRAMES}:
        order["saw_stop_frame"] = True
        if ft in {"0X36", "0X05", "0X85", "0X4002"}:
            order["has_remote_stop"] = True
            order["stop_reason"] = order["stop_reason"] or "平台远程停机"
        sr = _get_meaning(fmap, "stop_reason", "fail_reason")
        if sr and sr not in {"无"}:
            order["stop_reason"] = sr
            if log_ts:
                order["end_time"] = order["end_time"] or log_ts[:19]
        elif isinstance(_get(fmap, "stop_reason"), int) and _get(fmap, "stop_reason") != 0:
            code = int(_get(fmap, "stop_reason"))
            order["stop_code"] = code
            order["stop_reason"] = sr or f"停止原因 0x{code:02X}"
            if log_ts:
                order["end_time"] = order["end_time"] or log_ts[:19]
        stop_res = _get_meaning(fmap, "stop_result")
        if stop_res and not order["stop_reason"]:
            order["stop_reason"] = f"远程停机回复：{stop_res}"
    elif not order["stop_reason"]:
        sr = _get_meaning(fmap, "stop_reason", "fail_reason")
        if sr and sr not in {"无"}:
            order["stop_reason"] = sr
        elif isinstance(_get(fmap, "stop_reason"), int) and _get(fmap, "stop_reason") != 0:
            code = int(_get(fmap, "stop_reason"))
            order["stop_code"] = code
            order["stop_reason"] = f"停止原因 0x{code:02X}"

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
        # 仅统计充电中且已有电量的 SOC，避免空闲/起步 0% 拉低范围
        e_now = _get(fmap, "charge_energy")
        st_now = _get(fmap, "status", "gun_status")
        if ft in {x.upper() for x in _BILL_FRAMES}:
            order["socs"].append(int(soc))
        elif st_now in (3, "3", 0x03) and isinstance(e_now, (int, float)) and float(e_now) > 0.2:
            order["socs"].append(int(soc))
    for name in ("soc_start", "soc_end", "start_soc", "end_soc"):
        v = _get(fmap, name)
        if isinstance(v, (int, float)):
            order["socs"].append(int(v))

    volt = _get(fmap, "output_voltage")
    if isinstance(volt, (int, float)) and ft in {x.upper() for x in _REALTIME_FRAMES}:
        if float(volt) > 0.1:
            order["volts"].append(float(volt))
    curr = _get(fmap, "output_current")
    if isinstance(curr, (int, float)) and ft in {x.upper() for x in _REALTIME_FRAMES}:
        if float(curr) > 0.05:
            order["currs"].append(float(curr))
            if order["volts"]:
                order["powers"].append(round(order["volts"][-1] * float(curr) / 1000.0, 3))
    pwr = _get(fmap, "output_power")
    if isinstance(pwr, (int, float)) and float(pwr) > 0.05:
        order["powers"].append(float(pwr))

    energy = _get(fmap, "charge_energy", "total_energy", "loss_energy")
    money = _get(fmap, "charged_amount", "charge_money", "total_money")
    status_val = _get(fmap, "status", "gun_status")
    status_meaning = _get_meaning(fmap, "status", "gun_status") or ""
    idle_like = status_val in (0, 2, "0", "2") or status_meaning in {"离线", "空闲", "故障"}

    def _sane_kwh(v: Any) -> bool:
        return isinstance(v, (int, float)) and 0 < float(v) < 500

    def _sane_money(v: Any) -> bool:
        return isinstance(v, (int, float)) and 0 <= float(v) < 5000

    if ft in {x.upper() for x in _BILL_FRAMES}:
        order["has_bill_frame"] = True
        # 0x3B 旧版布局与 V1.7 0x3D 不完全一致，异常值则回退过程采样
        if _sane_kwh(energy):
            order["bill_energy"] = float(energy)
        total_e = _get(fmap, "total_energy")
        if _sane_kwh(total_e):
            order["bill_energy"] = float(total_e)
        if _sane_money(money) and float(money) > 0:
            order["bill_money"] = float(money)
        total_m = _get(fmap, "total_money")
        if _sane_money(total_m) and float(total_m) > 0:
            order["bill_money"] = float(total_m)
        ms = _get(fmap, "meter_start", "startMeterBattery", "chargeStartMeterBattery")
        me = _get(fmap, "meter_end", "endMeterBattery", "chargeEndMeterBattery")
        if isinstance(ms, (int, float)):
            order["meter_start"] = float(ms)
        if isinstance(me, (int, float)):
            order["meter_end"] = float(me)
        tou: dict[str, float] = {}
        for key in (
            "jian_energy",
            "feng_energy",
            "ping_energy",
            "gu_energy",
            "jian_price",
            "feng_price",
            "ping_price",
            "gu_price",
            "jian_money",
            "feng_money",
            "ping_money",
            "gu_money",
        ):
            v = _get(fmap, key)
            if isinstance(v, (int, float)):
                tou[key] = float(v)
        if tou:
            order["bill_tou"] = {**(order.get("bill_tou") or {}), **tou}
        sr = _get_meaning(fmap, "stop_reason")
        if sr and sr not in {"无"}:
            order["stop_reason"] = order["stop_reason"] or sr
        raw_sr = _get(fmap, "stop_reason")
        if isinstance(raw_sr, int):
            order["stop_code"] = raw_sr
        if log_ts:
            order["end_time"] = order["end_time"] or log_ts[:19]
    elif ft in {x.upper() for x in _REALTIME_FRAMES}:
        order["sample_count"] = int(order.get("sample_count") or 0) + 1
        for tname in ("gun_cable_temp", "battery_max_temp", "module_temp"):
            tv = _get(fmap, tname)
            if isinstance(tv, (int, float)) and -40 < float(tv) < 120:
                order["temps"].append(float(tv))
        if isinstance(energy, (int, float)) and float(energy) >= 0:
            e = float(energy)
            prev_e = order["energies"][-1] if order["energies"] else None
            # 充电结束后空闲帧电量归零，不算过程回落异常
            if prev_e is not None and e + 1e-6 < prev_e:
                if e <= 0.001 and (idle_like or prev_e > 0.5):
                    if log_ts and not order["end_time"]:
                        order["end_time"] = (order.get("charge_peak_ts") or log_ts)[:19]
                else:
                    order["series_issues"].append(
                        f"过程总电量回落：{prev_e} → {e} kWh（{ft}）"
                    )
            if e > 0.001:
                order["energies"].append(e)
                if log_ts:
                    if not order["log_start_ts"]:
                        order["log_start_ts"] = log_ts[:19]
                    order["log_end_ts"] = log_ts[:19]
                    if prev_e is None or e + 1e-9 >= (prev_e or 0):
                        order["charge_peak_ts"] = log_ts[:19]
            elif not order["energies"]:
                order["energies"].append(e)
        if isinstance(money, (int, float)) and float(money) >= 0:
            m = float(money)
            if m > 0:
                order["moneys"].append(m)
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

        # 枪口充电中（云快充 status=3；部分协议 meaning=充电/充电中；勿把空闲=2 当成充电）
        for name, item in fmap.items():
            if "status" not in name:
                continue
            meaning = ""
            if hasattr(item, "meaning") and item.meaning:
                meaning = str(item.meaning)
            val = item.value if hasattr(item, "value") else item
            if meaning in {"充电", "充电中", "操作中"} or val in (3, "3", 0x03):
                order["saw_charging_status"] = True
                if log_ts:
                    if not order["log_start_ts"]:
                        order["log_start_ts"] = log_ts[:19]
                    order["log_end_ts"] = log_ts[:19]

    if ft in {x.upper() for x in _START_FRAMES}:
        order["saw_start_frame"] = True

    if not order["start_way"]:
        tf = _get_meaning(fmap, "txn_flag")
        if tf and "交易标识" not in tf:
            order["start_way"] = tf


def _avg(xs: list[float]) -> float | None:
    if not xs:
        return None
    return sum(xs) / len(xs)


def _fmt_avg_range(xs: list[float], unit: str, digits: int = 1) -> tuple[str, str]:
    if not xs:
        return "-", "-"
    a = _avg(xs)
    assert a is not None
    avg_s = f"约 {a:.{digits}f} {unit}"
    rng_s = f"{min(xs):.{digits}f} ～ {max(xs):.{digits}f} {unit}"
    return avg_s, rng_s


def _duration_sec(start: Any, end: Any) -> int | None:
    if not start or not end or start == "-" or end == "-":
        return None
    from datetime import datetime

    try:
        a = datetime.strptime(str(start)[:19], "%Y-%m-%d %H:%M:%S")
        b = datetime.strptime(str(end)[:19], "%Y-%m-%d %H:%M:%S")
        sec = int((b - a).total_seconds())
        return sec if sec >= 0 else None
    except ValueError:
        return None


def _infer_stop_fields(od: dict[str, Any]) -> dict[str, str]:
    """从协议帧推断停止相关字段（对齐 JSON 报告命名）。"""
    has_remote = bool(od.get("has_remote_stop"))
    stop_reason = od.get("stop_reason") or "-"
    gun_transition = "-"
    if od.get("saw_charging_status") and od.get("end_time"):
        gun_transition = "充电中 → 结束（过程归零/结束时刻）"
    elif od.get("saw_charging_status"):
        gun_transition = "充电中"
    if has_remote:
        stop_type = "平台远程停止"
        tip = "报文中存在远程停机相关帧（如 0x36）。"
        basis = "远程停机指令/应答帧"
        platform_reason = "平台下发远程停机"
    elif od.get("has_bill_frame") and stop_reason not in (None, "-", ""):
        stop_type = "设备停止（账单）"
        tip = "依据交易记录帧中的停止原因。"
        basis = "交易记录（0x3D/0x3B）停止码"
        platform_reason = "-"
    elif od.get("saw_stop_frame"):
        stop_type = "设备/协议停机"
        tip = "报文中存在停机相关帧。"
        basis = "停机帧"
        platform_reason = "-"
    elif od.get("end_time") and (od.get("bill_energy") or 0) > 0:
        stop_type = "过程结束（未见停机/账单帧）"
        stop_reason = (
            stop_reason
            if stop_reason not in (None, "-", "")
            else "未见远程停机或交易记录，按过程电量峰值时刻结束"
        )
        tip = "建议结合平台账单核对最终停止原因。"
        basis = "实时监测过程结束（电量峰值后空闲归零）"
        platform_reason = "未见平台停止指令（纯协议抓包）"
    else:
        stop_type = "-"
        tip = "-"
        basis = "-"
        platform_reason = "-"
    return {
        "has_remote_stop": "是" if has_remote else "否",
        "stop_type": stop_type,
        "stop_reason": str(stop_reason),
        "stop_basis": basis,
        "stop_tip": tip,
        "device_finish": od.get("stop_reason") or "-",
        "stop_code": f"{od['stop_code']}" if od.get("stop_code") is not None else "-",
        "platform_stop_reason": platform_reason,
        "gun_transition": gun_transition,
    }


def _fmt_tou_from_bill(tou: dict[str, float]) -> str:
    if not tou:
        return "-"
    parts = []
    mapping = (
        ("jian_energy", "尖"),
        ("feng_energy", "峰"),
        ("ping_energy", "平"),
        ("gu_energy", "谷"),
    )
    for key, label in mapping:
        if key in tou and tou[key] > 0:
            parts.append(f"{label}{tou[key]:.3f} kWh")
    return "；".join(parts) if parts else "-"


def _fmt_slots(slots: dict[str, float]) -> str:
    if not slots:
        return "-"
    parts = []
    for k, v in sorted(slots.items()):
        if v <= 0:
            continue
        name = k.replace("tou_", "").replace("slot_", "").replace("_energy", "")
        parts.append(f"{name}{v:.3f} kWh")
    return "；".join(parts[:12]) if parts else "-"


def _build_frame_customer_report(
    *,
    protocol_name: str,
    pile: str,
    gun_text: str,
    trade_no: str,
    start_way: str,
    start_result: str,
    start_time: str,
    end_time: str,
    dur_text: str,
    balance_text: str,
    i_avg: str,
    i_rng: str,
    v_avg: str,
    v_rng: str,
    p_avg: str,
    p_rng: str,
    pwr_check: str,
    sample_count: int,
    meter_start: str,
    meter_end: str,
    energy_text: str,
    proc_energy_text: str,
    soc_text: str,
    vin_text: str,
    t_rng: str,
    tou_lines: list[str],
    start_ok: bool,
    start_msg: str,
    series_ok: bool,
    series_msg: str,
    bill_check: str,
    bill_check_msg: str,
    pt_label: str,
    pt_msg: str,
    has_bill: bool,
    fee_text: str,
    stop_info: dict[str, str],
    frame_count: int,
    link_count: int,
    order_count: int,
    verdict: str,
    bullets: list[str],
) -> str:
    """生成纯协议报文场景下的客户可读分析报告（结构对齐 JSON 订单报告）。"""
    from datetime import datetime

    from evcpa.order_report import _cn_datetime, _section

    report_date = datetime.now().strftime("%Y年%m月%d日")
    st = _cn_datetime(start_time) if start_time and start_time != "-" else "-"
    et = _cn_datetime(end_time) if end_time and end_time != "-" else "-"

    out: list[str] = [
        "充电订单分析报告",
        "",
        f"报告日期：{report_date}",
        f"分析对象：桩号 {pile or '-'} 协议抓包报文（{protocol_name}）",
        "数据来源：设备与运营平台之间的原始通信报文（非平台业务 JSON 日志）",
    ]
    out += _section("一、订单基本信息")
    out += [
        f"充电桩编号：{pile or '-'}",
        f"枪口号：{gun_text}",
        f"服务ID：-（原始报文通常不含平台服务ID）",
        f"订单流水号：{trade_no or '-'}",
        "手机号：-",
        "车牌号：-",
        f"启动方式：{start_way}",
        f"启动结果：{start_result}",
        f"启动时间：{st}",
        f"结束时间：{et}",
        f"充电时长：{dur_text}",
        f"启动时账户余额：{balance_text}",
    ]

    out += _section("二、充电电气数据")
    out += [
        f"充电电流（平均）：{i_avg}",
        f"充电电流（范围）：{i_rng}",
        f"充电电压（平均）：{v_avg}",
        f"充电电压（范围）：{v_rng}",
        f"输出功率（平均）：{p_avg}",
        f"输出功率（范围）：{p_rng}",
        f"功率印证（电流×电压）：{pwr_check}",
        f"实时采样点数：{sample_count}（实时监测帧）",
        f"起始终端表码：{meter_start}",
        f"结束终端表码：{meter_end}",
        f"实际充电电量：{energy_text}",
        f"过程电量（实时监测峰值）：{proc_energy_text}",
        f"电池荷电状态：{soc_text}",
        f"车辆识别码：{vin_text}",
        f"模块温度（范围）：{t_rng}",
        "",
        "说明：电流、电压取实时监测帧；输出功率由同帧电流×电压估算；"
        "实际电量优先取交易记录帧，若无则取过程监测峰值。",
    ]

    out += _section("三、分时电量（尖 / 峰 / 平 / 谷）")
    out.extend(tou_lines)
    out.append("")
    if has_bill:
        out.append("说明：分时电量来自交易记录（结算）帧。")
    else:
        out.append(
            "说明：本段抓包未见交易记录帧（如云快充 0x3D/0x3B），尖峰平谷分时暂缺；"
            "电量以过程监测峰值为准，建议结合平台账单核对分时。"
        )

    out += _section("四、过程与账单校验")
    out.append(
        "说明：核对启动是否成功、过程电量是否异常回落；"
        "若有交易记录则对比过程与账单电量；"
        "并用平均功率×充电时长估算电量作合理性参考（直流充电末段涓流时估算可能偏低）。"
    )
    out.append(f"启动校验：{start_msg}")
    out.append(
        "过程电量序列："
        + ("正常（未见异常回落）" if series_ok else f"异常（{series_msg}）")
    )
    out.append(f"过程与账单：[{bill_check}] {bill_check_msg}")
    out.append(f"功率×时间估算：[{pt_label}] {pt_msg}")
    if start_ok and series_ok and bill_check in {"通过", "未校验"} and pt_label != "异常":
        out.append(
            "结论：启动正常；过程电量序列正常；"
            + (
                "过程与账单一致；功率×时间估算合理。"
                if bill_check == "通过"
                else "未见交易记录帧，电量以过程峰值为准；功率×时间估算可供参考。"
            )
        )
    elif start_ok and series_ok and pt_label == "异常":
        out.append(
            "结论：启动与过程电量序列正常；功率×时间估算与过程电量存在偏差，"
            "常见于功率前高后低或采样不均匀，建议结合平台账单复核，不宜单独据此否定电量。"
        )
    else:
        bits = []
        if not start_ok:
            bits.append("启动校验未通过")
        if not series_ok:
            bits.append("过程电量序列异常")
        if bill_check == "异常":
            bits.append("过程与账单不一致")
        if pt_label == "异常":
            bits.append("功率×时间估算偏差较大")
        out.append("结论：" + ("；".join(bits) if bits else "请复核") + "，请结合平台侧账单与现场情况确认。")

    out += _section("五、费用明细")
    out += [
        f"电费（过程累计/账单）：{fee_text}",
        "服务费：-（原始报文通常不拆分服务费）",
        "占桩费：0 元",
        "预约费：0 元",
        f"费用合计：{fee_text}",
        "",
        "说明：费用来自实时监测累计金额或交易记录帧；若抓包不完整，请以平台账单为准。",
    ]

    out += _section("六、停止原因与占桩情况")
    remote_txt = stop_info.get("has_remote_stop") or "否"
    if remote_txt in {"否", "无"}:
        remote_txt = "无（抓包中未见平台远程停机指令）"
    elif remote_txt in {"是", "有"}:
        remote_txt = "有"
    out += [
        f"是否有远程停止指令：{remote_txt}",
        f"停止类型：{stop_info.get('stop_type') or '-'}",
        f"停止原因：{stop_info.get('stop_reason') or '-'}",
        f"平台停止原因：{stop_info.get('platform_stop_reason') or '-'}",
        f"设备结束原因：{stop_info.get('device_finish') or '-'}",
        f"结束原因代码：{stop_info.get('stop_code') or '-'}",
        f"枪口状态变迁：{stop_info.get('gun_transition') or '-'}",
        f"停止依据：{stop_info.get('stop_basis') or '-'}",
        "是否占桩计费：否",
        "占桩时长：未见占桩计费相关帧",
        "占桩费用：0 元",
        "本单异常/告警摘录：无（本段抓包未见明确故障告警帧）",
        "告警信息：无",
    ]
    if stop_info.get("stop_tip") and stop_info.get("stop_tip") not in {"-", ""}:
        out.append(f"提示：{stop_info['stop_tip']}")

    out += _section("七、结论要点")
    out.extend(bullets)
    out.append("")
    for line in str(verdict).splitlines():
        if line.strip():
            out.append(line.strip())
    out += [
        "",
        "-" * 80,
        "本报告依据设备与运营平台之间的原始协议报文解析生成，供客户查阅。",
        f"解析规模：共 {frame_count} 帧（其中链路心跳 {link_count} 帧不参与业务汇总），识别订单 {order_count} 笔。",
        "若抓包未覆盖交易记录或停机指令，结算与停止原因请以平台账单/完整日志为准。",
    ]
    return "\n".join(out)


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
        if od["energies"]:
            od["process_energy"] = max(od["energies"])
        if od["bill_money"] is None and od["moneys"]:
            od["bill_money"] = max(od["moneys"])
        # 无账单起止时间时，用日志过程时间补齐（结束优先取电量峰值时刻）
        if not od.get("start_time"):
            od["start_time"] = od.get("log_start_ts")
        if not od.get("end_time"):
            od["end_time"] = od.get("charge_peak_ts") or od.get("log_end_ts")
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

    primary = next(
        (
            o
            for o in orders
            if (o.get("bill_energy") or 0) > 0 and _valid_trade_no(o.get("trade_no"))
        ),
        next((o for o in orders if _valid_trade_no(o.get("trade_no"))), orders[0] if orders else _empty_order()),
    )

    # —— 对齐 JSON 订单报告的主字段结构 ——
    stop_info = _infer_stop_fields(primary)
    i_avg, i_rng = _fmt_avg_range(list(primary.get("currs") or []), "安")
    v_avg, v_rng = _fmt_avg_range(list(primary.get("volts") or []), "伏")
    p_avg, p_rng = _fmt_avg_range(list(primary.get("powers") or []), "千瓦", digits=3)
    t_rng = (
        f"{min(primary['temps']):.0f} ～ {max(primary['temps']):.0f} ℃"
        if primary.get("temps")
        else "-"
    )
    soc_text = (
        f"{min(primary['socs'])}% ～ {max(primary['socs'])}%"
        if primary.get("socs")
        else "未上报（全过程为 0）"
    )
    proc_e = primary.get("process_energy")
    bill_e = primary.get("bill_energy")
    if primary.get("has_bill_frame") and proc_e is not None and bill_e is not None:
        diff = abs(float(proc_e) - float(bill_e))
        bill_check = "通过" if diff <= max(1.0, float(bill_e) * 0.05) + 1e-9 else "异常"
        bill_check_msg = f"过程峰值 {proc_e} kWh，账单 {bill_e} kWh，差值 {diff:.3f} kWh"
    elif proc_e is not None:
        bill_check = "未校验"
        bill_check_msg = f"无交易记录帧（0x3D/0x3B），过程峰值电量 {proc_e} kWh（作实际电量）"
    else:
        bill_check = "-"
        bill_check_msg = "-"

    from evcpa.order_report import _check_energy_vs_power_time, _cn_datetime

    dur_sec = _duration_sec(primary.get("start_time"), primary.get("end_time"))
    avg_p = _avg(list(primary.get("powers") or []))
    pt = _check_energy_vs_power_time(
        energy_kwh=float(bill_e) if bill_e is not None else None,
        power_kw=avg_p,
        duration_sec=dur_sec,
    )
    pt_code = pt.get("code") or ""
    if pt_code == "POWER_TIME_MISMATCH":
        pt_label = "异常"
        base = str(pt.get("message") or "").rstrip("。；; ")
        pt_msg_customer = (
            f"{base}。"
            "直流充电常见末段功率下降，算术平均功率×时长可能低估电量，建议结合平台账单复核。"
        )
    elif pt_code == "POWER_TIME_OK":
        pt_label = "通过"
        pt_msg_customer = pt.get("message") or "功率×时间估算与实际电量一致。"
    else:
        pt_label = "未校验"
        pt_msg_customer = pt.get("message") or "缺少电量/功率/时长，未做功率×时间校验。"

    raw_sr = primary.get("start_result")
    if raw_sr in {"成功", "启动成功"} or str(raw_sr or "").startswith("成功"):
        start_result = "启动成功"
    elif raw_sr in {"失败", "启动失败"} or str(raw_sr or "").startswith("失败"):
        start_result = "启动失败"
    elif raw_sr:
        start_result = str(raw_sr)
    elif primary.get("saw_charging_status") or (
        primary.get("energies") and (primary.get("currs") or primary.get("volts"))
    ):
        start_result = "启动成功（由过程数据推断）"
    elif primary.get("saw_start_frame"):
        start_result = "已启机应答"
    else:
        start_result = "-"
    if primary.get("start_fail_reason") and start_result not in {"启动成功", "启动成功（由过程数据推断）"}:
        start_result = f"{start_result}（{primary['start_fail_reason']}）"

    def _tou_energy(key: str) -> str:
        tou = primary.get("bill_tou") or {}
        if key not in tou:
            return "-" if not primary.get("has_bill_frame") else "0 kWh"
        return f"{tou[key]} kWh"

    def _tou_price(key: str) -> str:
        tou = primary.get("bill_tou") or {}
        if key not in tou:
            return "-"
        return f"{tou[key]} 元/kWh"

    start_way = (
        primary.get("start_way")
        or next((o.get("start_way") for o in orders if o.get("start_way")), None)
        or "-"
    )
    pile_text = primary.get("pile") or meta.get("pile") or "-"
    gun_text = f"{primary['gun']} 枪" if primary.get("gun") is not None else "-"
    start_time_disp = (
        _cn_datetime(primary.get("start_time"))
        if primary.get("start_time")
        else "-"
    )
    end_time_disp = (
        _cn_datetime(primary.get("end_time"))
        if primary.get("end_time")
        else "-"
    )
    dur_text = _order_duration_text(primary.get("start_time"), primary.get("end_time"))
    balance_text = (
        f"{primary['balance']:.2f} 元"
        if isinstance(primary.get("balance"), (int, float))
        else "-"
    )
    energy_text = f"{bill_e} kWh" if bill_e is not None else "-"
    proc_energy_text = f"{proc_e} kWh" if proc_e is not None else "-"
    fee_text = f"{primary['bill_money']} 元" if primary.get("bill_money") is not None else "-"
    sample_n = int(primary.get("sample_count") or len(primary.get("energies") or []) or 0)
    pwr_check = (
        f"由输出电流×电压估算，采样功率均值 {avg_p:.3f} kW"
        if avg_p is not None
        else "未上报输出功率，且无法由电流×电压估算"
    )

    fields: list[dict[str, Any]] = [
        {"name": "充电桩编号", "value": pile_text},
        {"name": "枪口号", "value": gun_text},
        {"name": "服务ID", "value": "-"},
        {"name": "订单流水号", "value": primary.get("trade_no") or "-"},
        {"name": "手机号", "value": "-"},
        {"name": "车牌号", "value": "-"},
        {"name": "启动方式", "value": start_way},
        {"name": "启动结果", "value": start_result},
        {"name": "启动时间", "value": start_time_disp},
        {"name": "结束时间", "value": end_time_disp},
        {"name": "充电时长", "value": dur_text},
        {"name": "启动时账户余额", "value": balance_text},
        {"name": "充电电流（平均）", "value": i_avg},
        {"name": "充电电流（范围）", "value": i_rng},
        {"name": "充电电压（平均）", "value": v_avg},
        {"name": "充电电压（范围）", "value": v_rng},
        {"name": "需求电流（平均）", "value": "-"},
        {"name": "需求电流（范围）", "value": "-"},
        {"name": "需求电压（平均）", "value": "-"},
        {"name": "需求电压（范围）", "value": "-"},
        {"name": "输出功率（平均）", "value": p_avg},
        {"name": "输出功率（范围）", "value": p_rng},
        {"name": "功率印证（电流×电压）", "value": pwr_check},
        {"name": "实时采样点数", "value": f"{sample_n}（实时监测帧）"},
        {
            "name": "起始终端表码",
            "value": f"{primary['meter_start']:.4f} kWh" if isinstance(primary.get("meter_start"), (int, float)) else "-",
        },
        {
            "name": "结束终端表码",
            "value": f"{primary['meter_end']:.4f} kWh" if isinstance(primary.get("meter_end"), (int, float)) else "-",
        },
        {"name": "实际充电电量", "value": energy_text},
        {"name": "过程电量（实时监测）", "value": proc_energy_text},
        {"name": "过程分时", "value": _fmt_slots(primary.get("last_slots") or {})},
        {"name": "账单分时", "value": _fmt_tou_from_bill(primary.get("bill_tou") or {})},
        {
            "name": "账单总电量",
            "value": f"{bill_e} kWh" if primary.get("has_bill_frame") and bill_e is not None else "-",
        },
        {"name": "过程与账单校验", "value": bill_check},
        {"name": "过程与账单说明", "value": bill_check_msg},
        {"name": "功率×时间电量校验", "value": pt_label},
        {"name": "功率×时间电量说明", "value": pt_msg_customer},
        {
            "name": "电池荷电状态",
            "value": soc_text if primary.get("socs") else "未上报（全过程为 0）",
        },
        {"name": "车辆识别码", "value": primary.get("vin") or "未上报"},
        {"name": "模块温度（范围）", "value": t_rng},
        {"name": "尖电量", "value": _tou_energy("jian_energy")},
        {"name": "峰电量", "value": _tou_energy("feng_energy")},
        {"name": "平电量", "value": _tou_energy("ping_energy")},
        {"name": "谷电量", "value": _tou_energy("gu_energy")},
        {"name": "尖电价", "value": _tou_price("jian_price")},
        {"name": "峰电价", "value": _tou_price("feng_price")},
        {"name": "平电价", "value": _tou_price("ping_price")},
        {"name": "谷电价", "value": _tou_price("gu_price")},
        {"name": "电费", "value": fee_text},
        {"name": "服务费", "value": "-"},
        {"name": "占桩费", "value": "0 元"},
        {"name": "预约费", "value": "0 元"},
        {"name": "费用合计", "value": fee_text},
        {"name": "是否有远程停止指令", "value": stop_info["has_remote_stop"]},
        {"name": "停止类型", "value": stop_info["stop_type"]},
        {"name": "停止原因", "value": stop_info["stop_reason"]},
        {"name": "平台停止原因", "value": stop_info["platform_stop_reason"]},
        {"name": "设备结束原因", "value": stop_info["device_finish"]},
        {"name": "结束原因代码", "value": stop_info["stop_code"]},
        {"name": "枪口状态变迁", "value": stop_info["gun_transition"]},
        {"name": "停止依据", "value": stop_info["stop_basis"]},
        {"name": "停止提示", "value": stop_info["stop_tip"]},
        {"name": "本单异常/告警摘录", "value": "无"},
        {"name": "告警信息", "value": "无"},
        {"name": "同桩其他枪口提示", "value": "无"},
        {"name": "是否占桩计费", "value": "否"},
        {"name": "占桩时长", "value": "-"},
        {"name": "占桩费用", "value": "0 元"},
        {"name": "解析帧数", "value": str(len(results))},
        {"name": "订单笔数", "value": str(len(orders))},
        {"name": "帧类型统计", "value": "；".join(frame_brief) if frame_brief else "-"},
    ]
    if len(orders) > 1:
        for i, od in enumerate(orders, 1):
            prefix = f"订单{i}"
            fields.extend(
                [
                    {"name": f"{prefix}流水号", "value": od["trade_no"] or "-"},
                    {"name": f"{prefix}枪口", "value": f"{od['gun']} 枪" if od["gun"] is not None else "-"},
                    {"name": f"{prefix}启动方式", "value": od["start_way"] or "-"},
                    {"name": f"{prefix}启动结果", "value": od.get("start_result") or "-"},
                    {
                        "name": f"{prefix}开始时间",
                        "value": _cn_datetime(od["start_time"]) if od.get("start_time") else "-",
                    },
                    {
                        "name": f"{prefix}结束时间",
                        "value": _cn_datetime(od["end_time"]) if od.get("end_time") else "-",
                    },
                    {
                        "name": f"{prefix}电量",
                        "value": f"{od['bill_energy']} kWh" if od["bill_energy"] is not None else "-",
                    },
                    {
                        "name": f"{prefix}费用",
                        "value": f"{od['bill_money']} 元" if od["bill_money"] is not None else "-",
                    },
                    {"name": f"{prefix}结束原因", "value": od["stop_reason"] or "-"},
                ]
            )

    has_bill = any(o.get("has_bill_frame") for o in orders)
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
    if primary.get("start_result") in {"成功", "启动成功"} or str(primary.get("start_result") or "").startswith("成功"):
        start_bits.append(f"启机回复：{primary.get('start_result')}")
    if primary.get("saw_charging_status"):
        start_bits.append("枪口进入充电中")
    else:
        if primary.get("currs") or primary.get("volts") or primary.get("energies"):
            start_bits.append("有电流/电压/电量过程数据（侧面证明已启动）")
        else:
            start_bits.append("未见枪口充电中状态")
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

    check_fields = [
        {"name": "启动校验", "value": "通过" if start_ok_proto else "异常"},
        {"name": "启动校验说明", "value": start_msg},
        {"name": "过程电量序列校验", "value": "异常" if series_issues else "通过"},
    ]
    if series_issues:
        check_fields.append({"name": "过程电量序列异常", "value": "；".join(series_issues[:3])})
    insert_at = next((i for i, f in enumerate(fields) if f["name"] == "功率×时间电量说明"), len(fields) - 1)
    for j, cf in enumerate(check_fields):
        fields.insert(insert_at + 1 + j, cf)

    if series_issues:
        for msg in series_issues[:5]:
            warnings.append({"code": "ENERGY_SERIES", "level": "warn", "message": msg})
        valid = False
    if not start_ok_proto:
        warnings.append({"code": "START_FAIL", "level": "warn", "message": start_msg})
        valid = False
    if pt_code == "POWER_TIME_MISMATCH":
        warnings.append({"code": pt_code, "level": "warn", "message": pt.get("message") or ""})
        valid = False
    if bill_check == "异常":
        warnings.append({"code": "BILL_MISMATCH", "level": "warn", "message": bill_check_msg})
        valid = False

    # —— 客户可读结论要点（对齐 JSON 报告语气）——
    points: list[str] = []
    if start_ok_proto and start_result.startswith("启动成功"):
        points.append(
            f"1. {start_way}成功，枪口已进入充电，过程有电流/电压/电量上报。"
            if start_way and start_way != "-"
            else "1. 启动成功，枪口已进入充电，过程有电流/电压/电量上报。"
        )
    else:
        points.append(f"1. {start_msg}")

    if stop_info["has_remote_stop"] in {"是", "有"}:
        points.append(f"2. 平台下发远程停止，停止原因：{stop_info['stop_reason']}。")
    elif stop_info["stop_type"] not in {"-", ""}:
        points.append(
            f"2. 抓包中未见平台远程停机指令；停止类型「{stop_info['stop_type']}」，"
            f"原因：{stop_info['stop_reason']}。"
        )
    else:
        points.append("2. 抓包中未见明确停机指令或交易记录停止码，结束时刻按过程数据推断。")

    points.append(
        f"3. 实际充电电量 {energy_text}，费用合计约 {fee_text}，充电时长 {dur_text}。"
    )
    points.append("4. 未见占桩计费相关信息，占桩费用按 0 元计。")
    if primary.get("has_bill_frame"):
        points.append("5. 已解析到交易记录帧，结算字段可与过程数据交叉核对。")
    else:
        points.append(
            "5. 本段抓包未见交易记录帧，电量/费用以实时监测峰值为准，建议结合平台账单复核分时与结算。"
        )
    if series_issues:
        points.append(f"{len(points) + 1}. 过程电量序列异常：{'；'.join(series_issues[:2])}。")
    if not start_ok_proto:
        points.append(f"{len(points) + 1}. 启动校验未通过，详见启动校验说明。")
    if pt_label == "异常":
        points.append(
            f"{len(points) + 1}. 功率×时间估算与过程电量存在偏差，常见于末段涓流或采样不均，建议结合平台账单复核。"
        )
    if bill_check == "异常":
        points.append(f"{len(points) + 1}. 过程与账单电量校验异常：{bill_check_msg}。")
    if stop_info.get("stop_tip") and stop_info.get("stop_tip") not in {"-", ""}:
        points.append(f"{len(points) + 1}. {stop_info['stop_tip']}")

    data_check_fail = pt_label == "异常" or bill_check == "异常"
    if series_issues or not start_ok_proto or data_check_fail:
        bits = []
        if not start_ok_proto:
            bits.append("启动校验未通过")
        if series_issues:
            bits.append("过程电量序列异常")
        if bill_check == "异常":
            bits.append("过程与账单电量不一致")
        if pt_label == "异常":
            bits.append("功率×时间电量估算存在偏差")
        if series_issues or not start_ok_proto or bill_check == "异常":
            verdict = (
                f"综合判断：{'、'.join(bits)}，请复核后再确认。\n"
                "需到设备上核实相关数据，请设备方协助排查。"
            )
        else:
            verdict = f"综合判断：{'、'.join(bits)}，建议结合平台账单复核后再确认。"
        valid = False
    elif has_bill and start_ok_proto and not series_issues:
        verdict = (
            f"综合判断：{stop_info['stop_type'] if stop_info['stop_type'] not in {'-', ''} else '订单过程完整'}，"
            "结算与过程数据可核对。"
        )
        valid = True
    elif orders:
        has_process = any((o.get("bill_energy") or 0) > 0 or o.get("energies") for o in orders)
        if has_process and start_ok_proto and not series_issues:
            verdict = (
                "综合判断：启动与充电过程正常；本段抓包未见交易记录或远程停机帧，"
                "电量与费用以过程监测为准，建议结合平台账单确认最终结算与停止原因。"
            )
            valid = True
        else:
            verdict = (
                "综合判断：已解析过程数据，但结算信息不完整，请复核。\n"
                "需到设备上核实相关数据，请设备方协助排查。"
            )
            valid = False
    else:
        verdict = (
            "综合判断：未识别到有效订单。\n"
            "需到设备上核实相关数据，请设备方协助排查。"
        )
        valid = False

    tou_lines = [
        f"尖：{_tou_energy('jian_energy')}，电价 {_tou_price('jian_price')}",
        f"峰：{_tou_energy('feng_energy')}，电价 {_tou_price('feng_price')}",
        f"平：{_tou_energy('ping_energy')}，电价 {_tou_price('ping_price')}",
        f"谷：{_tou_energy('gu_energy')}，电价 {_tou_price('gu_price')}",
    ]
    if primary.get("last_slots"):
        tou_lines.append(f"过程分时参考：{_fmt_slots(primary.get('last_slots') or {})}")

    report_text = _build_frame_customer_report(
        protocol_name=protocol_name,
        pile=pile_text,
        gun_text=gun_text,
        trade_no=primary.get("trade_no") or "-",
        start_way=start_way,
        start_result=start_result,
        start_time=primary.get("start_time") or "-",
        end_time=primary.get("end_time") or "-",
        dur_text=dur_text,
        balance_text=balance_text,
        i_avg=i_avg,
        i_rng=i_rng,
        v_avg=v_avg,
        v_rng=v_rng,
        p_avg=p_avg,
        p_rng=p_rng,
        pwr_check=pwr_check,
        sample_count=sample_n,
        meter_start=(
            f"{primary['meter_start']:.4f} kWh"
            if isinstance(primary.get("meter_start"), (int, float))
            else "-"
        ),
        meter_end=(
            f"{primary['meter_end']:.4f} kWh"
            if isinstance(primary.get("meter_end"), (int, float))
            else "-"
        ),
        energy_text=energy_text,
        proc_energy_text=proc_energy_text,
        soc_text=soc_text if primary.get("socs") else "未上报（全过程为 0）",
        vin_text=primary.get("vin") or "未上报",
        t_rng=t_rng,
        tou_lines=tou_lines,
        start_ok=start_ok_proto,
        start_msg=start_msg,
        series_ok=not series_issues,
        series_msg="；".join(series_issues[:3]) if series_issues else "",
        bill_check=bill_check,
        bill_check_msg=bill_check_msg,
        pt_label=pt_label,
        pt_msg=pt_msg_customer,
        has_bill=bool(primary.get("has_bill_frame")),
        fee_text=fee_text,
        stop_info=stop_info,
        frame_count=len(results),
        link_count=link_count,
        order_count=len(orders),
        verdict=verdict,
        bullets=points,
    )

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
        "conclusion": points[0] if points else "已生成充电订单分析报告。",
        "verdict": verdict,
        "result_points": points,
        "report_text": report_text,
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
            "frames": frame_dicts[:80],
            "frame_type_stats": dict(type_counter),
        },
    }
