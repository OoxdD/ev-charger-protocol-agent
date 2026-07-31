"""盛弘多帧抓包会话汇总（心跳/状态/启停/充电记录 → 订单报告）。"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from evcpa.knowledge.shenghong import (
    SH_CMD_NAMES,
    SH_REMOTE_STOP_REASON_CODES,
    SH_STOP_REASON,
    SH_WORK_STATUS,
)
from evcpa.models import AnalysisResult

_NUM = re.compile(r"^-?\d+(?:\.\d+)?")


def _field_map(r: AnalysisResult) -> dict[str, Any]:
    return {f.name: f.value for f in r.fields}


def _field_meaning(r: AnalysisResult, name: str) -> str | None:
    for f in r.fields:
        if f.name == name:
            return f.meaning
    return None


def _num(v: Any) -> float | None:
    if v is None or v == "-" or v == "":
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip().replace(",", "")
    m = _NUM.match(s)
    if not m:
        return None
    try:
        return float(m.group(0))
    except ValueError:
        return None


def _int(v: Any) -> int | None:
    n = _num(v)
    return int(n) if n is not None else None


def _clean_card(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    if not s or s == "-":
        return None
    # 去掉前导 0，保留有效卡号/账号
    stripped = s.lstrip("0")
    return stripped or "0"


def _clean_pile(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    if not s or s == "-":
        return None
    # 盛弘桩号一般为数字/字母，长度约 8～32；过滤误解析噪声
    if not re.fullmatch(r"[0-9A-Za-z]{8,32}", s):
        return None
    return s


def _stop_text(code: Any) -> str | None:
    c = _int(code)
    if c is None:
        return None
    return SH_STOP_REASON.get(c, f"停止码 {c}")


def _cmd(r: AnalysisResult) -> int | None:
    ft = r.frame_type
    if ft is None:
        return None
    try:
        return int(str(ft))
    except ValueError:
        return None


def aggregate_shenghong_session(
    results: list[AnalysisResult],
    *,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """将盛弘多帧解析结果汇总为客户可读充电报告。"""
    meta = meta or {}
    sh = [r for r in results if r.protocol.value == "shenghong"]
    if not sh:
        sh = results

    type_counter: Counter[str] = Counter()
    ts_list: list[str] = []
    piles: set[str] = set()
    guns: set[int] = set()
    status_frames: list[tuple[str | None, dict[str, Any], AnalysisResult]] = []
    bills: list[dict[str, Any]] = []
    remote_stops: list[dict[str, Any]] = []
    start_cmds = 0
    start_ack = 0
    stop_cmds = 0
    stop_ack = 0
    sign_ins = 0

    for r in sh:
        cmd = _cmd(r)
        name = SH_CMD_NAMES.get(cmd or -1, r.frame_type_name or str(cmd))
        type_counter[str(name)] += 1
        ts = (r.extras or {}).get("log_ts")
        if isinstance(ts, str) and ts.strip():
            ts_list.append(ts.strip()[:26])
        fmap = _field_map(r)
        pile = _clean_pile(fmap.get("pile_code"))
        if pile:
            piles.add(pile)
        g = _int(fmap.get("gun_no"))
        if g is not None:
            guns.add(g)

        if cmd == 104:
            status_frames.append((ts if isinstance(ts, str) else None, fmap, r))
        elif cmd in (202, 222):
            bills.append(
                {
                    "log_ts": ts,
                    "pile_code": fmap.get("pile_code"),
                    "gun_no": g,
                    "card_no": _clean_card(fmap.get("card_no")),
                    "start_time": fmap.get("start_time"),
                    "end_time": fmap.get("end_time"),
                    "duration_sec": _int(fmap.get("duration_sec")),
                    "soc_start": _int(fmap.get("soc_start")),
                    "soc_end": _int(fmap.get("soc_end")),
                    "stop_reason_code": _int(fmap.get("stop_reason")),
                    "stop_reason": _stop_text(fmap.get("stop_reason")),
                    "session_energy": _num(fmap.get("session_energy")),
                    "session_money": _num(fmap.get("session_money")),
                    "meter_before": _num(fmap.get("meter_before")),
                    "meter_after": _num(fmap.get("meter_after")),
                }
            )
        elif cmd == 5:
            # 命令地址 2 + 参数 0x55 = 平台远程停止
            is_stop = fmap.get("is_remote_stop") is True or (
                _int(fmap.get("ctrl_addr")) == 2 and _int(fmap.get("ctrl_param")) == 0x55
            )
            if is_stop:
                stop_cmds += 1
                remote_stops.append(
                    {
                        "log_ts": ts if isinstance(ts, str) else None,
                        "gun_no": g,
                        "source": "cmd5",
                        "ctrl_addr": _int(fmap.get("ctrl_addr")),
                    }
                )
        elif cmd == 6:
            is_stop_ack = fmap.get("is_remote_stop") is True or _int(fmap.get("ctrl_addr")) == 2
            if is_stop_ack:
                stop_ack += 1
                if not any(
                    s.get("source") == "cmd5"
                    and s.get("gun_no") == g
                    and s.get("log_ts") == (ts if isinstance(ts, str) else None)
                    for s in remote_stops
                ):
                    # 仅有应答时也记一笔远程停止证据（少数抓包缺下行）
                    remote_stops.append(
                        {
                            "log_ts": ts if isinstance(ts, str) else None,
                            "gun_no": g,
                            "source": "cmd6",
                            "ctrl_addr": _int(fmap.get("ctrl_addr")),
                        }
                    )
        elif cmd == 7:
            start_cmds += 1
        elif cmd == 8:
            start_ack += 1
        elif cmd == 106:
            sign_ins += 1

    # 从状态帧还原过程峰值
    process: dict[str, Any] = {
        "energies": [],
        "fees": [],
        "volts": [],
        "currs": [],
        "socs": [],
        "charge_seconds": [],
        "work_status": Counter(),
        "card": None,
        "start_time": None,
        "first_charging_ts": None,
        "last_charging_ts": None,
        "end_ts": None,
    }
    for ts, fmap, r in status_frames:
        ws = _int(fmap.get("work_status"))
        if ws is not None:
            process["work_status"][ws] += 1
        energy = _num(fmap.get("session_energy"))
        fee = _num(fmap.get("session_fee"))
        # 交流优先取 A 相；直流取 dc
        volt = _num(fmap.get("ac_a_voltage")) or _num(fmap.get("dc_voltage"))
        curr = _num(fmap.get("ac_a_current")) or _num(fmap.get("dc_current"))
        soc = _int(fmap.get("soc"))
        secs = _int(fmap.get("charge_seconds"))
        card = _clean_card(fmap.get("card_or_user"))
        st = fmap.get("start_or_reserve_time")
        if card and not process["card"]:
            process["card"] = card
        if st and st != "-" and not process["start_time"]:
            process["start_time"] = st
        if ws == 2:  # 充电进行中
            if energy is not None:
                process["energies"].append(energy)
            if fee is not None:
                process["fees"].append(fee)
            if volt is not None and volt > 0.1:
                process["volts"].append(volt)
            if curr is not None and abs(curr) > 0.05:
                process["currs"].append(abs(curr))
            if soc is not None and 0 < soc <= 100:
                process["socs"].append(soc)
            if secs is not None:
                process["charge_seconds"].append(secs)
            if ts:
                if not process["first_charging_ts"]:
                    process["first_charging_ts"] = ts
                process["last_charging_ts"] = ts
        if ws == 3 and ts:
            process["end_ts"] = ts

    pile_text = "、".join(sorted(piles)) if piles else (meta.get("pile") or "-")
    gun_text = "、".join(str(g) for g in sorted(guns)) if guns else "-"
    start_ts = min(ts_list) if ts_list else "-"
    end_ts = max(ts_list) if ts_list else "-"

    # 订单：优先充电记录 202/222；否则用状态过程推算
    orders: list[dict[str, Any]] = []
    for b in bills:
        orders.append(
            {
                **b,
                "source": "cmd202",
                "start_way": None,
            }
        )
    if not orders and (process["energies"] or process["first_charging_ts"]):
        orders.append(
            {
                "pile_code": pile_text if pile_text != "-" else None,
                "gun_no": next(iter(sorted(guns)), None),
                "card_no": process["card"],
                "start_time": process["start_time"] or process["first_charging_ts"],
                "end_time": process["end_ts"] or process["last_charging_ts"],
                "duration_sec": max(process["charge_seconds"]) if process["charge_seconds"] else None,
                "session_energy": max(process["energies"]) if process["energies"] else None,
                "session_money": max(process["fees"]) if process["fees"] else None,
                "stop_reason": "未见充电记录上报，按状态帧推算",
                "source": "status104",
            }
        )

    # 补齐过程峰值到订单
    for o in orders:
        if process["energies"]:
            o["process_energy"] = max(process["energies"])
        if process["fees"]:
            o["process_fee"] = max(process["fees"])
        if process["volts"]:
            o["voltage_range"] = f"{min(process['volts']):.1f}～{max(process['volts']):.1f} V"
        if process["currs"]:
            o["current_range"] = f"{min(process['currs']):.1f}～{max(process['currs']):.1f} A"
        if o.get("start_way") is None:
            # 从任一充电中状态帧取启动方式
            for _, fmap, r in status_frames:
                if _int(fmap.get("work_status")) == 2:
                    meaning = _field_meaning(r, "start_way")
                    o["start_way"] = meaning or fmap.get("start_way")
                    break

    charging_n = int(process["work_status"].get(2, 0))
    idle_n = int(process["work_status"].get(0, 0))
    primary = orders[0] if orders else None
    top_types = "；".join(f"{k}×{v}" for k, v in type_counter.most_common(10))

    def _energy_text(v: Any) -> str:
        return f"{v} kWh" if v is not None else "-"

    def _money_text(v: Any) -> str:
        return f"{v} 元" if v is not None else "-"

    def _duration_text(sec: Any) -> str:
        n = _int(sec)
        if n is None:
            return "-"
        return f"{n // 60} 分 {n % 60} 秒"

    def _avg_text(vals: list[float], unit: str) -> str:
        if not vals:
            return "-"
        return f"{round(sum(vals) / len(vals), 1)} {unit}"

    def _rng_text(vals: list[float], unit: str) -> str:
        if not vals:
            return "-"
        return f"{min(vals):.1f}～{max(vals):.1f} {unit}"

    pile_ui = (primary or {}).get("pile_code") or pile_text or "-"
    gun_ui = (primary or {}).get("gun_no")
    if gun_ui is None and guns:
        gun_ui = next(iter(sorted(guns)))
    gun_text_ui = f"{gun_ui} 枪" if gun_ui is not None else "-"
    energy_ui = (primary or {}).get("session_energy")
    money_ui = (primary or {}).get("session_money")
    start_ui = (primary or {}).get("start_time") or "-"
    end_ui = (primary or {}).get("end_time") or "-"
    dur_ui = _duration_text((primary or {}).get("duration_sec"))
    card_ui = (primary or {}).get("card_no") or process["card"] or "-"
    start_way_ui = (primary or {}).get("start_way") or "-"
    meter_before = (primary or {}).get("meter_before")
    meter_after = (primary or {}).get("meter_after")

    def _match_remote_stop(order: dict[str, Any] | None) -> dict[str, Any] | None:
        """匹配本订单的平台停止控制（CMD=5/6）。停止帧常略晚于账单 end_time、早于记录上报。"""
        if not order or not remote_stops:
            return None
        og = _int(order.get("gun_no"))
        cands = [s for s in remote_stops if og is None or s.get("gun_no") in (None, og)]
        if not cands:
            return None
        start_key = str(order.get("start_time") or "")[:19]
        # 上界取账单上报时间，避免误吃下一单停止指令
        upper = str(order.get("log_ts") or order.get("end_time") or "")[:19]
        in_window = []
        for s in cands:
            ts = str(s.get("log_ts") or "")[:19]
            if not ts:
                continue
            if start_key and ts < start_key:
                continue
            if upper and ts > upper:
                continue
            in_window.append(s)
        pool = in_window or [s for s in cands if s.get("source") == "cmd5"] or cands
        # 优先下行 CMD=5
        downs = [s for s in pool if s.get("source") == "cmd5"]
        return (downs or pool)[-1]

    matched_stop = _match_remote_stop(primary)
    device_finish = (primary or {}).get("stop_reason") or "-"
    stop_code = (primary or {}).get("stop_reason_code")
    has_remote_stop = matched_stop is not None or (
        stop_code in SH_REMOTE_STOP_REASON_CODES
    )
    if has_remote_stop:
        # 原始报文无平台 stopReasonMsg：与 JSON 报告一致，默认用户远程停止
        stop_type = "用户远程停止"
        stop_ui = (
            "用户远程停止充电（平台下发 CMD=5 停止充电）"
            if matched_stop
            else f"用户远程停止充电（设备结束原因：{device_finish}）"
        )
        platform_stop_ui = "-"
        if matched_stop:
            gun_bit = (
                f"（枪 {matched_stop.get('gun_no')}）"
                if matched_stop.get("gun_no") is not None
                else ""
            )
            src = "CMD=5" if matched_stop.get("source") == "cmd5" else "CMD=6 应答"
            stop_evidence = f"识别到平台{src}停止充电{gun_bit}；设备结束原因：{device_finish}"
        else:
            stop_evidence = f"设备结束原因为后台停止（{device_finish}），判定为远程停止"
    elif primary:
        stop_type = "设备停止"
        stop_ui = device_finish
        platform_stop_ui = "-"
        stop_evidence = f"未见平台停止控制命令；设备结束原因：{device_finish}；卡号/账号 {card_ui}"
    else:
        stop_type = "-"
        stop_ui = "-"
        platform_stop_ui = "-"
        stop_evidence = "-"

    soc_start = (primary or {}).get("soc_start")
    soc_end = (primary or {}).get("soc_end")
    proc_socs = list(process.get("socs") or [])
    if soc_start is not None and soc_end is not None:
        soc_ui = f"{soc_start}% → {soc_end}%"
    elif soc_start is not None:
        soc_ui = f"{soc_start}%"
    elif soc_end is not None:
        soc_ui = f"{soc_end}%"
    elif proc_socs:
        soc_ui = f"{min(proc_socs)}% ～ {max(proc_socs)}%"
    else:
        soc_ui = "未上报"
    soc_reported = soc_ui != "未上报"

    volts = list(process.get("volts") or [])
    currs = list(process.get("currs") or [])
    energies = list(process.get("energies") or [])
    cur_avg = _avg_text(currs, "A")
    cur_rng = _rng_text(currs, "A")
    vol_avg = _avg_text(volts, "V")
    vol_rng = _rng_text(volts, "V")
    sample_n = max(len(volts), len(currs), len(energies))

    # 启动校验：枪口进入充电 + 过程电流/电压/电量（对齐 JSON / 云快充多帧）
    entered_charging = charging_n > 0
    has_vi = bool(volts or currs)
    has_energy_proc = bool(energies) or (
        energy_ui is not None and float(energy_ui) > 0
    )
    start_bits: list[str] = []
    start_problems: list[str] = []
    if start_cmds or start_ack or (start_way_ui and start_way_ui != "-"):
        if start_cmds:
            start_bits.append("平台下发开启充电")
        if start_ack:
            start_bits.append("桩应答开启充电")
        if start_way_ui and start_way_ui != "-":
            start_bits.append(f"启动方式 {start_way_ui}")
    else:
        start_problems.append("未见启动指令/启动方式")
    if entered_charging:
        start_bits.append("枪口已进入充电")
    else:
        start_problems.append("未见枪口进入充电")
    if has_vi:
        start_bits.append("过程有电流/电压上报")
    else:
        start_problems.append("无电流/电压上报")
    if has_energy_proc:
        start_bits.append("过程有电量上报")
    else:
        start_problems.append("无电量过程上报")
    # 充分条件：进入充电且有电气或电量过程，或账单电量>0
    start_ok = entered_charging and (has_vi or has_energy_proc)
    if start_ok:
        start_msg = "启动校验通过：" + "；".join(start_bits)
        start_result_ui = "启动成功"
        start_check_label = "通过"
    else:
        start_msg = "启动校验异常：" + "；".join(start_problems)
        if start_bits:
            start_msg += "。已具备：" + "；".join(start_bits)
        start_result_ui = "-"
        start_check_label = "异常"

    # 结论区：对齐 JSON；第 1 条写启动校验要点（不写帧数）
    points: list[str] = []
    if start_ok:
        way = start_way_ui if start_way_ui and start_way_ui != "-" else "启动"
        points.append(f"1. {way}成功，枪口已进入充电，过程有电流/电压/电量上报。")
    else:
        points.append(f"1. {start_msg}")
    if primary:
        points.append(
            f"2. 本订单充电桩 {pile_ui}，{gun_text_ui}，"
            f"{start_ui} 启动，{end_ui} 结束，充电时长 {dur_ui}。"
        )
        points.append(
            f"3. 停止类型「{stop_type}」，原因：{stop_ui}；"
            f"设备结束原因：{device_finish}；费用合计约 {_money_text(money_ui)}。"
        )
        points.append("4. 未产生占桩计费，占桩费用为 0 元。")
        if energy_ui is not None:
            points.append(f"5. 实际充电量以结算电量 {energy_ui} kWh 为准。")
        if not start_ok:
            points.append(f"{len(points) + 1}. 启动校验未通过，详见启动校验说明。")
    else:
        points.append(f"2. 充电桩 {pile_text}，枪号 {gun_text}，未见完整充电记录。")
        if not start_ok:
            points.append("3. 启动校验未通过，详见启动校验说明。")

    verdict = (
        (
            f"综合判断：{stop_type}，结算与结束原因可核对。"
            if start_ok
            else "综合判断：启动校验未通过，需复核后确认。"
        )
        if primary or start_ok
        else "综合判断：已识别盛弘报文，但未形成完整充电订单。"
    )
    conclusion = (
        f"本订单于 {start_ui} 启动、{end_ui} 结束，电量 {_energy_text(energy_ui)}，"
        f"费用 {_money_text(money_ui)}。"
        if primary
        else (points[0] if points else "盛弘报文分析")
    )

    warnings: list[dict[str, Any]] = []
    if not start_ok:
        warnings.append({"code": "START_FAIL", "level": "warn", "message": start_msg})

    # 项目表：字段名对齐 JSON；帧统计与过程电压/电流放在项目明细供研发查看
    fields: list[dict[str, Any]] = [
        {"name": "充电桩编号", "value": pile_ui},
        {"name": "枪口号", "value": gun_text_ui},
        {"name": "服务ID", "value": "-"},
        {"name": "订单流水号", "value": "-"},
        {"name": "手机号", "value": "-"},
        {"name": "车牌号", "value": "-"},
        {"name": "启动方式", "value": start_way_ui},
        {"name": "启动结果", "value": start_result_ui},
        {"name": "启动时间", "value": start_ui},
        {"name": "结束时间", "value": end_ui},
        {"name": "充电时长", "value": dur_ui},
        {"name": "SOC", "value": soc_ui},
        {"name": "启动时账户余额", "value": "-"},
        {"name": "充电电流（平均）", "value": cur_avg},
        {"name": "充电电流（范围）", "value": cur_rng},
        {"name": "充电电压（平均）", "value": vol_avg},
        {"name": "充电电压（范围）", "value": vol_rng},
        {"name": "需求电流（平均）", "value": "-"},
        {"name": "需求电流（范围）", "value": "-"},
        {"name": "需求电压（平均）", "value": "-"},
        {"name": "需求电压（范围）", "value": "-"},
        {"name": "输出功率（平均）", "value": "-"},
        {"name": "输出功率（范围）", "value": "-"},
        {"name": "实时采样点数", "value": str(sample_n) if sample_n else "-"},
        {"name": "起始终端表码", "value": _energy_text(meter_before)},
        {"name": "结束终端表码", "value": _energy_text(meter_after)},
        {"name": "实际充电电量", "value": _energy_text(energy_ui)},
        {"name": "账单总电量", "value": _energy_text(energy_ui)},
        {"name": "启动校验", "value": start_check_label},
        {"name": "启动校验说明", "value": start_msg},
        {"name": "枪口是否进入充电", "value": "是" if entered_charging else "否"},
        {"name": "过程是否有电流/电压上报", "value": "是" if has_vi else "否"},
        {"name": "过程是否有电量上报", "value": "是" if has_energy_proc else "否"},
        {
            "name": "电池荷电状态",
            "value": soc_ui if soc_reported else "未上报（全程为 0）",
        },
        {"name": "车辆识别码", "value": "-"},
        {"name": "电费", "value": _money_text(money_ui)},
        {"name": "服务费", "value": "0 元"},
        {"name": "占桩费", "value": "0 元"},
        {"name": "预约费", "value": "0 元"},
        {"name": "费用合计", "value": _money_text(money_ui)},
        {"name": "是否有远程停止指令", "value": "有" if has_remote_stop else "无"},
        {"name": "停止类型", "value": stop_type},
        {"name": "停止原因", "value": stop_ui},
        {"name": "平台停止原因", "value": platform_stop_ui},
        {"name": "设备结束原因", "value": device_finish if primary else "-"},
        {"name": "结束原因代码", "value": str(stop_code) if stop_code is not None else "-"},
        {
            "name": "停止依据",
            "value": stop_evidence if primary else "-",
        },
        {"name": "本单异常/告警摘录", "value": "无"},
        {"name": "告警信息", "value": "无"},
        {"name": "是否占桩计费", "value": "否"},
        {"name": "占桩时长", "value": "-"},
        {"name": "占桩费用", "value": "0 元"},
        # 研发明细（结论区不展示）
        {"name": "解析帧数", "value": str(len(sh))},
        {"name": "状态充电中帧数", "value": str(charging_n)},
        {"name": "状态空闲帧数", "value": str(idle_n)},
        {"name": "签到次数", "value": str(sign_ins)},
        {"name": "开启充电指令次数", "value": str(start_cmds)},
        {"name": "开启充电应答次数", "value": str(start_ack)},
        {"name": "停止充电指令次数", "value": str(stop_cmds)},
        {"name": "停止充电应答次数", "value": str(stop_ack)},
        {"name": "帧类型统计", "value": top_types or "-"},
        {"name": "日志开始时间", "value": start_ts},
        {"name": "日志结束时间", "value": end_ts},
    ]

    report_lines = [
        "充电订单分析报告",
        "",
        "【结论】",
        conclusion,
        "",
        *points,
        "",
        verdict,
        "",
        "【订单信息】",
        f"充电桩编号：{pile_ui}",
        f"枪口号：{gun_text_ui}",
        f"启动方式：{start_way_ui}",
        f"启动结果：{start_result_ui}",
        f"启动时间：{start_ui}",
        f"结束时间：{end_ui}",
        f"充电时长：{dur_ui}",
        f"SOC：{soc_ui}",
        f"启动校验：{start_check_label}",
        f"启动校验说明：{start_msg}",
        f"枪口是否进入充电：{'是' if entered_charging else '否'}",
        f"过程是否有电流/电压上报：{'是' if has_vi else '否'}",
        f"过程是否有电量上报：{'是' if has_energy_proc else '否'}",
        "",
        "【电气与电量】",
        f"充电电流（平均）：{cur_avg}",
        f"充电电流（范围）：{cur_rng}",
        f"充电电压（平均）：{vol_avg}",
        f"充电电压（范围）：{vol_rng}",
        f"起始终端表码：{_energy_text(meter_before)}",
        f"结束终端表码：{_energy_text(meter_after)}",
        f"实际充电电量：{_energy_text(energy_ui)}",
        "",
        "【费用】",
        f"电费：{_money_text(money_ui)}",
        "服务费：0 元",
        "占桩费：0 元",
        f"费用合计：{_money_text(money_ui)}",
        "",
        "【停止与占桩】",
        f"是否有远程停止指令：{'有' if has_remote_stop else '无'}",
        f"停止类型：{stop_type}",
        f"停止原因：{stop_ui}",
        f"设备结束原因：{device_finish if primary else '-'}",
        f"停止依据：{stop_evidence}",
        "是否占桩计费：否",
        "占桩时长：-",
        "",
        "【研发明细】",
        f"解析帧数：{len(sh)}",
        f"状态充电中帧数：{charging_n}",
        f"状态空闲帧数：{idle_n}",
        f"帧类型统计：{top_types or '-'}",
    ]

    return {
        "mode": "charging_report",
        "protocol": "shenghong",
        "protocol_name": "盛弘",
        "confidence": 0.92,
        "frame_type": None,
        "frame_type_name": "充电订单分析",
        "direction": None,
        "valid": start_ok if (primary or entered_charging or start_cmds) else True,
        "summary": "\n".join(points + ["", verdict]),
        "conclusion": conclusion,
        "verdict": verdict,
        "result_points": points,
        "report_text": "\n".join(report_lines),
        "fields": fields,
        "warnings": warnings,
        "raw_hex": None,
        "raw_json": None,
        "extras": {
            "source": meta.get("source") or "protocol_frames",
            "frame_count": len(sh),
            "piles": sorted(piles),
            "guns": sorted(guns),
            "type_stats": dict(type_counter),
            "orders": orders,
            "status_charging_frames": charging_n,
            "sign_ins": sign_ins,
            "card_no": card_ui,
            "start_check": {
                "ok": start_ok,
                "message": start_msg,
                "entered_charging": entered_charging,
                "has_vi": has_vi,
                "has_energy": has_energy_proc,
            },
        },
    }


def _format_order(idx: int, o: dict[str, Any]) -> str:
    gun = o.get("gun_no")
    parts = [f"{idx}. 枪{gun if gun is not None else '?'}"]
    if o.get("card_no"):
        parts.append(f"卡号 {o['card_no']}")
    st, et = o.get("start_time") or "-", o.get("end_time") or "-"
    parts.append(f"{st} ～ {et}")
    if o.get("duration_sec") is not None:
        sec = int(o["duration_sec"])
        parts.append(f"时长 {sec // 60} 分 {sec % 60} 秒")
    if o.get("session_energy") is not None:
        parts.append(f"电量 {o['session_energy']} kWh")
    if o.get("session_money") is not None:
        parts.append(f"金额 {o['session_money']} 元")
    if o.get("stop_reason"):
        parts.append(f"结束：{o['stop_reason']}")
    if o.get("source") == "status104":
        parts.append("（状态帧推算）")
    return "；".join(parts)
