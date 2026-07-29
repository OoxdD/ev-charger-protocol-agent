"""南网 IEC104 扩展多帧会话汇总（纯协议抓包）— 含订单充电数据。"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from evcpa.knowledge.csg import CSG_ASDU_TYPES, CSG_RECORD_TYPES
from evcpa.models import AnalysisResult


def _field_map(r: AnalysisResult) -> dict[str, Any]:
    return {f.name: f.value for f in r.fields}


def _me_values(fmap: dict[str, Any]) -> list[int]:
    keys = sorted(
        (k for k in fmap if k.startswith("me_") and k[3:].isdigit()),
        key=lambda x: int(x[3:]),
    )
    out: list[int] = []
    for k in keys:
        v = fmap[k]
        if isinstance(v, int):
            out.append(v)
    return out


def _md0(fmap: dict[str, Any]) -> float | None:
    v = fmap.get("md_0")
    if isinstance(v, int):
        return round(v / 100.0, 2)
    return None


def _is_charging_dc(vals: list[int]) -> bool:
    """直流遥测：输出电压/电流明显升高，或充电机状态=3。"""
    if len(vals) < 2:
        return False
    v, i = vals[0], vals[1]
    st = vals[6] if len(vals) > 6 else None
    if st == 3:
        return True
    return v > 100 and i > 50


def _reconstruct_orders_from_telemetry(results: list[AnalysisResult]) -> list[dict[str, Any]]:
    """从类型 11/132 遥测还原充电会话，作为加密业务体的订单近似。"""
    # 时间序列：枪 -> [(ts, me_vals)] / [(ts, md_kwh)]
    me_series: dict[int, list[tuple[str, list[int]]]] = defaultdict(list)
    md_series: dict[int, list[tuple[str, float]]] = defaultdict(list)
    for r in results:
        ts = str((r.extras or {}).get("log_ts") or "")
        fmap = _field_map(r)
        g = fmap.get("gun_no")
        if not isinstance(g, int):
            continue
        if str(r.frame_type) == "11":
            vals = _me_values(fmap)
            if vals:
                me_series[g].append((ts, vals))
        elif str(r.frame_type) == "132":
            md = _md0(fmap)
            if md is not None:
                md_series[g].append((ts, md))

    sessions: list[dict[str, Any]] = []
    for g, pts in me_series.items():
        cur: dict[str, Any] | None = None
        for ts, vals in pts:
            charging = _is_charging_dc(vals)
            v = vals[0] / 10.0
            i = vals[1] / 100.0
            soc = vals[3] if len(vals) > 3 else None
            if charging and cur is None:
                cur = {
                    "gun_no": g,
                    "start_time": ts,
                    "end_time": ts,
                    "start_voltage": round(v, 1),
                    "end_voltage": round(v, 1),
                    "max_voltage": round(v, 1),
                    "max_current": round(i, 1),
                    "start_soc": soc,
                    "end_soc": soc,
                    "source": "telemetry",
                }
            elif charging and cur is not None:
                cur["end_time"] = ts
                cur["end_voltage"] = round(v, 1)
                cur["max_voltage"] = max(cur["max_voltage"], round(v, 1))
                cur["max_current"] = max(cur["max_current"], round(i, 1))
                cur["end_soc"] = soc
            elif (not charging) and cur is not None:
                sessions.append(cur)
                cur = None
        if cur is not None:
            sessions.append(cur)

    def _md_at(g: int, ts: str, *, which: str) -> float | None:
        series = md_series.get(g) or []
        if not series or not ts:
            return None
        if which == "start":
            cand = [x for x in series if x[0] <= ts]
            return cand[-1][1] if cand else series[0][1]
        cand = [x for x in series if x[0] >= ts]
        return cand[0][1] if cand else series[-1][1]

    for s in sessions:
        g = int(s["gun_no"])
        m0 = _md_at(g, str(s.get("start_time") or ""), which="start")
        m1 = _md_at(g, str(s.get("end_time") or ""), which="end")
        s["start_meter"] = m0
        s["end_meter"] = m1
        if m0 is not None and m1 is not None and m1 >= m0:
            s["total_kwh"] = round(m1 - m0, 2)
        else:
            s["total_kwh"] = None
        s["encrypted_business"] = True

    sessions.sort(key=lambda x: str(x.get("start_time") or ""))
    return sessions


def _orders_from_business(
    results: list[AnalysisResult],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """从已解密/明文的 A.3、以及过程帧末态提取订单。"""
    orders: list[dict[str, Any]] = []
    process_by_trade: dict[str, dict[str, Any]] = {}

    for r in results:
        biz = (r.extras or {}).get("business")
        if not isinstance(biz, dict):
            continue
        rec = biz.get("record_type")
        ts = (r.extras or {}).get("log_ts")
        if rec == 17 and not biz.get("encrypted") and biz.get("trade_no"):
            trade = str(biz["trade_no"])
            prev = process_by_trade.get(trade)
            # 保留累计电量更大的过程帧
            if prev is None or float(biz.get("total_kwh") or 0) >= float(prev.get("total_kwh") or 0):
                process_by_trade[trade] = {**biz, "log_ts": ts}
        elif rec == 2 and not biz.get("encrypted"):
            orders.append(
                {
                    "gun_no": biz.get("gun_no"),
                    "pile_code": biz.get("pile_code"),
                    "trade_no": biz.get("trade_no"),
                    "start_time": biz.get("start_time"),
                    "end_time": biz.get("end_time") or ts,
                    "total_kwh": biz.get("total_kwh"),
                    "total_fee": biz.get("total_fee") or biz.get("consume_amount"),
                    "elec_fee": biz.get("elec_fee"),
                    "service_amount": biz.get("service_amount"),
                    "stop_reason": biz.get("stop_reason"),
                    "vin": biz.get("vin"),
                    "start_meter": biz.get("start_meter"),
                    "end_meter": biz.get("end_meter"),
                    "source": "a3_charge_record",
                    "encrypted_business": False,
                    "log_ts": ts,
                }
            )

    # 无 A.3 时用过程帧近似成单
    if not orders and process_by_trade:
        for trade, biz in process_by_trade.items():
            orders.append(
                {
                    "gun_no": biz.get("gun_no"),
                    "pile_code": biz.get("pile_code"),
                    "trade_no": trade,
                    "order_no": biz.get("order_no"),
                    "start_time": biz.get("start_time"),
                    "end_time": biz.get("end_time") or biz.get("log_ts"),
                    "total_kwh": biz.get("total_kwh"),
                    "total_fee": biz.get("charge_fee") or biz.get("total_fee"),
                    "vin": biz.get("vin"),
                    "charged_minutes": biz.get("charged_minutes"),
                    "source": "a33_process",
                    "encrypted_business": False,
                    "log_ts": biz.get("log_ts"),
                }
            )

    # 加密的 A.3：仅记录时间戳，供与遥测会话配对
    enc_records: list[dict[str, Any]] = []
    for r in results:
        fmap = _field_map(r)
        if fmap.get("record_type") != 2:
            continue
        biz = (r.extras or {}).get("business") or {}
        if biz and not biz.get("encrypted") and biz.get("trade_no"):
            continue
        enc_records.append(
            {
                "log_ts": (r.extras or {}).get("log_ts"),
                "pile_code": biz.get("pile_code") if isinstance(biz, dict) else None,
                "payload_len": biz.get("payload_len") if isinstance(biz, dict) else None,
                "encrypted_business": True,
                "source": "a3_encrypted",
            }
        )
    return orders, enc_records


def _pair_telemetry_with_records(
    sessions: list[dict[str, Any]],
    enc_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """按结束时间就近配对：充电记录上传时刻 ≈ 会话结束。"""
    used: set[int] = set()
    for s in sessions:
        end = str(s.get("end_time") or "")
        best_i = None
        for i, rec in enumerate(enc_records):
            if i in used:
                continue
            rts = str(rec.get("log_ts") or "")
            if not end or not rts:
                continue
            # 记录应在结束后上传
            if rts < end:
                continue
            best_i = i
            break
        if best_i is not None:
            used.add(best_i)
            rec = enc_records[best_i]
            s["charge_record_ts"] = rec.get("log_ts")
            s["pile_code"] = s.get("pile_code") or rec.get("pile_code")
            s["has_charge_record"] = True
        else:
            s["has_charge_record"] = False
    # 未配对的加密记录也列出
    for i, rec in enumerate(enc_records):
        if i in used:
            continue
        sessions.append(
            {
                "gun_no": None,
                "start_time": None,
                "end_time": rec.get("log_ts"),
                "total_kwh": None,
                "pile_code": rec.get("pile_code"),
                "charge_record_ts": rec.get("log_ts"),
                "has_charge_record": True,
                "source": "a3_encrypted",
                "encrypted_business": True,
                "note": "有充电记录上传，但业务体加密且未能匹配遥测会话",
            }
        )
    return sessions


def _format_order_line(idx: int, o: dict[str, Any]) -> str:
    gun = o.get("gun_no")
    gun_s = f"枪{gun}" if gun is not None else "枪?"
    parts = [f"{idx}. {gun_s}"]
    if o.get("trade_no"):
        parts.append(f"流水 {o['trade_no']}")
    if o.get("order_no"):
        parts.append(f"订单 {o['order_no']}")
    st, et = o.get("start_time") or "-", o.get("end_time") or "-"
    parts.append(f"{st} ～ {et}")
    if o.get("total_kwh") is not None:
        parts.append(f"电量 {o['total_kwh']} kWh")
    if o.get("total_fee") is not None:
        parts.append(f"费用 {o['total_fee']} 元")
    if o.get("start_soc") is not None or o.get("end_soc") is not None:
        parts.append(f"SOC {o.get('start_soc')}→{o.get('end_soc')}")
    if o.get("max_voltage") is not None:
        parts.append(f"峰值 {o['max_voltage']}V/{o.get('max_current')}A")
    if o.get("stop_reason"):
        parts.append(f"结束：{o['stop_reason']}")
    if o.get("encrypted_business") and o.get("source") == "telemetry":
        parts.append("（遥测推算；业务体加密）")
    if o.get("charge_record_ts"):
        parts.append(f"记录上传 {o['charge_record_ts']}")
    if o.get("note"):
        parts.append(str(o["note"]))
    return "；".join(parts)


def aggregate_csg_session(results: list[AnalysisResult], *, meta: dict[str, Any] | None = None) -> dict[str, Any]:
    """将南网多帧解析结果汇总为可读会话报告（含订单充电数据）。"""
    meta = meta or {}
    csg = [r for r in results if r.protocol.value == "csg"]
    if not csg:
        csg = results

    type_counter: Counter[str] = Counter()
    record_counter: Counter[str] = Counter()
    guns: set[int] = set()
    u_count = 0
    i_count = 0
    ts_list: list[str] = []
    pile_codes: set[str] = set()
    encrypted_biz = False

    for r in csg:
        ft = r.frame_type or "?"
        if ft == "U":
            u_count += 1
            type_counter["U 启停/测试"] += 1
        else:
            i_count += 1
            name = (
                CSG_ASDU_TYPES.get(int(ft), r.frame_type_name or ft)
                if str(ft).isdigit()
                else (r.frame_type_name or ft)
            )
            type_counter[str(name)] += 1
        fmap = _field_map(r)
        if "gun_no" in fmap and isinstance(fmap["gun_no"], int):
            guns.add(int(fmap["gun_no"]))
        if "record_type" in fmap:
            rec = fmap["record_type"]
            label = CSG_RECORD_TYPES.get(int(rec), str(rec)) if isinstance(rec, int) else str(rec)
            record_counter[label] += 1
        if fmap.get("pile_code"):
            pile_codes.add(str(fmap["pile_code"]))
        biz = (r.extras or {}).get("business")
        if isinstance(biz, dict):
            if biz.get("encrypted"):
                encrypted_biz = True
            if biz.get("pile_code"):
                pile_codes.add(str(biz["pile_code"]))
        ts = (r.extras or {}).get("log_ts")
        if isinstance(ts, str) and ts.strip():
            ts_list.append(ts.strip()[:26])

    gun_text = "、".join(str(g) for g in sorted(guns)) if guns else "-"
    start_ts = min(ts_list) if ts_list else "-"
    end_ts = max(ts_list) if ts_list else "-"
    pile_text = "、".join(sorted(pile_codes)) if pile_codes else (meta.get("pile") or "-")

    plain_orders, enc_records = _orders_from_business(csg)
    orders: list[dict[str, Any]]
    if plain_orders:
        orders = plain_orders
        order_source = "business_plaintext"
    else:
        sessions = _reconstruct_orders_from_telemetry(csg)
        orders = _pair_telemetry_with_records(sessions, enc_records)
        order_source = "telemetry_fallback"

    points = [
        f"1. 共解析南网报文 {len(csg)} 帧（I 帧 {i_count}，U/S 链路帧 {u_count}）。",
        f"2. 设备编号：{pile_text}；枪号：{gun_text}。",
        f"3. 日志时间范围：{start_ts} ～ {end_ts}。",
    ]
    if record_counter:
        top = "；".join(f"{k}×{v}" for k, v in record_counter.most_common(6))
        points.append(f"4. 业务记录类型：{top}。")
    else:
        points.append("4. 本段以遥信/遥测循环上送为主，未见类型 130 业务记录。")

    if orders:
        points.append(f"5. 识别订单充电数据 {len(orders)} 笔（来源：{'明文业务' if order_source == 'business_plaintext' else '遥测推算+充电记录配对'}）。")
        for i, o in enumerate(orders[:8], 1):
            points.append("   " + _format_order_line(i, o))
        if len(orders) > 8:
            points.append(f"   … 另有 {len(orders) - 8} 笔见下方汇总字段。")
        if order_source == "telemetry_fallback" and encrypted_biz:
            points.append(
                "6. 充电记录/过程业务体为 SM4 软加密，流水号与费用明细需配置密钥 "
                "EVCPA_CSG_SM4_KEY（32 位 hex）后解密；当前电量来自变长遥测有功总电度差值。"
            )
    else:
        top_types = "；".join(f"{k}×{v}" for k, v in type_counter.most_common(6))
        points.append(f"5. 帧类型统计：{top_types}。")
        if encrypted_biz:
            points.append("6. 业务载荷疑似加密，未能还原订单；请提供 SM4 密钥或平台侧解密报文。")

    top_types = "；".join(f"{k}×{v}" for k, v in type_counter.most_common(8))
    if orders and not any(p.startswith("5. 帧类型") for p in points):
        points.append(f"7. 帧类型统计：{top_types}。")

    verdict = (
        f"综合判断：已识别 {len(orders)} 笔订单充电数据"
        + (
            "（业务明文）。"
            if order_source == "business_plaintext"
            else "（业务体加密，由遥测与充电记录上传时刻还原）。"
        )
    )

    fields: list[dict[str, Any]] = [
        {"name": "协议", "value": "南方电网"},
        {"name": "规约", "value": "系统与充电设施（2020-04-28）"},
        {"name": "解析帧数", "value": str(len(csg))},
        {"name": "设备编号", "value": pile_text},
        {"name": "枪号", "value": gun_text},
        {"name": "开始时间", "value": start_ts},
        {"name": "结束时间", "value": end_ts},
        {"name": "订单笔数", "value": str(len(orders))},
        {"name": "订单数据来源", "value": "明文业务体" if order_source == "business_plaintext" else "遥测推算"},
        {
            "name": "业务记录统计",
            "value": "；".join(f"{k}×{v}" for k, v in record_counter.most_common(12)) or "-",
        },
        {"name": "帧类型统计", "value": top_types or "-"},
    ]

    for i, o in enumerate(orders, 1):
        fields.append({"name": f"订单{i}", "value": _format_order_line(i, o)})
        detail_bits = []
        if o.get("start_meter") is not None and o.get("end_meter") is not None:
            detail_bits.append(f"表计 {o['start_meter']}→{o['end_meter']} kWh")
        if o.get("vin"):
            detail_bits.append(f"VIN {o['vin']}")
        if detail_bits:
            fields.append({"name": f"订单{i}明细", "value": "；".join(detail_bits)})

    report_lines = [
        "充电设施通信分析报告（南方电网 / 协议抓包）",
        "",
        f"数据来源：{meta.get('source') or 'protocol_trace_log'}",
        "",
        "【结论要点】",
        *points,
        "",
        verdict,
        "",
        "【订单充电数据】",
    ]
    if orders:
        for i, o in enumerate(orders, 1):
            report_lines.append(_format_order_line(i, o))
    else:
        report_lines.append("（无）")
    report_lines.extend(["", "【汇总字段】"])
    for f in fields:
        report_lines.append(f"{f['name']}：{f['value']}")

    warnings: list[dict[str, Any]] = []
    if encrypted_biz and order_source == "telemetry_fallback":
        warnings.append(
            {
                "code": "CSG_BUSINESS_ENCRYPTED",
                "level": "warn",
                "message": "业务体 SM4 加密：订单电量/时段来自遥测推算；流水号与费用需密钥解密",
            }
        )

    return {
        "mode": "charging_report",
        "protocol": "csg",
        "protocol_name": "南方电网",
        "confidence": 0.9,
        "frame_type": None,
        "frame_type_name": f"南网多帧会话（{len(csg)} 帧）",
        "direction": None,
        "valid": True,
        "summary": "\n".join(points + ["", verdict]),
        "conclusion": points[0] if points else "南网多帧分析",
        "verdict": verdict,
        "result_points": points,
        "report_text": "\n".join(report_lines),
        "fields": fields,
        "warnings": warnings,
        "raw_hex": None,
        "raw_json": None,
        "extras": {
            "source": meta.get("source") or "protocol_frames",
            "frame_count": len(csg),
            "guns": sorted(guns),
            "pile_codes": sorted(pile_codes),
            "type_stats": dict(type_counter),
            "record_stats": dict(record_counter),
            "orders": orders,
            "order_source": order_source,
            "encrypted_business": encrypted_biz,
        },
    }
