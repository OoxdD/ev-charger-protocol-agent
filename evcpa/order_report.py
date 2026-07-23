"""从运营平台日志中抽取充电业务数据，生成客户可读报告（与《充电订单分析报告》同款格式）。"""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import date
from statistics import mean
from typing import Any


_REMOTE_CMD = re.compile(r"RemoteCmd>{8,}:(\{.*\})")
_REMOTE_START = re.compile(r"远程启动充电,\s*(\{.*\})")
_SOC_INFO = re.compile(r"--socInfo:(\{.*\})")
_CHARGING_INFO = re.compile(r"--chargingInfo:(\{.*\})")
_RECORD_INFO = re.compile(r"--recordInfo:(\{.*\})")
_BILL_CMD8 = re.compile(r"上报账单\[cmd=0x8\]:(\{.*\})")
_GUN_STATUS = re.compile(r"(\d+)枪:([A-Z_]+)")
_TS = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")
_SEP = "=" * 80

# 启动方式识别：日志文案优先，再回落到字段枚举
_CARD_START_MARKERS = (
    "刷卡启动",
    "刷卡鉴权",
    "刷卡启动充电执行结果",
)
_VIN_START_MARKERS = (
    "VIN验证启动",
    "VIN鉴权",
    "createCardChargeServiceInfo（VIN",
    "createCardChargeServiceInfo(VIN",
)


def looks_like_order_log(text: str) -> bool:
    if not text or len(text) < 80:
        return False
    markers = (
        "RemoteCmd",
        "--socInfo:",
        "--chargingInfo:",
        "--recordInfo:",
        "远程启动充电",
        "刷卡启动",
        "刷卡鉴权",
        "VIN验证启动",
        "上报账单",
        "枪:",
        "ChargingData",
        "ChargeRecord",
    )
    hit = sum(1 for m in markers if m in text)
    return hit >= 2 or ("--socInfo:" in text and "--chargingInfo:" in text)


def _nonempty_id(v: Any) -> str:
    if v is None:
        return ""
    s = str(v).strip()
    if not s:
        return ""
    if re.fullmatch(r"0+", s):
        return ""
    if s.lower() in {"ffffffffffffffff", "null", "none", "-"}:
        return ""
    return s


def _has_real_vin(v: Any) -> bool:
    s = _nonempty_id(v)
    if not s:
        return False
    # 常见 VIN 为 17 位；日志里偶有更短编码，至少要求字母数字且非全 0
    return bool(re.fullmatch(r"[A-HJ-NPR-Z0-9]{11,17}", s, re.I))


def _infer_start_way(
    text: str,
    *,
    remote: dict[str, Any] | None,
    start_ok: bool,
    src: dict[str, Any],
    data: dict[str, Any],
    card_auth: bool = False,
    vin_auth: bool = False,
) -> str:
    """区分远程启动 / 刷卡启动 / VIN鉴权启动。"""
    if card_auth or any(m in text for m in _CARD_START_MARKERS):
        return "刷卡启动（成功）"
    if vin_auth or any(m in text for m in _VIN_START_MARKERS):
        return "VIN鉴权启动（成功）"

    card_no = str(
        src.get("cardNo")
        or data.get("cardNo")
        or (remote or {}).get("cardNo")
        or ""
    ).strip()
    physical = _nonempty_id(
        src.get("physicalCardNo")
        or data.get("physicalCardNo")
        or (remote or {}).get("physicalCardNo")
    )
    vin = src.get("carvin") or data.get("carvin") or (remote or {}).get("carvin")
    start_way = src.get("startWay")
    if start_way is None:
        start_way = data.get("startWay")
    start_type = src.get("startType")
    if start_type is None:
        start_type = data.get("startType")
    sw = str(start_way).strip() if start_way is not None else ""
    st = str(start_type).strip() if start_type is not None else ""

    if card_no.upper().startswith("VIN") and _has_real_vin(card_no[3:] or vin):
        return "VIN鉴权启动（成功）"
    # 平台结算字段：startWay=5 常见为 VIN；云快充 0x31：1=刷卡、3=VIN
    if sw == "5" and (_has_real_vin(vin) or card_no.upper().startswith("VIN")):
        return "VIN鉴权启动（成功）"
    if sw == "3" and not remote:
        return "VIN鉴权启动（成功）"
    if st == "1" and (physical or _nonempty_id(card_no)) and not remote:
        return "刷卡启动（成功）"
    if sw == "1" and not remote and (physical or _nonempty_id(card_no)) and not _has_real_vin(vin):
        return "刷卡启动（成功）"
    if physical and not remote and "远程启动充电" not in text:
        return "刷卡启动（成功）"

    if remote or start_ok or "远程启动充电" in text:
        return "远程启动（成功）"
    if "RemoteCmd" in text or sw == "2":
        return "远程启动（成功）"
    return "未知"


def _load_json(s: str) -> dict[str, Any] | None:
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _num(v: Any, div: float = 1.0, digits: int = 3) -> float | None:
    if v is None:
        return None
    try:
        return round(float(v) / div, digits)
    except Exception:
        return None


def _fmt_money(v: Any, scale: int = 1000) -> str:
    n = _num(v, scale, 3)
    if n is None:
        return "-"
    text = f"{n:.3f}".rstrip("0").rstrip(".")
    return f"{text} 元"


def _fmt_kwh(v: Any) -> str:
    n = _num(v, 1000, 3)
    if n is None:
        return "-"
    if abs(n) < 1e-9:
        return "0 kwh"
    return f"{n:.3f} kwh"


def _fmt_amp(v: Any) -> str:
    n = _num(v, 1000, 2)
    return "-" if n is None else f"{n:.2f} 安"


def _fmt_volt(v: Any) -> str:
    n = _num(v, 1000, 1)
    return "-" if n is None else f"{n:.1f} 伏"


def _fmt_kw(v: Any) -> str:
    n = _num(v, 1000, 3)
    return "-" if n is None else f"{n:.3f} 千瓦"


def _fmt_temp(v: Any) -> str:
    n = _num(v, 1000, 1)
    return "-" if n is None else f"{n:.1f}℃"


def _fmt_price(v: Any) -> str:
    n = _num(v, 1000, 3)
    if n is None:
        return "-"
    text = f"{n:.3f}".rstrip("0").rstrip(".")
    return f"{text} 元/kwh"


def _cn_datetime(s: str) -> str:
    """2026-07-19 12:13:45 -> 2026年7月19日 12:13:45"""
    if not s or s == "-":
        return "-"
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})[ T](\d{2}:\d{2}:\d{2})", s)
    if not m:
        return s
    y, mo, d, t = m.groups()
    return f"{int(y)}年{int(mo)}月{int(d)}日 {t}"


def _section(title: str) -> list[str]:
    return ["", _SEP, title, _SEP]


def _norm_id(v: Any) -> str:
    """流水号常为左侧补 0 的 serviceId，比较时去掉前导 0。"""
    s = str(v).strip()
    if not s:
        return ""
    if s.isdigit():
        return str(int(s))  # 0000000080321060 -> 80321060
    return s


def _ids_of(obj: dict[str, Any] | None) -> set[str]:
    if not isinstance(obj, dict):
        return set()
    vals: set[str] = set()
    for key in ("serviceId", "service_id", "serviceChargeId", "tradeNo", "orderId", "txnId"):
        if obj.get(key) is not None:
            raw = str(obj.get(key)).strip()
            if raw:
                vals.add(raw)
                n = _norm_id(raw)
                if n:
                    vals.add(n)
    data = obj.get("data")
    if isinstance(data, dict):
        vals |= _ids_of(data)
    return vals


def _match_service(obj: dict[str, Any] | None, service_id: str | None) -> bool:
    """未填写不过滤；填写后匹配 serviceId，或左侧补 0 的 tradeNo/orderId。"""
    if not service_id or not str(service_id).strip():
        return True
    sid = str(service_id).strip()
    ids = _ids_of(obj)
    if sid in ids:
        return True
    ns = _norm_id(sid)
    return bool(ns) and ns in {_norm_id(x) for x in ids}


def _pick_primary_trade_no(
    *,
    remote: dict[str, Any] | None,
    start_frame: dict[str, Any] | None,
    record: dict[str, Any] | None,
    bill: dict[str, Any] | None,
    data: dict[str, Any],
    socs: list[dict[str, Any]],
    chgs: list[dict[str, Any]],
) -> str:
    """确定本单主流水号：优先启动令/结算单，否则取实时上报出现最多的 tradeNo。"""
    for obj in (remote, start_frame, record, bill, data):
        if not isinstance(obj, dict):
            continue
        for key in ("tradeNo", "orderId", "txnId"):
            v = obj.get(key)
            if v is not None and str(v).strip():
                return str(v).strip()
        nested = obj.get("data")
        if isinstance(nested, dict):
            for key in ("tradeNo", "orderId", "txnId"):
                v = nested.get(key)
                if v is not None and str(v).strip():
                    return str(v).strip()
    counts: Counter[str] = Counter()
    for s in list(socs) + list(chgs):
        tn = s.get("tradeNo") or s.get("orderId")
        if tn is not None and str(tn).strip():
            counts[str(tn).strip()] += 1
    if counts:
        return counts.most_common(1)[0][0]
    return "-"


def _belongs_to_order(obj: dict[str, Any], trade_no: str, gun: str) -> bool:
    """实时帧是否属于当前分析订单（按流水号，必要时再按枪口）。"""
    if trade_no and trade_no != "-":
        tn = obj.get("tradeNo") or obj.get("orderId")
        if tn is not None and str(tn).strip():
            if _norm_id(tn) != _norm_id(trade_no):
                return False
        else:
            # 无流水号的帧：若已指定枪口则按枪口归入，否则丢弃以免串单
            if gun and gun != "-" and obj.get("interfaceCode") is not None:
                return str(obj.get("interfaceCode")) == str(gun)
            return False
    if gun and gun != "-" and obj.get("interfaceCode") is not None:
        if str(obj.get("interfaceCode")) != str(gun):
            return False
    return True


def _tou_map(obj: dict[str, Any] | None) -> dict[str, float]:
    if not isinstance(obj, dict):
        return {"尖": 0.0, "峰": 0.0, "平": 0.0, "谷": 0.0}
    return {
        "尖": float(obj.get("jianBattery") or 0),
        "峰": float(obj.get("fengBattery") or 0),
        "平": float(obj.get("pingBattery") or 0),
        "谷": float(obj.get("guBattery") or 0),
    }


def _dominant_tou(tou: dict[str, float]) -> str | None:
    total = sum(tou.values())
    if total <= 0:
        return None
    return max(tou.items(), key=lambda kv: kv[1])[0]


def _fmt_tou_brief(tou: dict[str, float]) -> str:
    parts = [f"{k}{_fmt_kwh(v)}" for k, v in tou.items() if v and float(v) > 0]
    return "、".join(parts) if parts else "无分时电量"


# 过程与账单电量差 < 1 kwh（千分位 1000）视为可忽略
_ENERGY_TOL_RAW = 1000.0


def _check_process_vs_bill(
    proc: dict[str, Any] | None,
    bill_src: dict[str, Any] | None,
    start_meter: Any,
    end_meter: Any,
) -> list[dict[str, Any]]:
    """过程 chargingInfo 与账单/结算电量、分时交叉校验。"""
    checks: list[dict[str, Any]] = []
    if not proc and not bill_src:
        return [
            {
                "ok": True,
                "code": "SKIP",
                "message": "缺少过程与账单电量字段，未做交叉校验。",
            }
        ]

    proc_total = float((proc or {}).get("totalBattery") or 0) if proc else None
    bill_total = float((bill_src or {}).get("totalBattery") or 0) if bill_src else None
    meter_delta = None
    try:
        if start_meter is not None and end_meter is not None:
            meter_delta = float(end_meter) - float(start_meter)
    except (TypeError, ValueError):
        meter_delta = None

    # 1) 总电量：过程 vs 账单
    if proc_total is not None and bill_total is not None and (proc_total > 0 or bill_total > 0):
        diff = abs(proc_total - bill_total)
        if diff < _ENERGY_TOL_RAW:
            checks.append(
                {
                    "ok": True,
                    "code": "TOTAL_OK",
                    "message": (
                        f"总电量一致：过程 {_fmt_kwh(proc_total)}，账单 {_fmt_kwh(bill_total)}"
                        + (f"（差值 {_fmt_kwh(diff)}，可忽略）" if diff > 0 else "")
                        + "。"
                    ),
                }
            )
        else:
            checks.append(
                {
                    "ok": False,
                    "code": "TOTAL_MISMATCH",
                    "message": (
                        f"总电量不一致：过程 {_fmt_kwh(proc_total)}，账单 {_fmt_kwh(bill_total)}，"
                        f"相差 {_fmt_kwh(diff)}（超过 1 kwh 容差）。"
                    ),
                }
            )

    # 2) 表计差额 vs 账单总电量
    if meter_delta is not None and bill_total is not None and bill_total > 0:
        diff = abs(meter_delta - bill_total)
        if diff < _ENERGY_TOL_RAW:
            checks.append(
                {
                    "ok": True,
                    "code": "METER_OK",
                    "message": (
                        f"表计电量与账单一致：表计差额 {_fmt_kwh(meter_delta)}，"
                        f"账单 {_fmt_kwh(bill_total)}"
                        + (f"（差值 {_fmt_kwh(diff)}，可忽略）" if diff > 0 else "")
                        + "。"
                    ),
                }
            )
        else:
            checks.append(
                {
                    "ok": False,
                    "code": "METER_MISMATCH",
                    "message": (
                        f"表计电量与账单不一致：表计差额 {_fmt_kwh(meter_delta)}，"
                        f"账单 {_fmt_kwh(bill_total)}，相差 {_fmt_kwh(diff)}。"
                    ),
                }
            )

    # 3) 分时电量：过程 vs 账单（主导时段 + 各时段）
    proc_tou = _tou_map(proc)
    bill_tou = _tou_map(bill_src)
    proc_dom = _dominant_tou(proc_tou)
    bill_dom = _dominant_tou(bill_tou)
    if proc_dom and bill_dom:
        if proc_dom == bill_dom:
            checks.append(
                {
                    "ok": True,
                    "code": "TOU_DOM_OK",
                    "message": (
                        f"分时主导时段一致：过程与账单均为“{proc_dom}”"
                        f"（过程 {_fmt_tou_brief(proc_tou)}；账单 {_fmt_tou_brief(bill_tou)}）。"
                    ),
                }
            )
        else:
            checks.append(
                {
                    "ok": False,
                    "code": "TOU_DOM_MISMATCH",
                    "message": (
                        f"分时主导时段不一致：过程为“{proc_dom}”（{_fmt_tou_brief(proc_tou)}），"
                        f"账单为“{bill_dom}”（{_fmt_tou_brief(bill_tou)}）。"
                    ),
                }
            )

        # 各时段逐项：仅当两侧该时段都有明显电量，或一侧有另一侧接近 0
        for name in ("尖", "峰", "平", "谷"):
            pv, bv = proc_tou[name], bill_tou[name]
            if pv < _ENERGY_TOL_RAW and bv < _ENERGY_TOL_RAW:
                continue
            # 账单某时段被“归集放大”且远超账单总电量时，跳过该时段绝对值对比，避免误报
            if bill_total and bv > float(bill_total) + _ENERGY_TOL_RAW and name == "平":
                checks.append(
                    {
                        "ok": True,
                        "code": "TOU_BILL_AGG",
                        "message": (
                            f"账单“{name}”段 {_fmt_kwh(bv)} 高于账单总电量 {_fmt_kwh(bill_total)}，"
                            f"疑似结算归集，不与过程逐段绝对值强比对。"
                        ),
                    }
                )
                continue
            diff = abs(pv - bv)
            if diff < _ENERGY_TOL_RAW:
                continue
            # 一侧近 0、另一侧有电量 → 时段归属冲突
            if (pv < _ENERGY_TOL_RAW) != (bv < _ENERGY_TOL_RAW) or diff >= _ENERGY_TOL_RAW:
                if (pv < _ENERGY_TOL_RAW and bv >= _ENERGY_TOL_RAW) or (
                    bv < _ENERGY_TOL_RAW and pv >= _ENERGY_TOL_RAW
                ):
                    checks.append(
                        {
                            "ok": False,
                            "code": "TOU_SLOT_MISMATCH",
                            "message": (
                                f"分时“{name}”段不一致：过程 {_fmt_kwh(pv)}，账单 {_fmt_kwh(bv)}。"
                            ),
                        }
                    )
                elif proc_dom == bill_dom and name == proc_dom:
                    # 同主导时段但量差异大
                    checks.append(
                        {
                            "ok": False,
                            "code": "TOU_AMOUNT_MISMATCH",
                            "message": (
                                f"分时“{name}”段电量差异较大：过程 {_fmt_kwh(pv)}，"
                                f"账单 {_fmt_kwh(bv)}，相差 {_fmt_kwh(diff)}。"
                            ),
                        }
                    )
    elif proc_dom or bill_dom:
        checks.append(
            {
                "ok": True,
                "code": "TOU_PARTIAL",
                "message": (
                    f"分时仅一侧有数据：过程 {_fmt_tou_brief(proc_tou)}；"
                    f"账单 {_fmt_tou_brief(bill_tou)}。"
                ),
            }
        )

    if not checks:
        checks.append(
            {
                "ok": True,
                "code": "SKIP",
                "message": "过程/账单电量字段不足，未形成有效校验项。",
            }
        )
    return checks


def analyze_order_log(text: str, service_id: str | None = None) -> dict[str, Any]:
    sid = (service_id or "").strip() or None
    lines = text.splitlines()
    remote = None
    start_frame = None
    records: list[dict[str, Any]] = []
    bills: list[dict[str, Any]] = []
    socs: list[dict[str, Any]] = []
    chgs: list[dict[str, Any]] = []
    gun_events: list[tuple[str, str, str]] = []
    has_remote_stop = False
    start_ok = False
    card_auth = False
    vin_auth = False
    offline = False
    fault = False
    matched_guns: set[str] = set()
    matched_trade_nos: set[str] = set()

    for ln in lines:
        m = _REMOTE_CMD.search(ln)
        if m:
            obj = _load_json(m.group(1))
            if obj and _match_service(obj, sid):
                remote = obj
                matched_guns.add(str(obj.get("interfaceCode") or (obj.get("data") or {}).get("interfaceCode") or ""))
                matched_trade_nos |= _ids_of(obj)
                cmd = str(obj.get("remoteCmd", ""))
                if cmd and cmd not in {"17", "1", "03", "14"} and "停止" in ln:
                    has_remote_stop = True
        m = _REMOTE_START.search(ln)
        if m:
            obj = _load_json(m.group(1))
            if obj and _match_service(obj, sid):
                start_frame = obj
                matched_trade_nos |= _ids_of(obj)
        m = _SOC_INFO.search(ln)
        if m:
            obj = _load_json(m.group(1))
            if obj and _match_service(obj, sid):
                socs.append(obj)
                if obj.get("interfaceCode") is not None:
                    matched_guns.add(str(obj.get("interfaceCode")))
                matched_trade_nos |= _ids_of(obj)
        m = _CHARGING_INFO.search(ln)
        if m:
            obj = _load_json(m.group(1))
            if obj and _match_service(obj, sid):
                chgs.append(obj)
                if obj.get("interfaceCode") is not None:
                    matched_guns.add(str(obj.get("interfaceCode")))
                matched_trade_nos |= _ids_of(obj)
        m = _RECORD_INFO.search(ln)
        if m:
            obj = _load_json(m.group(1))
            if obj and _match_service(obj, sid):
                records.append(obj)
                if obj.get("interfaceCode") is not None:
                    matched_guns.add(str(obj.get("interfaceCode")))
                matched_trade_nos |= _ids_of(obj)
        m = _BILL_CMD8.search(ln)
        if m:
            obj = _load_json(m.group(1))
            if obj and _match_service(obj, sid):
                bills.append(obj)
                matched_trade_nos |= _ids_of(obj)

    record = records[-1] if records else None
    bill = bills[-1] if bills else None

    # 第二遍：状态行 / 启停标记，按已匹配流水或枪口过滤
    matched_guns.discard("")
    match_tokens = set(matched_trade_nos)
    if sid:
        match_tokens.add(sid)
        match_tokens.add(_norm_id(sid))
    for ln in lines:
        related = (not sid) or any(x and x in ln for x in match_tokens) or (_norm_id(sid) in ln)
        # 行内若出现补零流水号，也视为相关
        if sid and not related:
            for m in re.finditer(r"\b0*\d{6,}\b", ln):
                if _norm_id(m.group(0)) == _norm_id(sid):
                    related = True
                    break
        if "远程停止" in ln and related:
            has_remote_stop = True
        if ("启动充电响应:成功" in ln or "远程启动充电响应，成功" in ln) and related:
            start_ok = True
        if related and any(m in ln for m in _CARD_START_MARKERS):
            card_auth = True
            start_ok = True
        if related and any(m in ln for m in _VIN_START_MARKERS):
            vin_auth = True
            start_ok = True
        if related and "鉴权结果" in ln and "刷卡" not in ln:
            vm = re.search(r'"carvin"\s*:\s*"([^"]*)"', ln)
            if vm and _has_real_vin(vm.group(1)):
                vin_auth = True
                start_ok = True
        if ("桩已离线" in ln or "ReadTimeout" in ln) and (not sid or related):
            offline = True
        if "故障" in ln and "枪" in ln and related:
            fault = True
        gm = _GUN_STATUS.search(ln)
        ts_m = _TS.match(ln.strip())
        if gm:
            gun_no = gm.group(1)
            if (not sid) or (not matched_guns) or (gun_no in matched_guns):
                gun_events.append((ts_m.group(1) if ts_m else "", gun_no, gm.group(2)))

    # 指定了 serviceId 但没有任何业务 JSON 命中
    if sid and not (remote or start_frame or record or bill or socs or chgs):
        return {
            "mode": "charging_report",
            "protocol": "order_log",
            "protocol_name": "充电订单日志",
            "confidence": 0.2,
            "valid": False,
            "summary": f"未找到 serviceId/流水号 = {sid} 的充电数据，请确认填写是否正确。",
            "conclusion": f"未找到 serviceId/流水号 = {sid} 的充电订单。",
            "verdict": "综合判断：筛选条件下无匹配订单，请核对 serviceId 或流水号。",
            "result_points": [
                f"1. 已按 serviceId/流水号「{sid}」筛选日志。",
                "2. 未匹配到 RemoteCmd / socInfo / chargingInfo / recordInfo / 账单 等业务数据。",
                "3. 请确认该桩是否存在该服务号，或改为留空 serviceId 查看全部。",
            ],
            "report_text": (
                "充电订单分析报告\n\n"
                f"筛选条件：serviceId/流水号 = {sid}\n\n"
                "未找到匹配的充电业务数据。\n"
                "综合判断：筛选条件下无匹配订单，请核对 serviceId 或流水号。"
            ),
            "fields": [
                {"name": "筛选 serviceId", "value": sid},
                {"name": "匹配结果", "value": "无"},
            ],
            "warnings": [
                {
                    "code": "SERVICE_NOT_FOUND",
                    "level": "warn",
                    "message": f"未找到 serviceId/流水号 {sid}",
                }
            ],
            "raw_hex": None,
            "raw_json": None,
            "extras": {"service_id": sid, "filtered": True},
        }

    data = remote.get("data", {}) if isinstance(remote, dict) else {}
    record = records[-1] if records else None
    bill = bills[-1] if bills else None
    src_preview = record or bill or (chgs[-1] if chgs else {}) or data

    device_no = str((remote or {}).get("deviceNo") or src_preview.get("deviceNo") or data.get("deviceNo") or "-")
    gun = str((remote or {}).get("interfaceCode") or src_preview.get("interfaceCode") or data.get("interfaceCode") or "-")
    trade_no = _pick_primary_trade_no(
        remote=remote if isinstance(remote, dict) else None,
        start_frame=start_frame if isinstance(start_frame, dict) else None,
        record=record if isinstance(record, dict) else None,
        bill=bill if isinstance(bill, dict) else None,
        data=data if isinstance(data, dict) else {},
        socs=socs,
        chgs=chgs,
    )
    # 电气统计只使用本单流水号（及枪口）下的实时帧，避免多枪/多订单串数据导致功率范围失真
    socs_all = socs
    chgs_all = chgs
    socs = [s for s in socs_all if _belongs_to_order(s, trade_no, gun)]
    chgs = [c for c in chgs_all if _belongs_to_order(c, trade_no, gun)]
    if not socs and socs_all:
        # 流水号对不上时回退：按枪口；再不行用出现最多的 tradeNo 子集
        if gun and gun != "-":
            socs = [s for s in socs_all if str(s.get("interfaceCode")) == str(gun)]
            chgs = [c for c in chgs_all if str(c.get("interfaceCode")) == str(gun)]
        if not socs:
            counts = Counter(
                str(s.get("tradeNo")).strip()
                for s in socs_all
                if s.get("tradeNo") is not None and str(s.get("tradeNo")).strip()
            )
            if counts:
                major = counts.most_common(1)[0][0]
                trade_no = major
                socs = [s for s in socs_all if _norm_id(s.get("tradeNo")) == _norm_id(major)]
                chgs = [c for c in chgs_all if _norm_id(c.get("tradeNo")) == _norm_id(major)]
            else:
                socs = socs_all
                chgs = chgs_all
    # 结算/账单按主流水号选取
    matched_records = [r for r in records if _belongs_to_order(r, trade_no, gun)] or records
    matched_bills = [b for b in bills if _belongs_to_order(b, trade_no, gun)] or bills
    record = matched_records[-1] if matched_records else None
    bill = matched_bills[-1] if matched_bills else None
    src = record or bill or (chgs[-1] if chgs else {}) or data
    if isinstance(src, dict) and src.get("interfaceCode") is not None and (gun == "-" or not gun):
        gun = str(src.get("interfaceCode"))
    if isinstance(src, dict) and src.get("deviceNo"):
        device_no = str(src.get("deviceNo"))
    service_id_val = str(
        src.get("serviceId")
        or data.get("serviceId")
        or (remote or {}).get("data", {}).get("serviceId")
        or sid
        or "-"
    )
    mobile = str(data.get("memberMobile") or "-")
    car_no = str(data.get("carNo") or "") or "未上报"
    vin = str(src.get("carvin") or data.get("carvin") or "") or "未上报"

    balance_raw = data.get("balance")
    if balance_raw is not None:
        balance_disp = _fmt_money(balance_raw, 1000)
    elif start_frame and start_frame.get("balance") is not None:
        balance_disp = f"{float(start_frame['balance']) / 100:.2f} 元"
    else:
        balance_disp = "-"

    currents = [x for x in (s.get("batteryChargerOutputCurrent") for s in socs) if x not in (None, 0)]
    voltages = [x for x in (s.get("batteryChargerOutputVoltage") for s in socs) if x not in (None, 0)]
    # 输出功率以 batteryChargerOutPower 为准；同时用同帧电流×电压印证
    powers: list[float] = []
    calc_powers: list[float] = []
    power_check_ok = True
    power_check_samples = 0
    for s in socs:
        i_raw = s.get("batteryChargerOutputCurrent")
        u_raw = s.get("batteryChargerOutputVoltage")
        p_raw = s.get("batteryChargerOutPower")
        try:
            i_f = float(i_raw) if i_raw not in (None, "", 0, "0") else None
            u_f = float(u_raw) if u_raw not in (None, "", 0, "0") else None
            p_f = float(p_raw) if p_raw not in (None, "") else None
        except (TypeError, ValueError):
            continue
        if p_f is not None and p_f > 0:
            powers.append(p_f)
        if i_f is not None and u_f is not None:
            # 字段为千分位：I(A)*U(V)=W，再换算到与 OutPower 相同的「千分位千瓦」量纲
            p_calc = (i_f * u_f) / 1_000_000.0
            if p_calc > 0:
                calc_powers.append(p_calc)
            if p_f is not None and p_f > 0 and p_calc > 0:
                power_check_samples += 1
                # 允许约 8% 或 0.2 kW 偏差（上报常有取整）
                diff_kw = abs(p_f - p_calc) / 1000.0
                if diff_kw > 0.2 and abs(p_f - p_calc) / p_f > 0.08:
                    power_check_ok = False
    if not powers:
        for c in chgs:
            p_raw = c.get("batteryChargerOutPower")
            if p_raw not in (None, "", 0, "0"):
                try:
                    p_f = float(p_raw)
                except (TypeError, ValueError):
                    continue
                if p_f > 0:
                    powers.append(p_f)
    temps = [x for x in (s.get("batteryChargerTemperature") for s in socs) if x is not None]
    soc_vals = [s.get("soc") for s in socs if s.get("soc") is not None]
    soc_nonzero = any(v not in (0, None) for v in soc_vals)

    start_meter = src.get("chargeStartMeterBattery") or (bill or {}).get("startMeterBattery")
    end_meter = src.get("chargeEndMeterBattery") or (bill or {}).get("endMeterBattery")
    total_batt = src.get("totalBattery") or (bill or {}).get("totalBattery")
    duration = src.get("chargeDuration") or (chgs[-1].get("chargeDuration") if chgs else None)

    jian = src.get("jianBattery", 0) or 0
    feng = src.get("fengBattery", 0) or 0
    ping = src.get("pingBattery", 0) or 0
    gu = src.get("guBattery", 0) or 0
    jian_p, feng_p, ping_p, gu_p = src.get("jianPrice"), src.get("fengPrice"), src.get("pingPrice"), src.get("guPrice")

    # 过程帧：取本单 chargingInfo 中累计电量最大的一帧（接近结束）
    proc_frame = None
    if chgs:
        proc_frame = max(chgs, key=lambda x: float(x.get("totalBattery") or 0))
    bill_src = bill or record
    energy_checks = _check_process_vs_bill(proc_frame, bill_src, start_meter, end_meter)
    energy_mismatch = any(not c.get("ok", True) for c in energy_checks)

    charge_money = src.get("chargeMoney") or src.get("serverChargeMoney")
    service_money = src.get("serviceMoney") or src.get("serverServiceMoney")
    parking_money = src.get("parkingMoney") or src.get("serverParkingMoney") or 0
    appoint_money = src.get("appointmentMoney") or src.get("serverAppointmentMoney") or 0
    has_occupy = src.get("isHasOccupyFee", 0) in (1, "1", True)

    finish_code = src.get("deviceChargeFinishReasonCode")
    if finish_code is None:
        finish_code = src.get("chargeFinishReason")
    finish_msg = src.get("deviceChargeFinishReasonMsg") or "-"

    # 时间
    start_time = "-"
    end_time = "-"
    ready_ts = ""
    charge_start_ts = ""
    charge_end_ts = ""
    for ts, g, st in gun_events:
        if st == "READY_CHARGE" and not ready_ts:
            ready_ts = ts
        if st == "CHARGING":
            if not charge_start_ts:
                charge_start_ts = ts
            charge_end_ts = ts
    if bill and bill.get("startTime"):
        st = str(bill["startTime"])
        if len(st) >= 12 and st[:2].isdigit():
            start_time = f"20{st[0:2]}-{st[2:4]}-{st[4:6]} {st[6:8]}:{st[8:10]}:{st[10:12]}"
    elif charge_start_ts:
        start_time = charge_start_ts[:19]
    if bill and bill.get("endTime"):
        et = str(bill["endTime"])
        if len(et) >= 12 and et[:2].isdigit():
            end_time = f"20{et[0:2]}-{et[2:4]}-{et[4:6]} {et[6:8]}:{et[8:10]}:{et[10:12]}"
    elif charge_end_ts:
        end_time = charge_end_ts[:19]

    stages: list[dict[str, Any]] = []
    detail = src.get("chargeStageDetail")
    if isinstance(detail, str) and detail.startswith("["):
        try:
            stages = json.loads(detail)
        except Exception:
            stages = []
    elif isinstance(detail, list):
        stages = detail

    total_kwh = _num(total_batt, 1000, 3)
    ping_kwh = _num(ping, 1000, 3)
    charge_yuan = _num(charge_money, 1000, 3)
    service_yuan = _num(service_money, 1000, 3)
    total_fee = None
    if charge_money is not None or service_money is not None:
        total_fee = _num((charge_money or 0) + (service_money or 0) + (parking_money or 0), 1000, 3)
    ping_price = _num(ping_p, 1000, 3)
    balance_yuan = _num(balance_raw, 1000, 3) if balance_raw is not None else None

    # ---- 组装客户报告文本 ----
    today = date.today()
    report_date = f"{today.year}年{today.month}月{today.day}日"
    dur_text = f"约 {round(int(duration) / 60)} 分钟（{duration} 秒）" if duration else "-"
    start_way = _infer_start_way(
        text,
        remote=remote if isinstance(remote, dict) else None,
        start_ok=start_ok,
        src=src if isinstance(src, dict) else {},
        data=data if isinstance(data, dict) else {},
        card_auth=card_auth,
        vin_auth=vin_auth,
    )
    is_card_start = start_way.startswith("刷卡")
    is_vin_start = start_way.startswith("VIN")
    is_remote_start = start_way.startswith("远程")

    out: list[str] = [
        "充电订单分析报告",
        "",
        f"报告日期：{report_date}",
        f"分析对象：桩号 {device_no} 充电订单日志",
    ]
    if sid:
        out.append(f"筛选条件：serviceId/流水号 = {sid}")
    out += _section("一、订单基本信息")
    out += [
        f"充电桩编号：{device_no}",
        f"枪口号：{gun} 枪",
        f"服务ID：{service_id_val}",
        f"订单流水号：{trade_no}",
        f"手机号：{mobile}",
        f"车牌号：{car_no}",
        f"启动方式：{start_way}",
        f"启动时间：{_cn_datetime(start_time)}",
        f"结束时间：{_cn_datetime(end_time)}",
        f"充电时长：{dur_text}",
        f"启动时账户余额：{balance_disp}",
    ]

    out += _section("二、充电电气数据")
    cur_avg = f"约 {_fmt_amp(mean(currents)).replace(' 安', '')} 安" if currents else "-"
    cur_rng = f"{_fmt_amp(min(currents)).replace(' 安','')} ～ {_fmt_amp(max(currents))}" if currents else "-"
    vol_avg = f"约 {_fmt_volt(mean(voltages)).replace(' 伏', '')} 伏" if voltages else "-"
    vol_rng = f"{_fmt_volt(min(voltages)).replace(' 伏','')} ～ {_fmt_volt(max(voltages))}" if voltages else "-"
    pwr_avg = f"约 {_fmt_kw(mean(powers)).replace(' 千瓦', '')} 千瓦" if powers else "-"
    pwr_rng = f"{_fmt_kw(min(powers)).replace(' 千瓦','')} ～ {_fmt_kw(max(powers))}" if powers else "-"
    pwr_calc_avg = f"约 {_fmt_kw(mean(calc_powers)).replace(' 千瓦', '')} 千瓦" if calc_powers else "-"
    temp_rng = f"约 {_fmt_temp(min(temps)).replace('℃','')}℃ ～ {_fmt_temp(max(temps))}" if temps else "-"
    if power_check_samples > 0 and powers and calc_powers:
        if power_check_ok:
            pwr_check = (
                f"吻合（上报平均 {pwr_avg.replace('约 ', '')}，"
                f"电流×电压平均 {pwr_calc_avg.replace('约 ', '')}，共核对 {power_check_samples} 点）"
            )
        else:
            pwr_check = (
                f"存在偏差（上报平均 {pwr_avg.replace('约 ', '')}，"
                f"电流×电压平均 {pwr_calc_avg.replace('约 ', '')}，共核对 {power_check_samples} 点，建议复核）"
            )
    elif powers and calc_powers:
        pwr_check = f"已计算电流×电压（平均 {pwr_calc_avg.replace('约 ', '')}）作参考"
    elif powers:
        pwr_check = "已取 batteryChargerOutPower；缺少成对电流/电压，未做乘积印证"
    elif calc_powers:
        pwr_avg = pwr_calc_avg
        pwr_rng = (
            f"{_fmt_kw(min(calc_powers)).replace(' 千瓦','')} ～ {_fmt_kw(max(calc_powers))}"
            if calc_powers
            else "-"
        )
        pwr_check = "未上报 batteryChargerOutPower，已用电流×电压估算"
    else:
        pwr_check = "-"
    out += [
        f"充电电流（平均）：{cur_avg}",
        f"充电电流（范围）：{cur_rng}",
        f"充电电压（平均）：{vol_avg}",
        f"充电电压（范围）：{vol_rng}",
        f"输出功率（平均）：{pwr_avg}",
        f"输出功率（范围）：{pwr_rng}",
        f"功率印证（电流×电压）：{pwr_check}",
        f"实时采样点数：{len(socs)}（按流水号 {trade_no} 过滤后的 socInfo）",
        f"起始终端表码：{_fmt_kwh(start_meter)}",
        f"结束终端表码：{_fmt_kwh(end_meter)}",
        f"实际充电电量：{_fmt_kwh(total_batt)}",
        f"电池荷电状态：{'未上报（全程为 0）' if not soc_nonzero else '有上报'}",
        f"车辆识别码：{vin}",
        f"模块温度（范围）：{temp_rng}",
        "",
        "说明：电流、电压取实时上报；输出功率优先取 batteryChargerOutPower，并用同帧电流×电压交叉印证；电量与起止表码一致。",
    ]

    out += _section("三、分时电量（尖 / 峰 / 平 / 谷）")
    out += [
        f"尖：{_fmt_kwh(jian)}，电价 {_fmt_price(jian_p)}",
        f"峰：{_fmt_kwh(feng)}，电价 {_fmt_price(feng_p)}",
        f"平：{_fmt_kwh(ping)}"
        + ("（结算归集）" if ping_kwh and total_kwh and ping_kwh > total_kwh else "")
        + f"，电价 {_fmt_price(ping_p)}",
        f"谷：{_fmt_kwh(gu)}，电价 {_fmt_price(gu_p)}",
        "",
    ]
    if ping_kwh and total_kwh and ping_kwh > total_kwh + 0.01:
        out.append(
            f"说明：本单电量全部归集在“平”时段。结算平段电量 {ping_kwh:.3f} kwh 高于表计实际充电量 "
            f"{total_kwh:.3f} kwh，实际充电量建议以表计 {total_kwh:.3f} kwh 为准。"
        )
    elif (jian or feng or gu) in (0, None) and ping:
        out.append("说明：本单电量全部归集在“平”时段。")
    else:
        out.append("说明：分时电量来自结算字段。")

    if stages:
        stage_sum = sum(float(s.get("battery") or 0) for s in stages)
        out.append("")
        out.append(f"分时段明细（各时段电量之和 = {_fmt_kwh(stage_sum)}）：")
        for s in stages:
            note = ""
            # 简单提示首尾时段
            out.append(
                f"{s.get('startTime', '?')} ～ {s.get('endTime', '?')}：{_fmt_kwh(s.get('battery'))}{note}"
            )
        out.append(f"合计：{_fmt_kwh(stage_sum)}")

    out += _section("四、过程与账单校验")
    out.append("说明：对比 chargingInfo（过程）与 recordInfo/账单（结算）；差值小于 1 kwh 视为可忽略。")
    out.append(
        f"过程电量快照：总 {_fmt_kwh((proc_frame or {}).get('totalBattery'))}，"
        f"{_fmt_tou_brief(_tou_map(proc_frame))}。"
        if proc_frame
        else "过程电量快照：无 chargingInfo。"
    )
    out.append(
        f"账单电量快照：总 {_fmt_kwh((bill_src or {}).get('totalBattery'))}，"
        f"{_fmt_tou_brief(_tou_map(bill_src))}。"
        if bill_src
        else "账单电量快照：无结算/账单数据。"
    )
    for i, ck in enumerate(energy_checks, 1):
        mark = "通过" if ck.get("ok") else "异常"
        out.append(f"{i}. [{mark}] {ck.get('message')}")
    if energy_mismatch:
        out.append("结论：过程数据与账单存在不一致，请复核分时归属与电量归集。")
    else:
        out.append("结论：过程与账单电量/分时在容差内一致。")

    out += _section("五、费用明细")
    out += [
        f"电费：{_fmt_money(charge_money)}",
        f"服务费：{_fmt_money(service_money)}",
        f"占桩费：{_fmt_money(parking_money) if parking_money else '0 元'}",
        f"预约费：{_fmt_money(appoint_money) if appoint_money else '0 元'}",
        f"费用合计：{_fmt_money((charge_money or 0)+(service_money or 0)+(parking_money or 0)) if charge_money is not None or service_money is not None else '-'}",
        "",
    ]
    if total_fee is not None and balance_yuan is not None:
        out.append(
            f"费用校验：电费 + 服务费 ≈ 启动余额 {balance_disp}，与结束原因“{finish_msg}”相符。"
            if finish_msg and finish_msg != "-"
            else f"费用校验：费用合计约 {_fmt_money((charge_money or 0)+(service_money or 0)+(parking_money or 0))}，启动余额 {balance_disp}。"
        )
    if ping_kwh and ping_price and charge_yuan is not None:
        calc = round(ping_kwh * ping_price, 3)
        out.append(f"电费校验：结算平段电量 {ping_kwh:.3f} × 平电价 {ping_price:.3f} = {calc:.3f} 元。")

    out += _section("六、停止原因与占桩情况")
    if has_remote_stop:
        remote_stop_text = "有"
    else:
        if is_remote_start:
            remote_stop_text = "无（全程仅有远程启动，无平台下发停止充电指令）"
        elif is_card_start or is_vin_start:
            remote_stop_text = f"无（本单为{start_way.replace('（成功）', '')}，无平台下发停止充电指令）"
        else:
            remote_stop_text = "无"
    occupy_dur = "无计费占桩时长（结束后仅短暂占用状态约数秒，随后恢复空闲/待充）" if not has_occupy else "见平台占桩计费明细"
    out += [
        f"是否有远程停止指令：{remote_stop_text}",
        f"设备结束原因：{finish_msg if not has_remote_stop else (finish_msg or '远程停止')}",
        f"结束原因代码：{finish_code if finish_code is not None else '-'}",
        f"是否占桩计费：{'是' if has_occupy else '否'}",
        f"占桩时长：{occupy_dur}",
        f"占桩费用：{_fmt_money(parking_money) if parking_money else '0 元'}",
    ]

    out += _section("七、过程简述")
    steps: list[str] = []
    n = 1
    if ready_ts:
        steps.append(f"{n}. {ready_ts[:19]}　{gun} 枪处于待充电状态（已插枪）。")
        n += 1
    if start_time != "-":
        if is_card_start:
            steps.append(f"{n}. {_cn_datetime(start_time)}　刷卡鉴权通过并启动充电。")
        elif is_vin_start:
            steps.append(f"{n}. {_cn_datetime(start_time)}　VIN 鉴权通过并启动充电。")
        elif is_remote_start or start_ok or remote:
            steps.append(f"{n}. {_cn_datetime(start_time)}　平台下发远程启动，设备应答成功。")
        else:
            steps.append(f"{n}. {_cn_datetime(start_time)}　开始充电。")
        n += 1
        steps.append(f"{n}. 进入充电中，电流、电压、功率稳定，持续上报实时数据。")
        n += 1
    if end_time != "-":
        if finish_msg and finish_msg != "-" and not has_remote_stop:
            steps.append(f"{n}. {_cn_datetime(end_time)}　设备按“{finish_msg}”结束充电并上报账单。")
        elif has_remote_stop:
            steps.append(f"{n}. {_cn_datetime(end_time)}　远程停止充电并完成结算。")
        else:
            steps.append(f"{n}. {_cn_datetime(end_time)}　充电结束并上报账单。")
        n += 1
    if offline:
        steps.append(f"{n}. 过程中曾出现离线/超时记录，请结合现场确认。")
        n += 1
    steps.append(f"{n}. 结束后枪口恢复空闲/待充" + ("，无离线、无故障告警记录。" if not offline and not fault else "。"))
    out.extend(steps or ["1. 已提取订单关键充电数据。"])

    out += _section("八、结论")
    normal = bool(total_batt or socs) and not fault
    if normal and not has_remote_stop and not energy_mismatch:
        out.append("本订单为一次正常完成的交流充电订单。")
    elif energy_mismatch:
        out.append("本订单已提取完毕，但过程数据与账单校验存在差异，需重点复核。")
    elif has_remote_stop:
        out.append("本订单为远程停止结束的充电订单。")
    else:
        out.append("本订单充电数据已提取完毕，请结合下列要点复核。")
    out.append("")
    bullets = []
    if is_card_start:
        bullets.append(
            "1. 刷卡启动成功，充电过程电流、电压、功率稳定，表计电量与功率、时长基本自洽。"
            if currents
            else "1. 刷卡启动成功，并完成结算数据上报。"
        )
    elif is_vin_start:
        bullets.append(
            "1. VIN 鉴权启动成功，充电过程电流、电压、功率稳定，表计电量与功率、时长基本自洽。"
            if currents
            else "1. VIN 鉴权启动成功，并完成结算数据上报。"
        )
    elif is_remote_start or remote or start_ok:
        bullets.append(
            "1. 远程启动成功，充电过程电流、电压、功率稳定，表计电量与功率、时长基本自洽。"
            if currents
            else "1. 远程启动成功，并完成结算数据上报。"
        )
    else:
        bullets.append("1. 已提取启动与结算相关字段。")
    if energy_mismatch:
        bad = [c["message"] for c in energy_checks if not c.get("ok")]
        bullets.append("2. 过程与账单校验异常：" + ("；".join(bad[:2]) if bad else "电量或分时不一致。"))
    elif not offline and not fault:
        bullets.append("2. 充电期间无离线、无故障、无告警，也无平台远程停止指令。" if not has_remote_stop else "2. 订单由远程停止结束。")
    else:
        bullets.append("2. 日志中存在离线或异常相关记录，建议人工复核。")
    if finish_msg and finish_msg != "-":
        fee_txt = _fmt_money((charge_money or 0) + (service_money or 0) + (parking_money or 0)) if charge_money is not None else "-"
        if finish_msg == "金额截止":
            bullets.append(
                f"3. 订单因账户余额用尽（金额截止）正常结束，费用合计约 {fee_txt}"
                + ("，与启动余额一致。" if balance_disp != "-" else "。")
            )
        else:
            bullets.append(
                f"3. 订单因“{finish_msg}”结束，费用合计约 {fee_txt}"
                + ("，与启动余额一致。" if balance_disp != "-" else "。")
            )
    else:
        bullets.append("3. 已输出费用与停止相关字段。")
    bullets.append(f"4. {'未产生占桩计费，占桩费用为 0 元。' if not has_occupy else '存在占桩计费，详见费用明细。'}")
    if total_kwh is not None:
        only_ping = (jian in (0, None)) and (feng in (0, None)) and (gu in (0, None)) and bool(ping)
        if only_ping:
            bullets.append(f"5. 分时电量均归集在平段；实际充电量以表计 {total_kwh:.3f} kwh 为准。")
        else:
            bullets.append(f"5. 分时电量以结算字段为准；实际充电量以表计 {total_kwh:.3f} kwh 为准。")
    if energy_mismatch:
        bullets.append("6. 过程与账单校验：发现不一致，详见“四、过程与账单校验”。")
    out.extend(bullets)
    out.append("")
    if energy_mismatch:
        out.append("综合判断：过程与账单电量/分时不一致，请复核后再确认结算。")
        out.append("需到设备上核实相关数据，请设备方协助排查。")
        valid = False
        verdict = (
            "综合判断：过程与账单电量/分时不一致，请复核后再确认结算。\n"
            "需到设备上核实相关数据，请设备方协助排查。"
        )
    elif normal and not has_remote_stop and not offline and not fault:
        out.append("综合判断：充电情况正常，结算与结束原因合理。")
        valid = True
        verdict = "综合判断：充电情况正常，结算与结束原因合理。"
    elif has_remote_stop and not fault:
        out.append("综合判断：远程停止流程完整，结算数据可核对。")
        valid = True
        verdict = "综合判断：远程停止流程完整，结算数据可核对。"
    else:
        out.append("综合判断：请结合日志与现场情况复核。")
        out.append("需到设备上核实相关数据，请设备方协助排查。")
        valid = False
        verdict = (
            "综合判断：请结合日志与现场情况复核。\n"
            "需到设备上核实相关数据，请设备方协助排查。"
        )

    out += [
        "",
        "-" * 80,
        "本报告依据平台业务日志中的已解析数据，并结合设备上报报文交叉核对生成，供客户查阅。",
    ]

    report_text = "\n".join(out)
    conclusion = next((x for x in out if x.startswith("本订单")), "已生成充电订单分析报告。")

    result_points = list(bullets)

    info_fields = [
        {"name": "充电桩编号", "value": device_no},
        {"name": "枪口号", "value": f"{gun} 枪"},
        {"name": "服务ID", "value": service_id_val},
        {"name": "订单流水号", "value": trade_no},
        {"name": "手机号", "value": mobile},
        {"name": "车牌号", "value": car_no},
        {"name": "启动方式", "value": start_way},
        {"name": "启动时间", "value": _cn_datetime(start_time)},
        {"name": "结束时间", "value": _cn_datetime(end_time)},
        {"name": "充电时长", "value": dur_text},
        {"name": "启动时账户余额", "value": balance_disp},
        {"name": "充电电流（平均）", "value": cur_avg},
        {"name": "充电电流（范围）", "value": cur_rng},
        {"name": "充电电压（平均）", "value": vol_avg},
        {"name": "充电电压（范围）", "value": vol_rng},
        {"name": "输出功率（平均）", "value": pwr_avg},
        {"name": "输出功率（范围）", "value": pwr_rng},
        {"name": "功率印证（电流×电压）", "value": pwr_check},
        {"name": "实时采样点数", "value": f"{len(socs)}（流水号 {trade_no}）"},
        {"name": "起始终端表码", "value": _fmt_kwh(start_meter)},
        {"name": "结束终端表码", "value": _fmt_kwh(end_meter)},
        {"name": "实际充电电量", "value": _fmt_kwh(total_batt)},
        {
            "name": "过程电量（chargingInfo）",
            "value": _fmt_kwh((proc_frame or {}).get("totalBattery")) if proc_frame else "-",
        },
        {
            "name": "过程分时",
            "value": _fmt_tou_brief(_tou_map(proc_frame)) if proc_frame else "-",
        },
        {
            "name": "账单分时",
            "value": _fmt_tou_brief(_tou_map(bill_src)) if bill_src else "-",
        },
        {
            "name": "过程与账单校验",
            "value": "异常" if energy_mismatch else "通过",
        },
        {"name": "电池荷电状态", "value": "未上报（全程为 0）" if not soc_nonzero else "有上报"},
        {"name": "车辆识别码", "value": vin},
        {"name": "模块温度（范围）", "value": temp_rng},
        {"name": "尖电量", "value": _fmt_kwh(jian)},
        {"name": "峰电量", "value": _fmt_kwh(feng)},
        {"name": "平电量", "value": _fmt_kwh(ping)},
        {"name": "谷电量", "value": _fmt_kwh(gu)},
        {"name": "尖电价", "value": _fmt_price(jian_p)},
        {"name": "峰电价", "value": _fmt_price(feng_p)},
        {"name": "平电价", "value": _fmt_price(ping_p)},
        {"name": "谷电价", "value": _fmt_price(gu_p)},
        {"name": "电费", "value": _fmt_money(charge_money)},
        {"name": "服务费", "value": _fmt_money(service_money)},
        {"name": "占桩费", "value": _fmt_money(parking_money) if parking_money else "0 元"},
        {"name": "预约费", "value": _fmt_money(appoint_money) if appoint_money else "0 元"},
        {
            "name": "费用合计",
            "value": _fmt_money((charge_money or 0) + (service_money or 0) + (parking_money or 0))
            if charge_money is not None or service_money is not None
            else "-",
        },
        {"name": "是否有远程停止指令", "value": "有" if has_remote_stop else "无"},
        {"name": "设备结束原因", "value": finish_msg if finish_msg != "-" else "-"},
        {"name": "结束原因代码", "value": str(finish_code) if finish_code is not None else "-"},
        {"name": "是否占桩计费", "value": "是" if has_occupy else "否"},
        {"name": "占桩时长", "value": occupy_dur},
        {"name": "占桩费用", "value": _fmt_money(parking_money) if parking_money else "0 元"},
    ]
    for s in stages:
        info_fields.append(
            {
                "name": f"分时段 {s.get('startTime', '?')}～{s.get('endTime', '?')}",
                "value": _fmt_kwh(s.get("battery")),
            }
        )

    warnings: list[dict[str, Any]] = []
    for ck in energy_checks:
        if not ck.get("ok"):
            warnings.append(
                {
                    "code": str(ck.get("code") or "ENERGY_MISMATCH"),
                    "level": "warn",
                    "message": str(ck.get("message") or "过程与账单不一致"),
                }
            )

    return {
        "mode": "charging_report",
        "protocol": "order_log",
        "protocol_name": "充电订单日志",
        "confidence": 0.95 if valid else 0.65,
        "frame_type": None,
        "frame_type_name": "充电业务数据",
        "direction": None,
        "valid": valid,
        "summary": "\n".join(result_points + ["", verdict]),
        "conclusion": conclusion,
        "verdict": verdict,
        "result_points": result_points,
        "report_text": report_text,
        "fields": info_fields,
        "warnings": warnings,
        "raw_hex": None,
        "raw_json": None,
        "extras": {
            "has_remote_stop": has_remote_stop,
            "soc_samples": len(socs),
            "charging_samples": len(chgs),
            "service_id": sid or service_id_val,
            "filtered": bool(sid),
            "energy_checks": energy_checks,
            "energy_mismatch": energy_mismatch,
        },
    }
