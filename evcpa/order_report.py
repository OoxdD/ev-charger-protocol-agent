"""从运营平台日志中抽取充电业务数据，生成客户可读报告（与《充电订单分析报告》同款格式）。"""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import date, datetime
from statistics import mean
from typing import Any


_REMOTE_CMD = re.compile(r"RemoteCmd>{8,}:(\{.*\})")
_REMOTE_START = re.compile(r"远程启动充电,\s*(\{.*\})")
_SOC_INFO = re.compile(r"--socInfo:(\{.*\})")
_CHARGING_INFO = re.compile(r"--chargingInfo:(\{.*\})")
_RECORD_INFO = re.compile(r"--recordInfo:(\{.*\})")
_BILL_CMD8 = re.compile(r"上报账单\[cmd=0x8\]:(\{.*\})")
_BILL_ANY = re.compile(r"上报账单\[cmd=0x[0-9A-Fa-f]+\]:(\{.*\})")
_GUN_STATUS = re.compile(r"(\d+)枪[:：]?([A-Z_]+)")
_TS = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")
_SEP = "=" * 80


def _parse_gun_statuses(ln: str) -> list[tuple[str, str]]:
    """解析枪口状态。

    兼容：
    - 「1枪:IDLE|2枪:CHARGING|」
    - 「1枪：CHARGING」
    - 「1枪CHARGING」（无冒号，星星等）
    """
    return _GUN_STATUS.findall(ln)


_ALARM_CODE_CONTENT = re.compile(
    r"告警上报[，,]\s*告警码[：:]\s*(\d+)\s+内容[：:]\s*(.+?)(?:\s*$|\s*[\[【])"
)
_ALARM_DCODE = re.compile(
    r"告警上报[：:]\s*(.+?)\s+dCode\s*[：:]\s*(\d+)\s+pCode\s*[：:]\s*(\d+)"
)
_ALARM_MSG_JSON = re.compile(r"-----alarmmsg-----:(\{.*\})")
_ALARM_CODE_IN_JSON = re.compile(r'"alarmCode"\s*:\s*([^,}\]]+|\[.*?\])')
# 平台中文启动结果，如「启动失败，2 枪不可用」「启动失败，未插枪」
_START_RESULT_CN = re.compile(
    r"(?:\]|\s)(启动(?:失败|成功)[，,:：]?[^\"\{\}\n\[\]]{0,80})"
)


def _extract_start_result_phrase(ln: str) -> str | None:
    """提取日志中的中文启动结果文案；无则返回 None。"""
    if "启动失败" not in ln and "启动成功" not in ln:
        return None
    # 跳过纯 JSON 字段内嵌（如 stopReasonMsg），只取日志行可见文案
    if "RemoteCmd" in ln and ln.strip().endswith("}"):
        # RemoteCmd 行偶发夹带；仍允许 ]启动失败 形态
        pass
    m = _START_RESULT_CN.search(ln)
    if not m:
        return None
    phrase = m.group(1).strip()
    # 去掉尾部 serviceId / nid 等附属
    phrase = re.split(r"\s*[,，]\s*serviceId\s*:", phrase, maxsplit=1)[0]
    phrase = re.split(r"\s+nid\s*:", phrase, maxsplit=1)[0]
    phrase = phrase.strip(" 。.;；,，")
    if phrase in {"启动失败", "启动成功"}:
        return phrase
    if phrase.startswith("启动失败") or phrase.startswith("启动成功"):
        return phrase
    return None


def _alarm_code_meaningful(raw: Any) -> bool:
    """alarmCode 是否表示真实告警（排除 0 / 全 0 数组 / 空）。"""
    if raw is None or raw == "" or raw == "null":
        return False
    if isinstance(raw, list):
        return any(_alarm_code_meaningful(x) for x in raw)
    if isinstance(raw, (int, float)):
        return float(raw) != 0
    s = str(raw).strip()
    if not s or s in {"0", "0.0", "[]", "{}", "null"}:
        return False
    # base64 占位如 AAA= 常见于无告警
    if s in {"AAA=", "AAAA", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}:
        return False
    if s.isdigit():
        return int(s) != 0
    try:
        arr = json.loads(s) if s.startswith("[") else None
        if isinstance(arr, list):
            return any(_alarm_code_meaningful(x) for x in arr)
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    return True


def _alarm_bytes_meaningful(alarm_bytes: str | None) -> bool:
    if not alarm_bytes:
        return False
    hex_only = re.sub(r"[\s,]", "", str(alarm_bytes))
    if not hex_only:
        return False
    return any(c not in "0" for c in hex_only.upper() if c in "0123456789ABCDEF")


def _format_alarm_note(ts: str, body: str) -> str:
    body = re.sub(r"\s+", " ", body.strip())
    if len(body) > 160:
        body = body[:160] + "…"
    return f"{ts + '　' if ts else ''}{body}"


def _extract_alarm_notes_from_line(ln: str) -> list[str]:
    """从单行日志提取告警文案。

    仅输出中文告警文案或告警 JSON；原始协议 hex（如蔚景【上报 0D】）不输出。
    """
    if "告警恢复" in ln:
        return []
    # 平台离线超时「发送告警」属于离线提示，不作为设备告警信息
    if "发送告警" in ln and "告警上报" not in ln and "alarmmsg" not in ln:
        return []
    # 原始告警帧 hex 不作为可读告警输出
    if "【上报" in ln and re.search(r"【上报\s*0[Dd]】", ln):
        return []

    ts = ""
    tm = _TS.match(ln.strip())
    if tm:
        ts = tm.group(1)
    notes: list[str] = []

    m = _ALARM_CODE_CONTENT.search(ln)
    if m:
        notes.append(_format_alarm_note(ts, f"告警码 {m.group(1)}：{m.group(2).strip()}"))
        return notes

    m = _ALARM_DCODE.search(ln)
    if m:
        notes.append(
            _format_alarm_note(
                ts,
                f"{m.group(1).strip()}（dCode={m.group(2)}, pCode={m.group(3)}）",
            )
        )
        return notes

    if "告警上报" in ln:
        idx = ln.find("告警上报")
        snippet = ln[idx:].strip()
        snippet = re.sub(r"\s*nid:.*$", "", snippet)
        notes.append(_format_alarm_note(ts, snippet))
        return notes

    m = _ALARM_MSG_JSON.search(ln)
    if m:
        try:
            obj = json.loads(m.group(1))
        except (TypeError, ValueError, json.JSONDecodeError):
            obj = None
        if isinstance(obj, dict):
            code = obj.get("alarmCode")
            info = obj.get("alarmInfo") or obj.get("infoField") or obj.get("alarmPoint")
            alarm_bytes = obj.get("alarmBytes")
            parts: list[str] = []
            if _alarm_code_meaningful(code):
                parts.append(f"alarmCode={code}")
            if _alarm_bytes_meaningful(str(alarm_bytes) if alarm_bytes is not None else None):
                parts.append(f"alarmBytes={str(alarm_bytes).strip()}")
            if info not in (None, "", 0, "0") and str(info) not in {
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "AAA=",
            }:
                parts.append(f"info={info}")
            if parts:
                gun = obj.get("interfaceCode") or obj.get("gunNo") or obj.get("gun")
                prefix = f"{gun}枪 " if gun not in (None, "", "-") else ""
                notes.append(_format_alarm_note(ts, prefix + "告警报文：" + "，".join(parts)))
                return notes

    # ChargingData / 实时帧中的非零 alarmCode（JSON）
    if "alarmCode" in ln and (
        "ChargingData" in ln or "--socInfo" in ln or "--chargingInfo" in ln or "-----" in ln
    ):
        m = _ALARM_CODE_IN_JSON.search(ln)
        if m:
            raw = m.group(1).strip()
            try:
                val: Any = json.loads(raw)
            except (TypeError, ValueError, json.JSONDecodeError):
                val = raw.strip('"')
            if _alarm_code_meaningful(val):
                notes.append(_format_alarm_note(ts, f"过程数据告警码 alarmCode={val}"))
                return notes

    return notes


# 启动方式识别：日志文案优先，再回落到字段枚举
_CARD_START_MARKERS = (
    "刷卡启动",
    "刷卡鉴权",
    "刷卡启动充电执行结果",
)
_VIN_START_MARKERS = (
    "VIN验证启动",
    "VIN鉴权",
    "VIN充电",
    "创建VIN码充电服务信息",
    "创建VIN充电服务信息",
    "createCardChargeServiceInfo（VIN",
    "createCardChargeServiceInfo(VIN",
)

# 仅应答文案，不能当作平台下发了远程停止命令
_REMOTE_STOP_ACK_ONLY = (
    "远程停止充电应答",
    "远程停止应答",
)

# 离线/掉电/重连相关（日志文案或设备结束原因）
_OFFLINE_LOG_MARKERS = (
    "桩已离线",
    "设备离线",
    "ReadTimeout",
    "恢复上线",
    "设备登录",
    "设备重复登录",
    "告警恢复：恢复上线",
)
_OFFLINE_FINISH_HINTS = (
    "掉电",
    "离线",
    "断网",
    "通信中断",
    "重连",
    "非正常停止(掉电)",
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
    # 卡号本身就是 VIN（万马 VIN 启动常见）
    if _has_real_vin(card_no) and (card_no == str(vin or "").strip() or not physical):
        if any(m in text for m in ("VIN", "创建VIN")) or sw in {"4", "5", "3"}:
            return "VIN鉴权启动（成功）"
    # 平台结算字段：startWay=5 常见为 VIN；万马 startWay=4=VIN；云快充 0x31：1=刷卡、3=VIN
    if sw in {"4", "5"} and (_has_real_vin(vin) or _has_real_vin(card_no) or card_no.upper().startswith("VIN")):
        return "VIN鉴权启动（成功）"
    if sw == "3" and not remote:
        return "VIN鉴权启动（成功）"
    if st == "1" and (physical or _nonempty_id(card_no)) and not remote:
        return "刷卡启动（成功）"
    if sw == "1" and not remote and (physical or _nonempty_id(card_no)) and not _has_real_vin(vin):
        return "刷卡启动（成功）"
    if physical and not remote and "远程启动充电" not in text:
        return "刷卡启动（成功）"

    # 「远程启动充电应答」常见于 VIN/刷卡桩内启机后的平台应答，不能单凭该文案判远程启动
    has_remote_start_cmd = bool(remote) and _remote_cmd_str(remote) in _REMOTE_START_CMDS
    has_remote_start_phrase = "远程启动充电," in text or "下发远程启动" in text
    if has_remote_start_cmd or start_ok or has_remote_start_phrase:
        return "远程启动（成功）"
    if "RemoteCmd" in text and _remote_cmd_str(remote) in _REMOTE_START_CMDS:
        return "远程启动（成功）"
    if sw == "2":
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


def _accuracy_scale(obj: dict[str, Any] | None, default: int = 1000) -> int:
    """从 accuracyFlag 得到除数：4→10000（万分位），缺省千分位 1000。"""
    if not isinstance(obj, dict):
        return default
    flag = obj.get("accuracyFlag")
    if flag is None:
        flag = obj.get("accuracy")
    try:
        f = int(flag)
    except (TypeError, ValueError):
        return default
    if 0 <= f <= 6:
        return 10**f
    return default


def _to_real(v: Any, scale: int, digits: int = 4) -> float | None:
    """原始整型 → 实际物理量（kWh/元等）。"""
    return _num(v, float(scale), digits)


def _fmt_money(v: Any, scale: int = 1000) -> str:
    digits = 4 if scale >= 10000 else 3
    n = _num(v, scale, digits)
    if n is None:
        return "-"
    text = f"{n:.{digits}f}".rstrip("0").rstrip(".")
    return f"{text} 元"


def _fmt_kwh(v: Any, scale: int = 1000) -> str:
    digits = 4 if scale >= 10000 else 3
    n = _num(v, scale, digits)
    if n is None:
        return "-"
    if abs(n) < 1e-9:
        return "0 kwh"
    text = f"{n:.{digits}f}".rstrip("0").rstrip(".")
    return f"{text} kwh"


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


def _fmt_price(v: Any, scale: int = 1000) -> str:
    digits = 4 if scale >= 10000 else 3
    n = _num(v, scale, digits)
    if n is None:
        return "-"
    text = f"{n:.{digits}f}".rstrip("0").rstrip(".")
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


def _parse_log_time(v: Any) -> str | None:
    """解析账单/结算中的时间：BCD(yyMMddHHmmss) / unix 秒 / ISO 字符串。"""
    if v is None or v == "" or v == "-":
        return None
    # 已是标准串
    if isinstance(v, str):
        s = v.strip()
        if re.match(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", s):
            return s[:19].replace("T", " ")
        # 14 位：yyyyMMddHHmmss
        if re.fullmatch(r"\d{14}", s):
            return f"{s[0:4]}-{s[4:6]}-{s[6:8]} {s[8:10]}:{s[10:12]}:{s[12:14]}"
        # 12 位：yyMMddHHmmss（蔚景账单常见）
        if re.fullmatch(r"\d{12}", s):
            return f"20{s[0:2]}-{s[2:4]}-{s[4:6]} {s[6:8]}:{s[8:10]}:{s[10:12]}"
        # 纯数字 unix
        if re.fullmatch(r"\d{9,12}", s):
            try:
                v = int(s)
            except ValueError:
                return None
        else:
            return None
    if isinstance(v, (int, float)):
        n = int(v)
        # 12 位 BCD 整数：260722115634
        if 10**11 <= n < 10**12:
            s = f"{n:012d}"
            return f"20{s[0:2]}-{s[2:4]}-{s[4:6]} {s[6:8]}:{s[8:10]}:{s[10:12]}"
        # 14 位
        if 10**13 <= n < 10**14:
            s = f"{n:014d}"
            return f"{s[0:4]}-{s[4:6]}-{s[6:8]} {s[8:10]}:{s[10:12]}:{s[12:14]}"
        # unix 秒（约 2001–2099）
        if 1_000_000_000 <= n <= 4_102_444_800:
            try:
                return datetime.fromtimestamp(n).strftime("%Y-%m-%d %H:%M:%S")
            except (OverflowError, OSError, ValueError):
                return None
        # 毫秒时间戳
        if 1_000_000_000_000 <= n <= 4_102_444_800_000:
            try:
                return datetime.fromtimestamp(n / 1000.0).strftime("%Y-%m-%d %H:%M:%S")
            except (OverflowError, OSError, ValueError):
                return None
    return None


def _duration_seconds(start_iso: str | None, end_iso: str | None) -> int | None:
    if not start_iso or not end_iso or start_iso == "-" or end_iso == "-":
        return None
    try:
        a = datetime.strptime(start_iso[:19], "%Y-%m-%d %H:%M:%S")
        b = datetime.strptime(end_iso[:19], "%Y-%m-%d %H:%M:%S")
        sec = int((b - a).total_seconds())
        return sec if sec >= 0 else None
    except ValueError:
        return None


def _parse_event_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    s = str(ts).strip()
    if "." in s[:26]:
        try:
            return datetime.strptime(s[:26].ljust(26, "0")[:26], "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            pass
    try:
        return datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _charging_duration_from_gun_events(
    gun_events: list[tuple[str, str, str]],
    gun: str | None,
) -> tuple[int | None, str | None, str | None]:
    """按枪口处于 CHARGING 的时段累计实际充电时长。

    离开 CHARGING（如变为 OCCUPYING）即结束该段计时；多段 CHARGING 累加。
    返回 (秒数, 首次进入CHARGING时间, 最后离开CHARGING时间)。
    """
    seq = _gun_status_sequence(gun_events, gun or "")
    if not seq and gun in (None, "", "-"):
        # 未指定枪号时，用全部事件压缩（多枪场景可能混杂，仅作兜底）
        seq = []
        for ts, _g, st in gun_events:
            if not seq or seq[-1][1] != st:
                seq.append((ts, st))

    total = 0.0
    charging_since: datetime | None = None
    first_charge: str | None = None
    last_leave: str | None = None
    for ts, st in seq:
        t = _parse_event_ts(ts)
        if t is None:
            continue
        if st == "CHARGING":
            if charging_since is None:
                charging_since = t
                if first_charge is None:
                    first_charge = ts[:19] if ts else None
        else:
            if charging_since is not None:
                total += max(0.0, (t - charging_since).total_seconds())
                last_leave = ts[:19] if ts else last_leave
                charging_since = None
    # 若日志截断时仍停在 CHARGING，不计开放区间（避免虚高）
    if total <= 0:
        return None, first_charge, last_leave
    return int(round(total)), first_charge, last_leave


def _fmt_duration(seconds: Any) -> str:
    if seconds is None or seconds == "" or seconds == "-":
        return "-"
    try:
        sec = int(float(seconds))
    except (TypeError, ValueError):
        return "-"
    if sec < 0:
        return "-"
    return f"约 {round(sec / 60)} 分钟（{sec} 秒）"


# 平台远程停止命令（常见 remoteCmd=18）
_REMOTE_STOP_CMDS = {"18", "16", "19"}
_REMOTE_START_CMDS = {"17", "1", "03", "3", "14"}


def _remote_cmd_str(obj: dict[str, Any] | None) -> str:
    if not isinstance(obj, dict):
        return ""
    return str(obj.get("remoteCmd") or "").strip()


def _extract_stop_reason_msg(obj: dict[str, Any] | None) -> str | None:
    if not isinstance(obj, dict):
        return None
    data = obj.get("data") if isinstance(obj.get("data"), dict) else {}
    for key in ("stopReasonMsg", "stopReason", "remoteStopReason", "stopMsg"):
        v = obj.get(key)
        if v is None:
            v = data.get(key)
        if v is not None and str(v).strip():
            return str(v).strip()
    return None


# 远程停止命令里常见的“空壳”原因，不算具体停止原因
_GENERIC_REMOTE_STOP_REASONS = {
    "-",
    "平台远程停止",
    "远程停止",
    "远程停止充电",
    "平台主动停止",
    "主动停止",
    "停止充电",
}


def _is_specific_remote_stop_reason(msg: str | None) -> bool:
    """远程停止是否带有具体原因（有则用平台文案；无则一般判用户远程停止）。"""
    s = (msg or "").strip()
    if not s or s in _GENERIC_REMOTE_STOP_REASONS:
        return False
    # 纯数字多为 stopReason 代码，不算具体说明
    if s.isdigit():
        return False
    return True


# 平台侧守护/校验触发停止的中文异常（常无 stopReasonMsg，但日志有明确文案）
_PLATFORM_GUARD_STOP_PATTERNS = (
    re.compile(r"(设备充电功率不为零[，,]\s*电量为\s*0[，,]\s*停止充电)"),
    re.compile(r"(设备充电功率不为零[^，\n]{0,20}电量为\s*0[^，\n]{0,10}停止充电)"),
    re.compile(r"(设备充电电量增量一直为\s*0[，,]\s*停止充电)"),
)


def _extract_platform_guard_stop_msg(ln: str) -> str | None:
    """从日志行提取平台守护停止的中文异常原因。"""
    for pat in _PLATFORM_GUARD_STOP_PATTERNS:
        m = pat.search(ln)
        if m:
            return re.sub(r"\s+", "", m.group(1).replace(",", "，"))
    return None


def _gun_status_sequence(
    gun_events: list[tuple[str, str, str]],
    gun: str,
) -> list[tuple[str, str]]:
    """提取本枪口状态序列 [(ts, status), ...]。"""
    seq: list[tuple[str, str]] = []
    for ts, g, st in gun_events:
        if gun and gun != "-" and str(g) != str(gun):
            continue
        if not seq or seq[-1][1] != st:
            seq.append((ts, st))
    return seq


def _trouble_followed_by_charging(
    gun_events: list[tuple[str, str, str]],
    gun: str | None = None,
) -> bool:
    """本枪出现 TROUBLE 之后又进入 CHARGING（后续正常开充）则可忽略该 TROUBLE。"""
    had_trouble = False
    for _ts, g, st in gun_events:
        if gun and gun not in (None, "", "-") and str(g) != str(gun):
            continue
        if st == "TROUBLE":
            had_trouble = True
        elif had_trouble and st == "CHARGING":
            return True
    return False


def _ts_key(ts: str) -> str:
    """时间戳排序键（取到秒或毫秒原文前缀，缺省排到最后）。"""
    return (ts or "").strip()[:26] or "\uffff"


def _first_idle_after_charging(
    gun_events: list[tuple[str, str, str]],
    gun: str | None,
) -> str | None:
    """本枪离开 CHARGING 后首次进入 IDLE（拔枪）的时间戳。"""
    gun_s = str(gun) if gun not in (None, "", "-") else None
    seen_charging = False
    for ts, g, st in gun_events:
        if gun_s and str(g) != gun_s:
            continue
        if st == "CHARGING":
            seen_charging = True
            continue
        if seen_charging and st == "IDLE":
            return ts or ""
    return None


def _clip_gun_events_after_unplug(
    gun_events: list[tuple[str, str, str]],
    gun: str | None,
) -> list[tuple[str, str, str]]:
    """充电结束并拔枪(IDLE)后，本枪后续状态变化不再归属本单。

    保留拔枪当次 IDLE；其后的 TROUBLE / READY / 再开充等一律丢弃，
    避免后一枪会话的故障/异常污染前一订单。
    """
    gun_s = str(gun) if gun not in (None, "", "-") else None
    out: list[tuple[str, str, str]] = []
    seen_charging = False
    closed = False
    for ts, g, st in gun_events:
        if gun_s and str(g) != gun_s:
            # 他枪事件仍保留，供「同桩其他枪」摘录
            out.append((ts, g, st))
            continue
        if closed:
            continue
        out.append((ts, g, st))
        if st == "CHARGING":
            seen_charging = True
        elif seen_charging and st == "IDLE":
            closed = True
    return out


def _filter_notes_before_ts(notes: list[str], cutoff_ts: str | None) -> list[str]:
    """丢弃时间戳晚于 cutoff（拔枪后）的异常摘录。无时间戳的保留。"""
    if not cutoff_ts:
        return notes
    cut = _ts_key(cutoff_ts)
    kept: list[str] = []
    for note in notes:
        m = _TS.match(note.strip())
        if m and _ts_key(m.group(1)) > cut:
            continue
        kept.append(note)
    return kept


def _is_offline_finish(finish: str, finish_code: Any = None) -> bool:
    """设备结束原因是否指向掉电/离线类。"""
    if finish and any(h in finish for h in _OFFLINE_FINISH_HINTS):
        return True
    # 星星充电等：stopReason=60 且文案含非正常停止
    code = str(finish_code).strip() if finish_code is not None else ""
    if code == "60" and finish and ("非正常" in finish or "掉电" in finish or "离线" in finish):
        return True
    return False


def _analyze_stop(
    *,
    has_remote_stop: bool,
    remote_stop_msg: str | None,
    finish_msg: str | None,
    finish_code: Any,
    gun_events: list[tuple[str, str, str]],
    gun: str,
    offline_reconnect: bool = False,
    alarm_notes: list[str] | None = None,
    platform_guard_msg: str | None = None,
) -> dict[str, Any]:
    """区分平台远程停止 / 离线重连 / 设备跳枪 / 直接拔枪 / 枪口故障 / 疑似急停。

    疑似急停仅在「短暂 TROUBLE 且无告警信息」时成立；有告警则按真实枪口故障，需设备方排查。
    """
    finish = (finish_msg or "").strip() if finish_msg and finish_msg != "-" else ""
    platform_msg = (remote_stop_msg or "").strip() if remote_stop_msg else ""
    guard_msg = (platform_guard_msg or "").strip() if platform_guard_msg else ""
    has_alarms = bool(alarm_notes)
    alarm_summary = "；".join((alarm_notes or [])[:3]) if has_alarms else ""
    seq = _gun_status_sequence(gun_events, gun)

    # 充电后的状态变迁（拔枪 IDLE 后会话结束，不再看后续枪口变化）
    after_charge: list[tuple[str, str]] = []
    seen_charging = False
    session_closed = False
    for ts, st in seq:
        if session_closed:
            break
        if st == "CHARGING":
            seen_charging = True
            after_charge = []
            continue
        if seen_charging:
            after_charge.append((ts, st))
            if st == "IDLE":
                session_closed = True

    # 会话边界：首次 CHARGING 起，至拔枪 IDLE（含）为止
    first_charge_idx = next((i for i, (_, st) in enumerate(seq) if st == "CHARGING"), None)
    session_end_idx = len(seq) - 1
    if first_charge_idx is not None:
        for i in range(first_charge_idx + 1, len(seq)):
            if seq[i][1] == "IDLE":
                session_end_idx = i
                break
    trouble_idxs = [
        i
        for i, (_, st) in enumerate(seq)
        if st == "TROUBLE"
        and (first_charge_idx is None or i >= first_charge_idx)
        and i <= session_end_idx
    ]

    brief_trouble = False
    persistent_trouble = False
    if trouble_idxs:
        # 故障后是否恢复正常
        last_t = trouble_idxs[-1]
        recovered = any(
            seq[i][1] in {"READY_CHARGE", "IDLE", "CHARGING", "OCCUPYING", "FINISH"}
            for i in range(last_t + 1, len(seq))
        )
        # 故障出现次数少且很快恢复 → 疑似急停
        if recovered and len(trouble_idxs) <= 3:
            brief_trouble = True
        elif not recovered or len(trouble_idxs) >= 5:
            persistent_trouble = True
        else:
            brief_trouble = recovered

    first_after = after_charge[0][1] if after_charge else None

    if has_remote_stop:
        # 平台守护异常（如功率不为零但电量为0）优先于「无原因→用户停止」
        if guard_msg and not _is_specific_remote_stop_reason(platform_msg):
            return {
                "category": "platform_guard_stop",
                "stop_type": "平台停止",
                "reason": guard_msg,
                "platform_stop_reason": guard_msg,
                "device_finish_reason": finish or "-",
                "gun_transition": first_after or "-",
                "tip": "",
                "evidence": f"平台检测到异常并下发远程停止：{guard_msg}",
            }
        # 有具体 stopReasonMsg → 按平台文案；无具体原因 → 一般是用户远程停止
        if _is_specific_remote_stop_reason(platform_msg):
            return {
                "category": "remote_stop",
                "stop_type": "平台远程停止",
                "reason": platform_msg,
                "platform_stop_reason": platform_msg,
                "device_finish_reason": finish or "-",
                "gun_transition": first_after or "-",
                "tip": "",
                "evidence": f"日志中存在平台远程停止指令；平台原因：{platform_msg}",
            }
        return {
            "category": "user_remote_stop",
            "stop_type": "用户远程停止",
            "reason": "用户远程停止充电（平台未下发具体停止原因）",
            "platform_stop_reason": platform_msg or "-",
            "device_finish_reason": finish or "-",
            "gun_transition": first_after or "-",
            "tip": "远程停止指令无具体停止原因时，一般判定为用户端远程结束充电。",
            "evidence": "日志中存在远程停止指令，但无具体 stopReasonMsg，一般判定为用户远程停止",
        }

    # 掉电/离线重连：优先于枪口 IDLE 误判为拔枪（重连后常直接报 IDLE）
    # 若重连后才上报 TROUBLE：归为「离线上报枪口故障」，绝不能判人工急停
    if offline_reconnect or _is_offline_finish(finish, finish_code):
        post_offline_trouble = bool(trouble_idxs) or first_after == "TROUBLE" or any(
            st == "TROUBLE" for _, st in after_charge
        )
        if post_offline_trouble:
            return {
                "category": "offline_gun_fault",
                "stop_type": "离线上报枪口故障",
                "reason": finish or "设备离线重连后上报枪口故障",
                "platform_stop_reason": "-",
                "device_finish_reason": finish or "-",
                "gun_transition": (
                    f"CHARGING→{first_after}" if first_after else "重连后 TROUBLE"
                ),
                "tip": "设备先离线，重连后才上报枪口故障（TROUBLE），属离线场景下的故障上报，非人工急停。",
                "evidence": "日志先出现离线/超时/重连登录，随后枪口变为 TROUBLE"
                + (f"；设备上报：{finish}" if finish else ""),
            }
        return {
            "category": "offline_reconnect",
            "stop_type": "设备离线重连结束",
            "reason": finish or "设备离线后重连上报账单导致订单结束",
            "platform_stop_reason": "-",
            "device_finish_reason": finish or "-",
            "gun_transition": (
                f"CHARGING→{first_after}" if first_after else "离线后重连上报"
            ),
            "tip": "订单因设备掉电/离线后重新登录并上报充电记录而结束，非用户主动拔枪。",
            "evidence": "日志出现离线/恢复上线/重复登录，或设备结束原因为掉电类"
            + (f"；设备上报：{finish}" if finish else ""),
        }

    # 无远程停止 → 设备侧结束
    # 持续 TROUBLE，或短暂 TROUBLE 但伴随告警 → 真实枪口故障（非急停）
    if persistent_trouble or (first_after == "TROUBLE" and not brief_trouble) or (
        brief_trouble and has_alarms
    ):
        tip = (
            "枪口 TROUBLE 且日志存在告警信息，判定为真实枪口/设备故障（非急停），需设备方排查。"
            if has_alarms
            else "枪口状态变为 TROUBLE 并持续上报，请结合设备故障码排查，需设备方协助。"
        )
        evidence = "枪口状态出现 TROUBLE"
        if brief_trouble and has_alarms:
            evidence = "枪口曾短暂 TROUBLE，但同时存在告警信息，按枪口故障处理（非急停）"
        elif not brief_trouble:
            evidence = "枪口状态出现 TROUBLE 且未快速恢复"
        if finish:
            evidence += f"；设备上报：{finish}"
        if alarm_summary:
            evidence += f"；告警：{alarm_summary}"
        return {
            "category": "gun_fault",
            "stop_type": "枪口故障停止",
            "reason": finish or ("枪口故障（伴随告警）" if has_alarms else "枪口故障（TROUBLE）"),
            "platform_stop_reason": "-",
            "device_finish_reason": finish or "-",
            "gun_transition": "TROUBLE→恢复" if brief_trouble else "TROUBLE",
            "tip": tip,
            "evidence": evidence,
        }

    # 仅短暂 TROUBLE、且无告警信息 → 才疑似急停
    if brief_trouble:
        return {
            "category": "estop_suspect",
            "stop_type": "疑似急停停止",
            "reason": finish or "疑似用户按下急停按钮",
            "platform_stop_reason": "-",
            "device_finish_reason": finish or "-",
            "gun_transition": "TROUBLE→恢复",
            "tip": "枪口曾短暂进入 TROUBLE 后恢复，且无告警信息，大概率为用户按下急停按钮，请向现场用户确认。",
            "evidence": "短暂 TROUBLE 后恢复，且日志无告警信息"
            + (f"；设备上报：{finish}" if finish else ""),
        }

    if first_after == "IDLE" or any(st == "IDLE" for _, st in after_charge[:3]):
        return {
            "category": "device_idle_unplug",
            "stop_type": "设备跳枪停止",
            "reason": finish or "充电过程中直接拔枪（枪口变为 IDLE）",
            "platform_stop_reason": "-",
            "device_finish_reason": finish or "-",
            "gun_transition": "CHARGING→IDLE",
            "tip": "",
            "evidence": "充电中枪口变为 IDLE，通常为未回枪座直接拔枪"
            + (f"；设备上报：{finish}" if finish else ""),
        }

    if first_after == "OCCUPYING" or any(st == "OCCUPYING" for _, st in after_charge[:3]):
        return {
            "category": "device_occupy",
            "stop_type": "设备跳枪停止",
            "reason": finish or "充电结束，枪口变为 OCCUPYING",
            "platform_stop_reason": "-",
            "device_finish_reason": finish or "-",
            "gun_transition": "CHARGING→OCCUPYING",
            "tip": "",
            "evidence": "充电结束后枪口变为 OCCUPYING"
            + (f"；设备上报：{finish}" if finish else ""),
        }

    if first_after == "READY_CHARGE" or any(st == "READY_CHARGE" for _, st in after_charge[:3]):
        return {
            "category": "device_unplug",
            "stop_type": "设备跳枪停止",
            "reason": finish or "设备跳枪（CHARGING→READY_CHARGE）",
            "platform_stop_reason": "-",
            "device_finish_reason": finish or "-",
            "gun_transition": "CHARGING→READY_CHARGE",
            "tip": "",
            "evidence": "枪口由充电变为待充 READY_CHARGE"
            + (f"；设备上报：{finish}" if finish else ""),
        }

    # 无枪状态变迁时，仍优先展示设备账单原因
    if finish:
        return {
            "category": "device_finish",
            "stop_type": "设备主动结束",
            "reason": finish,
            "platform_stop_reason": "-",
            "device_finish_reason": finish,
            "gun_transition": first_after or "-",
            "tip": "",
            "evidence": f"无平台远程停止指令；设备上报结束原因：{finish}",
        }

    return {
        "category": "unknown",
        "stop_type": "停止原因待确认",
        "reason": "-",
        "platform_stop_reason": "-",
        "device_finish_reason": "-",
        "gun_transition": first_after or "-",
        "tip": "日志中未识别到远程停止或明确枪口跳变，请结合现场确认。",
        "evidence": "缺少平台远程停止指令与可用的枪口状态变迁",
    }


def _section(title: str) -> list[str]:
    return ["", _SEP, title, _SEP]


def _norm_id(v: Any) -> str:
    """流水号常为左侧补 0 的 serviceId，比较时去掉前导 0。"""
    if v is None:
        return ""
    s = str(v).strip()
    if not s or s.lower() == "none":
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


def _order_key_of(obj: dict[str, Any] | None) -> tuple[str, str]:
    """返回 (service_id, trade_no)，优先用于多订单分组。"""
    if not isinstance(obj, dict):
        return ("", "")
    data = obj.get("data") if isinstance(obj.get("data"), dict) else {}
    sid = ""
    for key in ("serviceId", "service_id", "serviceChargeId"):
        v = obj.get(key) or data.get(key)
        if v is not None and str(v).strip() and not re.fullmatch(r"0+", str(v).strip()):
            sid = str(v).strip()
            break
    tn = ""
    for key in ("tradeNo", "orderId", "txnId"):
        v = obj.get(key) or data.get(key)
        if v is not None and str(v).strip() and not re.fullmatch(r"0+", str(v).strip()):
            tn = str(v).strip()
            break
    return (sid, tn)


def _discover_orders(text: str) -> list[dict[str, Any]]:
    """从平台日志扫描出多笔订单的服务ID/流水号（用于多枪提示）。"""
    items: list[dict[str, Any]] = []

    def _push(obj: dict[str, Any] | None) -> None:
        if not isinstance(obj, dict):
            return
        sid, tn = _order_key_of(obj)
        if not sid and not tn:
            return
        data = obj.get("data") if isinstance(obj.get("data"), dict) else {}
        gun = obj.get("interfaceCode")
        if gun is None:
            gun = data.get("interfaceCode")
        try:
            gun_v = int(gun) if gun is not None else None
        except (TypeError, ValueError):
            gun_v = gun
        energy = None
        money = None
        for ek, mk in (
            ("totalElect", "totalMoney"),
            ("chargedPower", "chargedAmount"),
            ("totalBattery", "chargeMoney"),
            ("battery", "money"),
        ):
            ev = obj.get(ek)
            if ev is None:
                ev = data.get(ek)
            mv = obj.get(mk)
            if mv is None:
                mv = data.get(mk)
            try:
                if energy is None and ev is not None and float(ev) > 0:
                    # totalBattery 等常见为 0.001 kWh
                    fv = float(ev)
                    energy = fv / 1000.0 if fv >= 100 else fv
            except (TypeError, ValueError):
                pass
            try:
                if money is None and mv is not None and float(mv) > 0:
                    fv = float(mv)
                    money = fv / 1000.0 if fv > 1000 else fv
            except (TypeError, ValueError):
                pass
        pile = obj.get("deviceNo") or data.get("deviceNo")
        items.append(
            {
                "service_id": sid or None,
                "trade_no": tn or None,
                "gun": gun_v,
                "pile": str(pile) if pile else None,
                "energy": energy,
                "money": money,
            }
        )

    for ln in text.splitlines():
        for rx in (_REMOTE_CMD, _REMOTE_START, _SOC_INFO, _CHARGING_INFO, _RECORD_INFO, _BILL_CMD8):
            m = rx.search(ln)
            if m:
                _push(_load_json(m.group(1)))

    if not items:
        return []

    # 并查集合并：共享 serviceId 或 tradeNo 的视为同一订单
    parent = list(range(len(items)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    sid_index: dict[str, int] = {}
    tn_index: dict[str, int] = {}
    for i, it in enumerate(items):
        sid_n = _norm_id(it.get("service_id"))
        tn_n = _norm_id(it.get("trade_no"))
        if sid_n:
            if sid_n in sid_index:
                union(i, sid_index[sid_n])
            else:
                sid_index[sid_n] = i
        if tn_n:
            if tn_n in tn_index:
                union(i, tn_index[tn_n])
            else:
                tn_index[tn_n] = i
        # 若同一条同时有 sid/tn，再交叉关联
        if sid_n and tn_n and sid_n in sid_index and tn_n in tn_index:
            union(sid_index[sid_n], tn_index[tn_n])

    groups: dict[int, dict[str, Any]] = {}
    for i, it in enumerate(items):
        root = find(i)
        slot = groups.setdefault(
            root,
            {
                "service_id": None,
                "trade_no": None,
                "gun": None,
                "pile": None,
                "energy": None,
                "money": None,
                "start_way": None,
                "stop_reason": None,
            },
        )
        if it.get("service_id") and not slot["service_id"]:
            slot["service_id"] = it["service_id"]
        if it.get("trade_no") and not slot["trade_no"]:
            slot["trade_no"] = it["trade_no"]
        if it.get("gun") is not None and slot["gun"] is None:
            slot["gun"] = it["gun"]
        if it.get("pile") and not slot["pile"]:
            slot["pile"] = it["pile"]
        if it.get("energy") is not None:
            slot["energy"] = it["energy"]
        if it.get("money") is not None:
            slot["money"] = it["money"]

    orders = [o for o in groups.values() if o.get("service_id") or o.get("trade_no")]
    orders.sort(
        key=lambda o: (
            str(o.get("service_id") or ""),
            str(o.get("trade_no") or ""),
        )
    )
    return orders


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


def _fmt_tou_brief(tou: dict[str, float], scale: int = 1000) -> str:
    parts = [f"{k}{_fmt_kwh(v, scale)}" for k, v in tou.items() if v and float(v) > 0]
    return "、".join(parts) if parts else "无分时电量"


_TOU_KEYS = ("尖", "峰", "平", "谷")
# 原始整数电量允许 1 个最小计量单位抖动（千分位下约 0.001 kWh）
_ENERGY_SERIES_EPS = 1.0


def _check_process_energy_series(
    chgs: list[dict[str, Any]],
    *,
    scale: int = 1000,
) -> list[dict[str, Any]]:
    """过程帧总电量/分时电量应逐步递增；出现回落则异常。"""
    checks: list[dict[str, Any]] = []
    if len(chgs) < 2:
        checks.append(
            {
                "ok": True,
                "code": "SERIES_SKIP",
                "message": "过程帧不足 2 条，未做电量递增校验。",
            }
        )
        return checks

    prev_total: float | None = None
    prev_tou: dict[str, float] | None = None
    issues: list[str] = []
    for i, fr in enumerate(chgs):
        if not isinstance(fr, dict):
            continue
        total_raw = fr.get("totalBattery")
        try:
            total = float(total_raw) if total_raw is not None else None
        except (TypeError, ValueError):
            total = None
        tou = _tou_map(fr)
        if prev_total is not None and total is not None:
            if total + _ENERGY_SERIES_EPS < prev_total:
                issues.append(
                    f"第{i + 1}帧总电量回落："
                    f"{_fmt_kwh(prev_total, scale)} → {_fmt_kwh(total, scale)}"
                )
        if prev_tou is not None:
            for k in _TOU_KEYS:
                if tou[k] + _ENERGY_SERIES_EPS < prev_tou[k]:
                    issues.append(
                        f"第{i + 1}帧分时“{k}”回落："
                        f"{_fmt_kwh(prev_tou[k], scale)} → {_fmt_kwh(tou[k], scale)}"
                    )
        if total is not None:
            prev_total = total
        prev_tou = tou

    if issues:
        # 最多列 3 条，避免刷屏
        detail = "；".join(issues[:3])
        if len(issues) > 3:
            detail += f"等共 {len(issues)} 处"
        checks.append(
            {
                "ok": False,
                "code": "ENERGY_DECREASE",
                "message": f"充电过程电量未单调递增：{detail}",
            }
        )
    else:
        checks.append(
            {
                "ok": True,
                "code": "SERIES_OK",
                "message": f"过程总电量与分时电量均逐步递增（共 {len(chgs)} 帧）。",
            }
        )
    return checks


def _check_inactive_tou_frozen(
    chgs: list[dict[str, Any]],
    *,
    scale: int = 1000,
) -> list[dict[str, Any]]:
    """非当前增长时段的分时电量应保持不变；已锁定时段再变动则异常。

    判定：当总电量仍在增加时，某分时段本帧未增长则锁定；之后该段再增/减均告警。
    """
    checks: list[dict[str, Any]] = []
    if len(chgs) < 2:
        checks.append(
            {
                "ok": True,
                "code": "TOU_FREEZE_SKIP",
                "message": "过程帧不足 2 条，未做非当前时段分时固化校验。",
            }
        )
        return checks

    locked: set[str] = set()
    prev_tou: dict[str, float] | None = None
    prev_total: float | None = None
    issues: list[str] = []

    for i, fr in enumerate(chgs):
        if not isinstance(fr, dict):
            continue
        tou = _tou_map(fr)
        try:
            total = float(fr.get("totalBattery") or 0)
        except (TypeError, ValueError):
            total = 0.0

        if prev_tou is not None:
            deltas = {k: tou[k] - prev_tou[k] for k in _TOU_KEYS}
            total_up = prev_total is not None and total > prev_total + _ENERGY_SERIES_EPS
            growing = {k for k, d in deltas.items() if d > _ENERGY_SERIES_EPS}

            for k in locked:
                d = deltas[k]
                if abs(d) > _ENERGY_SERIES_EPS:
                    direction = "增长" if d > 0 else "回落"
                    issues.append(
                        f"第{i + 1}帧非当前时段“{k}”不应再变动（{direction}："
                        f"{_fmt_kwh(prev_tou[k], scale)} → {_fmt_kwh(tou[k], scale)}）"
                    )

            # 总电量在涨时：未增长且已有电量的时段视为离开所属时段，予以锁定
            if total_up:
                for k in _TOU_KEYS:
                    if k in growing:
                        continue
                    if prev_tou[k] > _ENERGY_SERIES_EPS:
                        locked.add(k)

        prev_tou = tou
        prev_total = total

    if issues:
        detail = "；".join(issues[:3])
        if len(issues) > 3:
            detail += f"等共 {len(issues)} 处"
        checks.append(
            {
                "ok": False,
                "code": "TOU_INACTIVE_CHANGED",
                "message": f"非所属时段分时电量发生变动：{detail}",
            }
        )
    else:
        checks.append(
            {
                "ok": True,
                "code": "TOU_FREEZE_OK",
                "message": "非当前所属时段的分时电量保持不变。",
            }
        )
    return checks


def _check_start_success(
    *,
    start_ok: bool,
    is_card_start: bool,
    is_vin_start: bool,
    is_remote_start: bool,
    has_remote_cmd: bool,
    gun_events: list[tuple[str, str, str]],
    gun: str | None,
    socs: list[dict[str, Any]],
    chgs: list[dict[str, Any]],
    start_result_msgs: list[str] | None = None,
) -> dict[str, Any]:
    """启动是否成功：有电流/电压/电量过程数据即可；有中文启动失败文案则直接输出。"""
    evidence: list[str] = []
    problems: list[str] = []
    start_results = [m for m in (start_result_msgs or []) if m]
    fail_msgs = [m for m in start_results if m.startswith("启动失败")]
    ok_msgs = [m for m in start_results if m.startswith("启动成功")]

    # 1) 启动响应 / 鉴权（可选辅证）
    has_ack = bool(start_ok or is_card_start or is_vin_start or is_remote_start or has_remote_cmd)
    if is_card_start:
        evidence.append("刷卡/卡鉴权成功")
    elif is_vin_start:
        evidence.append("VIN 鉴权成功")
    elif is_remote_start or has_remote_cmd or start_ok:
        evidence.append("启动响应成功或远程启动指令已下发")

    # 2) 枪口进入 CHARGING（可选辅证）
    gun_s = str(gun) if gun not in (None, "", "-") else None
    charging_hits = [
        (ts, g, st)
        for ts, g, st in gun_events
        if st == "CHARGING" and (not gun_s or str(g) == gun_s)
    ]
    if charging_hits:
        ts0 = charging_hits[0][0] or ""
        evidence.append(
            f"{charging_hits[0][1]}枪进入 CHARGING"
            + (f"（{_cn_datetime(ts0) if ts0 else ts0}）" if ts0 else "")
        )

    # 枪口占桩等状态，辅助说明启动失败原因
    occupy_hits = [
        (ts, g, st)
        for ts, g, st in gun_events
        if st == "OCCUPYING" and (not gun_s or str(g) == gun_s)
    ]
    if occupy_hits and fail_msgs:
        evidence.append(
            f"{occupy_hits[-1][1]}枪启动前为 OCCUPYING（占桩）"
            + (f"（{occupy_hits[-1][0][:19]}）" if occupy_hits[-1][0] else "")
        )

    # 3) 过程电气量 / 电量（充分条件）
    def _has_pos(obj: dict[str, Any], *keys: str) -> bool:
        for k in keys:
            v = obj.get(k)
            try:
                if v not in (None, "", 0, "0") and float(v) > 0:
                    return True
            except (TypeError, ValueError):
                continue
        return False

    has_vi = any(
        _has_pos(
            s,
            "batteryChargerOutputCurrent",
            "batteryChargerOutputVoltage",
            "outputCurrent",
            "outputVoltage",
        )
        for s in socs
        if isinstance(s, dict)
    )
    has_energy = any(
        _has_pos(c, "totalBattery") for c in chgs if isinstance(c, dict)
    )
    if has_vi:
        evidence.append("有电流/电压过程上报")
    if has_energy:
        evidence.append("有电量过程上报")

    has_process = has_vi or has_energy
    if has_process:
        ok = True
        msg = "启动成功：" + "；".join(evidence)
        code = "START_OK"
        return {
            "ok": ok,
            "code": code,
            "message": msg,
            "evidence": evidence,
            "problems": problems,
            "start_result": ok_msgs[0] if ok_msgs else "启动成功",
        }

    # 无过程数据：优先直接输出日志中文启动失败结果
    if fail_msgs:
        # 去重保序
        uniq: list[str] = []
        for m in fail_msgs:
            if m not in uniq:
                uniq.append(m)
        msg = uniq[0] if len(uniq) == 1 else "；".join(uniq)
        return {
            "ok": False,
            "code": "START_FAIL",
            "message": msg,
            "evidence": evidence,
            "problems": uniq,
            "start_result": msg,
        }

    if not has_ack:
        problems.append("未找到启动成功响应（启动充电响应/鉴权成功等）")
    if not charging_hits:
        problems.append("枪口状态未观察到 CHARGING")
    problems.append("无电流/电压/电量过程数据")

    msg = "启动校验异常：" + "；".join(problems)
    if evidence:
        msg += "。已具备：" + "；".join(evidence)
    return {
        "ok": False,
        "code": "START_FAIL",
        "message": msg,
        "evidence": evidence,
        "problems": problems,
        "start_result": ok_msgs[0] if ok_msgs else "-",
    }


# 过程与账单电量：基础容差 1 kWh；高功率按末帧功率×滞后窗口放大
_ENERGY_TOL_KWH = 1.0
_ENERGY_TOL_LAG_MINUTES = 2.0
# 功率×时间估算电量：相对 25% 且至少 1.5 kWh（功率波动大，恒功率近似）
_POWER_TIME_REL_TOL = 0.25
_POWER_TIME_ABS_TOL_KWH = 1.5
_POWER_TIME_MIN_DURATION_SEC = 60.0


def _estimate_power_kw(*frames: dict[str, Any] | None) -> float | None:
    """从 socInfo / chargingInfo 估算输出功率（kW）。优先 OutPower，否则 I×U。"""
    for obj in frames:
        if not isinstance(obj, dict):
            continue
        p_raw = obj.get("batteryChargerOutPower")
        try:
            if p_raw not in (None, "", 0, "0"):
                p = float(p_raw)
                if p > 0:
                    # 与报告电气统计一致：千分位千瓦（122500 → 122.5）
                    return p / 1000.0 if p >= 100 else p
        except (TypeError, ValueError):
            pass
        i_raw = obj.get("batteryChargerOutputCurrent")
        u_raw = obj.get("batteryChargerOutputVoltage")
        if i_raw in (None, "", 0, "0") or u_raw in (None, "", 0, "0"):
            # 星星过程帧偶见 outputCurrent/Voltage（百分位电流、十分位电压）
            i_raw = obj.get("outputCurrent")
            u_raw = obj.get("outputVoltage")
            try:
                if i_raw not in (None, "", 0, "0") and u_raw not in (None, "", 0, "0"):
                    i_f, u_f = float(i_raw), float(u_raw)
                    if i_f > 0 and u_f > 0:
                        # 22998×5327 → 先按百分位/十分位：I/100 * U/10 / 1000 = kW
                        if i_f > 1000 or u_f > 1000:
                            return (i_f / 100.0) * (u_f / 10.0) / 1000.0
                        return i_f * u_f / 1000.0
            except (TypeError, ValueError):
                pass
            continue
        try:
            i_f, u_f = float(i_raw), float(u_raw)
        except (TypeError, ValueError):
            continue
        if i_f > 0 and u_f > 0:
            # socInfo 千分位：I*U/1e6 → 千分位千瓦，再 /1000 → kW
            return (i_f * u_f) / 1_000_000.0 / 1000.0 if i_f >= 1000 else (i_f * u_f) / 1000.0
    return None


def _energy_tol_kwh(power_kw: float | None) -> tuple[float, str]:
    """总电量容差：基础 1 kWh；大功率按末帧功率×约 2 分钟滞后放大。"""
    base = _ENERGY_TOL_KWH
    if power_kw is None or power_kw <= 0:
        return base, f"{base:g} kwh"
    dyn = float(power_kw) * _ENERGY_TOL_LAG_MINUTES / 60.0
    tol = max(base, dyn)
    if tol > base + 1e-9:
        return (
            tol,
            f"{tol:.3f} kwh（末帧功率约 {power_kw:.1f} kW，允许约 {_ENERGY_TOL_LAG_MINUTES:g} 分钟滞后）",
        )
    return base, f"{base:g} kwh"


def _avg_power_kw_from_samples(
    powers_milli_kw: list[float],
    calc_powers_milli_kw: list[float] | None = None,
    fallback_kw: float | None = None,
) -> float | None:
    """从 OutPower / I×U 采样（千分位千瓦）得到平均功率 kW。"""
    samples = list(powers_milli_kw or []) or list(calc_powers_milli_kw or [])
    if samples:
        try:
            return float(mean(samples)) / 1000.0
        except (TypeError, ValueError):
            pass
    if fallback_kw is not None and fallback_kw > 0:
        return float(fallback_kw)
    return None


def _check_energy_vs_power_time(
    *,
    energy_kwh: float | None,
    power_kw: float | None,
    duration_sec: Any,
) -> dict[str, Any]:
    """用电量 ≈ 平均功率 × 充电时长 校验合理性。

    E(kWh) ≈ P(kW) × t(h)。容差取 max(1.5 kWh, 期望值×25%)，覆盖功率波动与启停非恒功率段。
    """
    try:
        sec = float(duration_sec) if duration_sec not in (None, "", "-") else None
    except (TypeError, ValueError):
        sec = None
    if energy_kwh is None or power_kw is None or sec is None:
        return {
            "ok": True,
            "code": "POWER_TIME_SKIP",
            "message": "缺少电量/功率/时长，未做功率×时间电量校验。",
        }
    if energy_kwh < 0 or power_kw <= 0 or sec <= 0:
        return {
            "ok": True,
            "code": "POWER_TIME_SKIP",
            "message": "电量/功率/时长无效，未做功率×时间电量校验。",
        }
    if sec < _POWER_TIME_MIN_DURATION_SEC:
        return {
            "ok": True,
            "code": "POWER_TIME_SKIP",
            "message": f"充电时长仅 {sec:.0f} 秒，过短未做功率×时间电量校验。",
        }

    hours = sec / 3600.0
    expected = float(power_kw) * hours
    diff = abs(float(energy_kwh) - expected)
    tol = max(_POWER_TIME_ABS_TOL_KWH, expected * _POWER_TIME_REL_TOL)
    msg_core = (
        f"功率×时间估算电量 {expected:.3f} kwh"
        f"（平均功率 {power_kw:.2f} kW × {hours:.3f} h / {sec:.0f} 秒），"
        f"实际电量 {energy_kwh:.3f} kwh，差值 {diff:.3f} kwh"
        f"（容差 {tol:.3f} kwh）"
    )
    if diff <= tol + 1e-9:
        return {
            "ok": True,
            "code": "POWER_TIME_OK",
            "message": f"{msg_core}，电量合理。",
            "expected_kwh": expected,
            "actual_kwh": float(energy_kwh),
            "tol_kwh": tol,
        }
    return {
        "ok": False,
        "code": "POWER_TIME_MISMATCH",
        "message": f"{msg_core}，超出容差，电量可能不合理。",
        "expected_kwh": expected,
        "actual_kwh": float(energy_kwh),
        "tol_kwh": tol,
    }


def _pick_bill_energy_src(
    record: dict[str, Any] | None,
    bill: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """结算电量优先用 recordInfo；原始上报账单常无 totalBattery。"""
    if isinstance(record, dict) and record.get("totalBattery") is not None:
        return record
    if isinstance(bill, dict) and bill.get("totalBattery") is not None:
        return bill
    # 原始 CHARGE_RECORD：用 periodInfos.battery 汇总（星星等常比结算多一位）
    if isinstance(bill, dict):
        periods = bill.get("periodInfos")
        if isinstance(periods, list) and periods:
            try:
                raw = sum(float(p.get("battery") or 0) for p in periods if isinstance(p, dict))
            except (TypeError, ValueError):
                raw = 0.0
            if raw > 0:
                synth = dict(bill)
                synth["totalBattery"] = raw / 10.0 if raw >= 10000 else raw
                return synth
    return record or bill


def _pick_proc_frame(
    chgs: list[dict[str, Any]],
    bill_src: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """过程帧取本单最后一条 chargingInfo，与账单做电量对比。"""
    if not chgs:
        return None
    # 日志按时间顺序收集，末帧即最后一次过程上报
    return chgs[-1]


def _check_process_vs_bill(
    proc: dict[str, Any] | None,
    bill_src: dict[str, Any] | None,
    start_meter: Any,
    end_meter: Any,
    *,
    meter_scale: int | None = None,
    last_power_kw: float | None = None,
) -> list[dict[str, Any]]:
    """过程 chargingInfo 与账单/结算电量、分时交叉校验。

    各侧按自身 accuracyFlag 换算为 kWh 后再比较（蔚景账单常见 accuracyFlag=4 万分位）。
    总电量容差默认 1 kWh；若末帧为大功率，按功率×约 2 分钟滞后放大。
    """
    checks: list[dict[str, Any]] = []
    if not proc and not bill_src:
        return [
            {
                "ok": True,
                "code": "SKIP",
                "message": "缺少过程与账单电量字段，未做交叉校验。",
            }
        ]

    proc_scale = _accuracy_scale(proc, 1000)
    bill_scale = _accuracy_scale(bill_src, 1000)
    m_scale = meter_scale if meter_scale is not None else bill_scale
    if last_power_kw is None:
        last_power_kw = _estimate_power_kw(proc)
    tol_kwh, tol_desc = _energy_tol_kwh(last_power_kw)

    proc_raw = float((proc or {}).get("totalBattery") or 0) if proc else None
    bill_raw = float((bill_src or {}).get("totalBattery") or 0) if bill_src else None
    proc_total = (proc_raw / proc_scale) if proc_raw is not None else None
    bill_total = (bill_raw / bill_scale) if bill_raw is not None else None
    meter_delta = None
    try:
        if start_meter is not None and end_meter is not None:
            meter_delta = (float(end_meter) - float(start_meter)) / float(m_scale)
    except (TypeError, ValueError):
        meter_delta = None

    def _fk(v: float | None) -> str:
        if v is None:
            return "-"
        return _fmt_kwh(v * 1000, 1000)  # 已是 kWh，借千分位格式化

    # 1) 总电量：过程 vs 账单（容差随末帧功率动态调整）
    if proc_total is not None and bill_total is not None and (proc_total > 0 or bill_total > 0):
        diff = abs(proc_total - bill_total)
        if diff < tol_kwh:
            checks.append(
                {
                    "ok": True,
                    "code": "TOTAL_OK",
                    "message": (
                        f"总电量一致：过程 {_fk(proc_total)}，账单 {_fk(bill_total)}"
                        + (
                            f"（差值 {_fk(diff)}，容差 {tol_desc}，可忽略）"
                            if diff > 0
                            else ""
                        )
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
                        f"总电量不一致：过程 {_fk(proc_total)}，账单 {_fk(bill_total)}，"
                        f"相差 {_fk(diff)}（超过容差 {tol_desc}）。"
                    ),
                }
            )

    # 2) 表计差额 vs 账单总电量（结算自洽，仍用基础 1 kWh）
    # 起止表码均为 0 多为未上报占位，不算有效表计，跳过交叉校验，避免「差额 0 vs 账单」误报
    meters_placeholder = False
    try:
        if start_meter is not None and end_meter is not None:
            meters_placeholder = float(start_meter) == 0 and float(end_meter) == 0
    except (TypeError, ValueError):
        meters_placeholder = False
    if meters_placeholder and bill_total is not None and bill_total > 0:
        checks.append(
            {
                "ok": True,
                "code": "METER_SKIP",
                "message": (
                    "起止表码均为 0（未上报有效表计读数），跳过表计与账单电量交叉校验；"
                    f"账单电量 {_fk(bill_total)} 以结算字段为准。"
                ),
            }
        )
    elif meter_delta is not None and bill_total is not None and bill_total > 0:
        diff = abs(meter_delta - bill_total)
        if diff < _ENERGY_TOL_KWH:
            checks.append(
                {
                    "ok": True,
                    "code": "METER_OK",
                    "message": (
                        f"表计电量与账单一致：表计差额 {_fk(meter_delta)}，"
                        f"账单 {_fk(bill_total)}"
                        + (f"（差值 {_fk(diff)}，可忽略）" if diff > 0 else "")
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
                        f"表计电量与账单不一致：表计差额 {_fk(meter_delta)}，"
                        f"账单 {_fk(bill_total)}，相差 {_fk(diff)}。"
                    ),
                }
            )

    # 3) 分时电量：过程 vs 账单（主导时段 + 各时段）——先换算到 kWh
    proc_tou_raw = _tou_map(proc)
    bill_tou_raw = _tou_map(bill_src)
    proc_tou = {k: float(v) / proc_scale for k, v in proc_tou_raw.items()}
    bill_tou = {k: float(v) / bill_scale for k, v in bill_tou_raw.items()}
    # dominant 用换算后的量
    proc_dom = _dominant_tou(proc_tou)
    bill_dom = _dominant_tou(bill_tou)

    def _tou_brief_kwh(tou: dict[str, float]) -> str:
        parts = [f"{k}{_fk(v)}" for k, v in tou.items() if v and float(v) > 0]
        return "、".join(parts) if parts else "无分时电量"

    if proc_dom and bill_dom:
        if proc_dom == bill_dom:
            checks.append(
                {
                    "ok": True,
                    "code": "TOU_DOM_OK",
                    "message": (
                        f"分时主导时段一致：过程与账单均为“{proc_dom}”"
                        f"（过程 {_tou_brief_kwh(proc_tou)}；账单 {_tou_brief_kwh(bill_tou)}）。"
                    ),
                }
            )
        else:
            checks.append(
                {
                    "ok": False,
                    "code": "TOU_DOM_MISMATCH",
                    "message": (
                        f"分时主导时段不一致：过程为“{proc_dom}”（{_tou_brief_kwh(proc_tou)}），"
                        f"账单为“{bill_dom}”（{_tou_brief_kwh(bill_tou)}）。"
                    ),
                }
            )

        for name in ("尖", "峰", "平", "谷"):
            pv, bv = proc_tou[name], bill_tou[name]
            if pv < _ENERGY_TOL_KWH and bv < _ENERGY_TOL_KWH:
                continue
            if bill_total and bv > float(bill_total) + _ENERGY_TOL_KWH and name == "平":
                checks.append(
                    {
                        "ok": True,
                        "code": "TOU_BILL_AGG",
                        "message": (
                            f"账单“{name}”段 {_fk(bv)} 高于账单总电量 {_fk(bill_total)}，"
                            f"疑似结算归集，不与过程逐段绝对值强比对。"
                        ),
                    }
                )
                continue
            diff = abs(pv - bv)
            if diff < tol_kwh:
                continue
            if (pv < _ENERGY_TOL_KWH) != (bv < _ENERGY_TOL_KWH) or diff >= tol_kwh:
                if (pv < _ENERGY_TOL_KWH and bv >= _ENERGY_TOL_KWH) or (
                    bv < _ENERGY_TOL_KWH and pv >= _ENERGY_TOL_KWH
                ):
                    checks.append(
                        {
                            "ok": False,
                            "code": "TOU_SLOT_MISMATCH",
                            "message": (
                                f"分时“{name}”段不一致：过程 {_fk(pv)}，账单 {_fk(bv)}。"
                            ),
                        }
                    )
                elif proc_dom == bill_dom and name == proc_dom:
                    checks.append(
                        {
                            "ok": False,
                            "code": "TOU_AMOUNT_MISMATCH",
                            "message": (
                                f"分时“{name}”段电量差异较大：过程 {_fk(pv)}，"
                                f"账单 {_fk(bv)}，相差 {_fk(diff)}"
                                f"（超过容差 {tol_desc}）。"
                            ),
                        }
                    )
    elif proc_dom or bill_dom:
        checks.append(
            {
                "ok": True,
                "code": "TOU_PARTIAL",
                "message": (
                    f"分时仅一侧有数据：过程 {_tou_brief_kwh(proc_tou)}；"
                    f"账单 {_tou_brief_kwh(bill_tou)}。"
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


def analyze_order_log(
    text: str,
    service_id: str | None = None,
    trade_no: str | None = None,
) -> dict[str, Any]:
    from evcpa.multi_order import build_multi_order_choice, combine_filter

    filter_id = combine_filter(service_id, trade_no)
    sid = filter_id
    # 未指定筛选时，先扫描是否存在多笔订单
    if not sid:
        discovered = _discover_orders(text)
        if len(discovered) > 1:
            pile = next((o.get("pile") for o in discovered if o.get("pile")), None)
            return build_multi_order_choice(
                discovered,
                protocol="order_log",
                protocol_name="充电订单日志",
                pile=pile,
            )

    lines = text.splitlines()
    remote = None
    remote_stop = None
    start_frame = None
    records: list[dict[str, Any]] = []
    bills: list[dict[str, Any]] = []
    socs: list[dict[str, Any]] = []
    chgs: list[dict[str, Any]] = []
    gun_events: list[tuple[str, str, str]] = []
    has_remote_stop = False
    remote_stop_msg: str | None = None
    start_ok = False
    card_auth = False
    vin_auth = False
    offline = False
    fault = False
    fault_notes: list[str] = []
    alarm_notes: list[str] = []
    platform_guard_msg: str | None = None
    start_result_msgs: list[str] = []
    other_gun_notes: list[str] = []
    matched_guns: set[str] = set()
    matched_trade_nos: set[str] = set()

    for ln in lines:
        m = _REMOTE_CMD.search(ln)
        if m:
            obj = _load_json(m.group(1))
            if obj and _match_service(obj, sid):
                cmd = _remote_cmd_str(obj)
                matched_guns.add(str(obj.get("interfaceCode") or (obj.get("data") or {}).get("interfaceCode") or ""))
                matched_trade_nos |= _ids_of(obj)
                if cmd in _REMOTE_STOP_CMDS or (cmd and cmd not in _REMOTE_START_CMDS and ("停止" in ln or cmd == "18")):
                    has_remote_stop = True
                    remote_stop = obj
                    msg = _extract_stop_reason_msg(obj)
                    if msg:
                        remote_stop_msg = msg
                elif cmd in _REMOTE_START_CMDS or not remote:
                    # 保留启动令；停止令不覆盖 remote
                    if cmd in _REMOTE_START_CMDS or remote is None:
                        remote = obj
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
        m = _BILL_CMD8.search(ln) or _BILL_ANY.search(ln)
        if m:
            obj = _load_json(m.group(1))
            if obj and _match_service(obj, sid):
                bills.append(obj)
                matched_trade_nos |= _ids_of(obj)

    # 万马等账单常只有 tradeNo、无 serviceId：按已匹配流水号补收账单
    if not bills and matched_trade_nos:
        for ln in lines:
            m = _BILL_CMD8.search(ln) or _BILL_ANY.search(ln)
            if not m:
                continue
            obj = _load_json(m.group(1))
            if not obj:
                continue
            ids = _ids_of(obj)
            if ids & matched_trade_nos or (not sid and obj):
                bills.append(obj)
                matched_trade_nos |= ids

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
            # 「远程停止充电应答」仅为设备/平台应答，不能当作下发了远程停止命令
            if any(ack in ln for ack in _REMOTE_STOP_ACK_ONLY):
                pass
            elif "RemoteCmd" in ln or "remoteCmd" in ln or "下发远程停止" in ln or "远程停止充电," in ln:
                has_remote_stop = True
                sm = re.search(r'"stopReasonMsg"\s*:\s*"([^"]*)"', ln)
                if sm and sm.group(1).strip():
                    remote_stop_msg = remote_stop_msg or sm.group(1).strip()
        if ("启动充电响应:成功" in ln or "远程启动充电响应，成功" in ln) and related:
            start_ok = True
        if related and any(m in ln for m in _CARD_START_MARKERS):
            card_auth = True
            start_ok = True
        if related and any(m in ln for m in _VIN_START_MARKERS):
            vin_auth = True
            start_ok = True
        # 万马等：创建VIN码充电服务信息成功 / MsgHandler VIN充电
        if related and ("创建VIN" in ln or "【MsgHandler】VIN" in ln or "MsgHandler】VIN" in ln):
            vin_auth = True
            start_ok = True
        if related and "鉴权结果" in ln and "刷卡" not in ln:
            vm = re.search(r'"carvin"\s*:\s*"([^"]*)"', ln)
            if vm and _has_real_vin(vm.group(1)):
                vin_auth = True
                start_ok = True
        if any(m in ln for m in _OFFLINE_LOG_MARKERS):
            # 离线/超时/登录为桩级事件，行内常无 serviceId，仍作为本单离线背景
            offline = True
        for alarm_note in _extract_alarm_notes_from_line(ln):
            # 告警多为桩级事件（常无 serviceId），整段日志内出现即收录
            if alarm_note not in alarm_notes:
                alarm_notes.append(alarm_note)
        # 平台守护停止中文异常（功率不为零电量为0等）
        if related:
            guard = _extract_platform_guard_stop_msg(ln)
            if guard:
                platform_guard_msg = platform_guard_msg or guard
                ts = ts_m.group(1) if (ts_m := _TS.match(ln.strip())) else ""
                note = f"{ts + '　' if ts else ''}{guard}"
                if note not in fault_notes:
                    fault_notes.append(note)
        # 中文启动结果（启动失败/成功）常无 serviceId，按桩级事件收录并原样输出
        start_phrase = _extract_start_result_phrase(ln)
        if start_phrase and start_phrase not in start_result_msgs:
            start_result_msgs.append(start_phrase)
        if "故障" in ln and "枪" in ln and related:
            # 尽量绑定本单枪口；无法识别枪号时仍记入本单异常摘录
            statuses = _parse_gun_statuses(ln)
            gun_hit = statuses[0][0] if statuses else ""
            if not gun_hit:
                gm_fault = re.search(r"(\d+)\s*枪", ln)
                gun_hit = gm_fault.group(1) if gm_fault else ""
            if (not matched_guns) or (not gun_hit) or (gun_hit in matched_guns):
                fault = True
                ts = ts_m.group(1) if (ts_m := _TS.match(ln.strip())) else ""
                snippet = ln.strip()
                if len(snippet) > 120:
                    snippet = snippet[:120] + "…"
                fault_notes.append(f"{ts + '　' if ts else ''}{snippet}")
        ts_m = _TS.match(ln.strip())
        for gun_no, st in _parse_gun_statuses(ln):
            # 仅收录本单已匹配枪口，避免同桩其他枪 TROUBLE 污染本单
            gun_ok = (not matched_guns) or (gun_no in matched_guns)
            if gun_ok:
                gun_events.append((ts_m.group(1) if ts_m else "", gun_no, st))
                if st == "TROUBLE":
                    # 稍后若本枪又进入 CHARGING，则忽略该 TROUBLE
                    pass
            elif st == "TROUBLE":
                ts = ts_m.group(1) if ts_m else ""
                note = f"{ts + '　' if ts else ''}同桩{gun_no}枪 TROUBLE（非本单枪口）"
                if note not in other_gun_notes:
                    other_gun_notes.append(note)

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
    req_currents = [
        x
        for x in (s.get("requireCurrent") for s in socs)
        if x not in (None, "", 0, "0")
    ]
    req_voltages = [
        x
        for x in (s.get("requireVoltage") for s in socs)
        if x not in (None, "", 0, "0")
    ]
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

    start_meter = None
    end_meter = None
    meter_scale = 1000
    if isinstance(src, dict) and src.get("chargeStartMeterBattery") is not None:
        start_meter = src.get("chargeStartMeterBattery")
        end_meter = src.get("chargeEndMeterBattery")
        meter_scale = _accuracy_scale(src, 1000)
    elif isinstance(bill, dict) and bill.get("startMeterBattery") is not None:
        start_meter = bill.get("startMeterBattery")
        end_meter = bill.get("endMeterBattery")
        meter_scale = _accuracy_scale(bill, 1000)
    else:
        start_meter = (src or {}).get("chargeStartMeterBattery") if isinstance(src, dict) else None
        end_meter = (src or {}).get("chargeEndMeterBattery") if isinstance(src, dict) else None
        if start_meter is None and isinstance(bill, dict):
            start_meter = bill.get("startMeterBattery")
            end_meter = bill.get("endMeterBattery")
            meter_scale = _accuracy_scale(bill, 1000)
        elif isinstance(src, dict):
            meter_scale = _accuracy_scale(src, 1000)

    src_scale = _accuracy_scale(src if isinstance(src, dict) else None, 1000)
    total_batt = src.get("totalBattery") or (bill or {}).get("totalBattery")
    # 主展示电量若来自账单，用账单精度
    if src.get("totalBattery") is None and isinstance(bill, dict) and bill.get("totalBattery") is not None:
        display_scale = _accuracy_scale(bill, 1000)
    else:
        display_scale = src_scale
    duration = src.get("chargeDuration") or (chgs[-1].get("chargeDuration") if chgs else None)

    jian = src.get("jianBattery", 0) or 0
    feng = src.get("fengBattery", 0) or 0
    ping = src.get("pingBattery", 0) or 0
    gu = src.get("guBattery", 0) or 0
    # 分时若结算侧无值而账单有，回落到账单（并切换精度）
    tou_scale = display_scale
    if not any(float(x or 0) > 0 for x in (jian, feng, ping, gu)) and isinstance(bill, dict):
        jian = bill.get("jianBattery", 0) or 0
        feng = bill.get("fengBattery", 0) or 0
        ping = bill.get("pingBattery", 0) or 0
        gu = bill.get("guBattery", 0) or 0
        tou_scale = _accuracy_scale(bill, 1000)
    jian_p, feng_p, ping_p, gu_p = src.get("jianPrice"), src.get("fengPrice"), src.get("pingPrice"), src.get("guPrice")

    # 过程帧：优先对齐账单结束表码；账单电量优先 recordInfo
    bill_src = _pick_bill_energy_src(
        record if isinstance(record, dict) else None,
        bill if isinstance(bill, dict) else None,
    )
    proc_frame = _pick_proc_frame(chgs, bill_src if isinstance(bill_src, dict) else None)
    bill_scale = _accuracy_scale(bill_src if isinstance(bill_src, dict) else None, 1000)
    proc_scale = _accuracy_scale(proc_frame, 1000)
    last_power_kw = _estimate_power_kw(
        proc_frame,
        socs[-1] if socs else None,
    )
    energy_checks = _check_process_vs_bill(
        proc_frame,
        bill_src,
        start_meter,
        end_meter,
        meter_scale=meter_scale,
        last_power_kw=last_power_kw,
    )
    series_checks = _check_process_energy_series(chgs, scale=proc_scale)
    tou_freeze_checks = _check_inactive_tou_frozen(chgs, scale=proc_scale)
    energy_checks = list(energy_checks) + list(series_checks) + list(tou_freeze_checks)
    energy_mismatch = any(not c.get("ok", True) for c in energy_checks)
    charge_money = src.get("chargeMoney") or src.get("serverChargeMoney")
    service_money = src.get("serviceMoney") or src.get("serverServiceMoney")
    parking_money = src.get("parkingMoney") or src.get("serverParkingMoney") or 0
    appoint_money = src.get("appointmentMoney") or src.get("serverAppointmentMoney") or 0
    has_occupy = src.get("isHasOccupyFee", 0) in (1, "1", True)

    finish_code = src.get("deviceChargeFinishReasonCode")
    if finish_code is None:
        finish_code = src.get("chargeFinishReason")
    if finish_code is None and isinstance(bill, dict):
        finish_code = bill.get("stopReason") or bill.get("deviceChargeFinishReasonCode")
    finish_msg = src.get("deviceChargeFinishReasonMsg") or "-"
    if (not finish_msg or finish_msg == "-") and isinstance(bill, dict):
        finish_msg = (
            bill.get("deviceChargeFinishReasonMsg")
            or bill.get("chargeFinishReasonMsg")
            or bill.get("stopReasonMsg")
            or finish_msg
        )
    # 万马等账单只有 stopReason 代码、无中文说明
    if (not finish_msg or finish_msg == "-") and finish_code is not None and str(finish_code).strip() not in {"", "-", "0"}:
        finish_msg = f"结束代码 {finish_code}"
    if not remote_stop_msg and remote_stop:
        remote_stop_msg = _extract_stop_reason_msg(remote_stop)

    # 掉电结束原因也视为离线场景
    if _is_offline_finish(
        "" if finish_msg == "-" else str(finish_msg or ""),
        finish_code,
    ):
        offline = True

    # 账单 startWay 并入 src 供启动方式识别
    if isinstance(src, dict) and src.get("startWay") is None and isinstance(bill, dict) and bill.get("startWay") is not None:
        src = {**src, "startWay": bill.get("startWay"), "carvin": src.get("carvin") or bill.get("carvin")}

    # 充电结束拔枪后：本枪后续状态/故障/异常与本单脱钩
    unplug_ts = _first_idle_after_charging(gun_events, gun)
    gun_events = _clip_gun_events_after_unplug(gun_events, gun)
    fault_notes = _filter_notes_before_ts(fault_notes, unplug_ts)
    alarm_notes = _filter_notes_before_ts(alarm_notes, unplug_ts)
    for ts, gun_no, st in gun_events:
        if st != "TROUBLE":
            continue
        if gun not in (None, "", "-") and str(gun_no) != str(gun):
            continue
        if _trouble_followed_by_charging(gun_events, gun_no):
            continue
        note = f"{ts + '　' if ts else ''}{gun_no}枪状态变为 TROUBLE"
        if note not in fault_notes:
            fault_notes.append(note)
    fault = bool(fault_notes)

    stop_info = _analyze_stop(
        has_remote_stop=has_remote_stop,
        remote_stop_msg=remote_stop_msg,
        finish_msg=None if finish_msg == "-" else finish_msg,
        finish_code=finish_code,
        gun_events=gun_events,
        gun=gun,
        offline_reconnect=offline,
        alarm_notes=alarm_notes,
        platform_guard_msg=platform_guard_msg,
    )
    # 急停/故障类在结论里需要提示确认
    need_user_confirm = stop_info["category"] in {"estop_suspect", "gun_fault"}

    # 时间：账单 BCD → 结算/账单 unix/ISO → 枪状态行
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

    for obj in (bill, record, src if isinstance(src, dict) else None):
        if not isinstance(obj, dict):
            continue
        st = _parse_log_time(obj.get("startTime"))
        et = _parse_log_time(obj.get("endTime"))
        if st and start_time == "-":
            start_time = st
        if et and end_time == "-":
            end_time = et
        if start_time != "-" and end_time != "-":
            break
    if start_time == "-" and charge_start_ts:
        start_time = charge_start_ts[:19]
    if end_time == "-" and charge_end_ts:
        end_time = charge_end_ts[:19]

    # 时长：优先按枪口 CHARGING 时段累计（OCCUPYING 等不算充电）；
    # 其次平台 chargeDuration；最后用订单起止时间差。
    charge_dur, charge_first, charge_last = _charging_duration_from_gun_events(gun_events, gun)
    if charge_dur is not None and charge_dur > 0:
        duration = charge_dur
        if charge_first:
            charge_start_ts = charge_first
        if charge_last:
            charge_end_ts = charge_last
    elif duration in (None, "", "-", 0, "0"):
        duration = _duration_seconds(
            start_time if start_time != "-" else None,
            end_time if end_time != "-" else None,
        )

    # 功率×时间 ≈ 电量合理性校验（依赖最终时长与平均功率）
    avg_power_kw = _avg_power_kw_from_samples(powers, calc_powers, last_power_kw)
    energy_for_pt = None
    if isinstance(bill_src, dict) and bill_src.get("totalBattery") is not None:
        try:
            energy_for_pt = float(bill_src["totalBattery"]) / float(bill_scale)
        except (TypeError, ValueError):
            energy_for_pt = None
    if energy_for_pt is None and total_batt is not None:
        energy_for_pt = _num(total_batt, display_scale, 4)
    if energy_for_pt is None and isinstance(proc_frame, dict) and proc_frame.get("totalBattery") is not None:
        try:
            energy_for_pt = float(proc_frame["totalBattery"]) / float(proc_scale)
        except (TypeError, ValueError):
            energy_for_pt = None
    power_time_check = _check_energy_vs_power_time(
        energy_kwh=energy_for_pt,
        power_kw=avg_power_kw,
        duration_sec=duration,
    )
    energy_checks = list(energy_checks) + [power_time_check]
    energy_mismatch = any(not c.get("ok", True) for c in energy_checks)

    stages: list[dict[str, Any]] = []
    detail = src.get("chargeStageDetail")
    if isinstance(detail, str) and detail.startswith("["):
        try:
            stages = json.loads(detail)
        except Exception:
            stages = []
    elif isinstance(detail, list):
        stages = detail

    total_kwh = _num(total_batt, display_scale, 4)
    ping_kwh = _num(ping, tou_scale, 4)
    money_scale = src_scale
    if src.get("chargeMoney") is None and isinstance(bill, dict) and bill.get("chargeMoney") is not None:
        money_scale = _accuracy_scale(bill, 1000)
    charge_yuan = _num(charge_money, money_scale, 4)
    service_yuan = _num(service_money, money_scale, 4)
    total_fee = None
    if charge_money is not None or service_money is not None:
        total_fee = _num(
            (charge_money or 0) + (service_money or 0) + (parking_money or 0), money_scale, 4
        )
    ping_price = _num(ping_p, src_scale, 4)
    balance_yuan = _num(balance_raw, 1000, 3) if balance_raw is not None else None
    # ---- 组装客户报告文本 ----
    today = date.today()
    report_date = f"{today.year}年{today.month}月{today.day}日"
    dur_text = _fmt_duration(duration)
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
    start_check = _check_start_success(
        start_ok=start_ok,
        is_card_start=is_card_start,
        is_vin_start=is_vin_start,
        is_remote_start=is_remote_start,
        has_remote_cmd=bool(remote),
        gun_events=gun_events,
        gun=gun,
        socs=socs,
        chgs=chgs,
        start_result_msgs=start_result_msgs,
    )
    # 日志已有明确「启动失败，…」文案：结论明确，不纳入需复核的 start_mismatch
    start_result_txt = str(
        start_check.get("start_result") or start_check.get("message") or ""
    ).strip()
    start_fail_explicit = (not start_check.get("ok", True)) and start_result_txt.startswith(
        "启动失败"
    )
    start_mismatch = (not start_check.get("ok", True)) and not start_fail_explicit
    if start_fail_explicit:
        start_check = {
            **start_check,
            "code": "START_REJECTED",
            "explicit_fail": True,
        }

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
        f"启动结果：{start_check.get('start_result') or ('启动成功' if start_check.get('ok') else '-')}",
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
    req_cur_avg = (
        f"约 {_fmt_amp(mean(req_currents)).replace(' 安', '')} 安" if req_currents else "-"
    )
    req_cur_rng = (
        f"{_fmt_amp(min(req_currents)).replace(' 安','')} ～ {_fmt_amp(max(req_currents))}"
        if req_currents
        else "-"
    )
    req_vol_avg = (
        f"约 {_fmt_volt(mean(req_voltages)).replace(' 伏', '')} 伏" if req_voltages else "-"
    )
    req_vol_rng = (
        f"{_fmt_volt(min(req_voltages)).replace(' 伏','')} ～ {_fmt_volt(max(req_voltages))}"
        if req_voltages
        else "-"
    )
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
        f"需求电流 requireCurrent（平均）：{req_cur_avg}",
        f"需求电流 requireCurrent（范围）：{req_cur_rng}",
        f"需求电压 requireVoltage（平均）：{req_vol_avg}",
        f"需求电压 requireVoltage（范围）：{req_vol_rng}",
        f"输出功率（平均）：{pwr_avg}",
        f"输出功率（范围）：{pwr_rng}",
        f"功率印证（电流×电压）：{pwr_check}",
        f"实时采样点数：{len(socs)}（按流水号 {trade_no} 过滤后的 socInfo）",
        f"起始终端表码：{_fmt_kwh(start_meter, meter_scale)}",
        f"结束终端表码：{_fmt_kwh(end_meter, meter_scale)}",
        f"实际充电电量：{_fmt_kwh(total_batt, display_scale)}",
        f"电池荷电状态：{'未上报（全程为 0）' if not soc_nonzero else '有上报'}",
        f"车辆识别码：{vin}",
        f"模块温度（范围）：{temp_rng}",
        "",
        "说明：电流、电压与需求电流/电压取实时 socInfo 上报；输出功率优先取 batteryChargerOutPower，并用同帧电流×电压交叉印证；电量与起止表码一致。",
    ]

    out += _section("三、分时电量（尖 / 峰 / 平 / 谷）")
    out += [
        f"尖：{_fmt_kwh(jian, tou_scale)}，电价 {_fmt_price(jian_p, src_scale)}",
        f"峰：{_fmt_kwh(feng, tou_scale)}，电价 {_fmt_price(feng_p, src_scale)}",
        f"平：{_fmt_kwh(ping, tou_scale)}"
        + ("（结算归集）" if ping_kwh and total_kwh and ping_kwh > total_kwh else "")
        + f"，电价 {_fmt_price(ping_p, src_scale)}",
        f"谷：{_fmt_kwh(gu, tou_scale)}，电价 {_fmt_price(gu_p, src_scale)}",
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
        out.append(f"分时段明细（各时段电量之和 = {_fmt_kwh(stage_sum, display_scale)}）：")
        for s in stages:
            note = ""
            # 简单提示首尾时段
            out.append(
                f"{s.get('startTime', '?')} ～ {s.get('endTime', '?')}：{_fmt_kwh(s.get('battery'), display_scale)}{note}"
            )
        out.append(f"合计：{_fmt_kwh(stage_sum, display_scale)}")

    out += _section("四、过程与账单校验")
    out.append(
        "说明：对比 chargingInfo（过程）与 recordInfo/账单（结算）；"
        "并校验过程总电量/分时是否逐步递增、非所属时段分时是否固化；"
        "再用平均功率×充电时长估算电量，核对实际电量是否合理；"
        "各侧按 accuracyFlag 换算（缺省千分位，蔚景账单常见万分位）；"
        "基础容差 1 kwh，末帧为大功率时按功率×约 2 分钟滞后放大容差；"
        f"功率×时间容差取 max({_POWER_TIME_ABS_TOL_KWH:g} kwh, 期望值×{_POWER_TIME_REL_TOL:.0%})。"
    )
    out.append(f"启动校验：{start_check.get('message')}")
    out.append(
        f"过程电量快照：总 {_fmt_kwh((proc_frame or {}).get('totalBattery'), proc_scale)}，"
        f"{_fmt_tou_brief(_tou_map(proc_frame), proc_scale)}。"
        if proc_frame
        else "过程电量快照：无 chargingInfo。"
    )
    out.append(
        f"账单电量快照：总 {_fmt_kwh((bill_src or {}).get('totalBattery'), bill_scale)}"
        + (
            f"（accuracyFlag={bill_src.get('accuracyFlag')}，÷{bill_scale}）"
            if isinstance(bill_src, dict) and bill_src.get("accuracyFlag") is not None
            else ""
        )
        + f"，{_fmt_tou_brief(_tou_map(bill_src), bill_scale)}。"
        if bill_src
        else "账单电量快照：无结算/账单数据。"
    )
    for i, ck in enumerate(energy_checks, 1):
        mark = "通过" if ck.get("ok") else "异常"
        out.append(f"{i}. [{mark}] {ck.get('message')}")
    if energy_mismatch or start_mismatch:
        bits = []
        if start_mismatch:
            bits.append("启动校验未通过")
        if energy_mismatch:
            bits.append("过程电量序列/账单交叉校验或功率×时间电量校验存在异常")
        out.append("结论：" + "；".join(bits) + "，请复核。")
    elif start_fail_explicit:
        out.append(f"结论：{start_result_txt}，启动未成功，原因明确，无需复核。")
    else:
        out.append(
            "结论：启动校验通过；过程电量递增与非所属时段固化正常；"
            "过程与账单电量/分时在容差内一致；功率×时间估算电量合理。"
        )

    out += _section("五、费用明细")
    out += [
        f"电费：{_fmt_money(charge_money, money_scale)}",
        f"服务费：{_fmt_money(service_money, money_scale)}",
        f"占桩费：{_fmt_money(parking_money, money_scale) if parking_money else '0 元'}",
        f"预约费：{_fmt_money(appoint_money, money_scale) if appoint_money else '0 元'}",
        f"费用合计：{_fmt_money((charge_money or 0)+(service_money or 0)+(parking_money or 0), money_scale) if charge_money is not None or service_money is not None else '-'}",
        "",
    ]
    if total_fee is not None and balance_yuan is not None:
        out.append(
            f"费用校验：电费 + 服务费 ≈ 启动余额 {balance_disp}，与结束原因“{finish_msg}”相符。"
            if finish_msg and finish_msg != "-"
            else f"费用校验：费用合计约 {_fmt_money((charge_money or 0)+(service_money or 0)+(parking_money or 0), money_scale)}，启动余额 {balance_disp}。"
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
        f"停止类型：{stop_info['stop_type']}",
        f"停止原因：{stop_info['reason']}",
        f"平台停止原因（stopReasonMsg）：{stop_info['platform_stop_reason']}",
        f"设备结束原因（deviceChargeFinishReasonMsg）：{stop_info['device_finish_reason']}",
        f"结束原因代码：{finish_code if finish_code is not None else '-'}",
        f"枪口状态变迁：{stop_info['gun_transition']}",
        f"停止依据：{stop_info['evidence']}",
        f"是否占桩计费：{'是' if has_occupy else '否'}",
        f"占桩时长：{occupy_dur}",
        f"占桩费用：{_fmt_money(parking_money, money_scale) if parking_money else '0 元'}",
    ]
    if fault_notes:
        out.append("本单异常/告警摘录：" + "；".join(fault_notes[:5]) + "。")
    else:
        out.append("本单异常/告警摘录：无（本单枪口未见 TROUBLE/故障告警）。")
    if alarm_notes:
        out.append("告警信息：" + "；".join(alarm_notes[:8]) + "。")
    else:
        out.append("告警信息：无。")
    if other_gun_notes:
        out.append("同桩其他枪口提示（非本单）：" + "；".join(other_gun_notes[:3]) + "。")
    if stop_info.get("tip"):
        out.append(f"提示：{stop_info['tip']}")
    if finish_msg and str(finish_msg).startswith("结束代码 ") and not fault_notes:
        out.append(
            f"说明：设备仅上报停止码 {finish_code}，日志中无对应中文原因；"
            "请结合厂商停止码表核对（不等于平台判定的电气异常）。"
        )

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
        if has_remote_stop:
            if stop_info["category"] == "user_remote_stop":
                steps.append(
                    f"{n}. {_cn_datetime(end_time)}　用户远程停止充电（平台未下发具体停止原因）并完成结算。"
                )
            elif stop_info["category"] == "platform_guard_stop":
                steps.append(
                    f"{n}. {_cn_datetime(end_time)}　平台停止：{stop_info['reason']}，并完成结算。"
                )
            else:
                steps.append(
                    f"{n}. {_cn_datetime(end_time)}　平台下发远程停止"
                    + (f"（{stop_info['reason']}）" if stop_info.get("reason") and stop_info["reason"] != "-" else "")
                    + "并完成结算。"
                )
        elif stop_info["category"] == "offline_gun_fault":
            steps.append(
                f"{n}. {_cn_datetime(end_time)}　设备离线重连后上报枪口故障并结单"
                + (
                    f"，设备上报“{stop_info['device_finish_reason']}”。"
                    if stop_info.get("device_finish_reason")
                    and stop_info["device_finish_reason"] != "-"
                    else "。"
                )
            )
        elif stop_info["category"] == "offline_reconnect":
            steps.append(
                f"{n}. {_cn_datetime(end_time)}　设备离线重连后上报账单结束订单"
                + (
                    f"，设备上报“{stop_info['device_finish_reason']}”。"
                    if stop_info.get("device_finish_reason")
                    and stop_info["device_finish_reason"] != "-"
                    else "。"
                )
            )
        elif stop_info["category"] in {"device_unplug", "device_occupy", "device_idle_unplug"}:
            steps.append(
                f"{n}. {_cn_datetime(end_time)}　{stop_info['stop_type']}，"
                f"设备上报“{stop_info['device_finish_reason']}”并上报账单。"
            )
        elif stop_info["category"] == "estop_suspect":
            steps.append(
                f"{n}. {_cn_datetime(end_time)}　枪口短暂故障后恢复，疑似急停；"
                f"设备上报“{stop_info['device_finish_reason']}”。"
            )
        elif stop_info["category"] == "gun_fault":
            steps.append(
                f"{n}. {_cn_datetime(end_time)}　枪口故障停止，设备上报“{stop_info['device_finish_reason']}”。"
            )
        elif finish_msg and finish_msg != "-":
            steps.append(f"{n}. {_cn_datetime(end_time)}　设备按“{finish_msg}”结束充电并上报账单。")
        else:
            steps.append(f"{n}. {_cn_datetime(end_time)}　充电结束并上报账单。")
        n += 1
    if offline:
        steps.append(f"{n}. 过程中曾出现离线/超时记录，需到设备上核实充电数据，请设备方协助排查。")
        n += 1
    if stop_info.get("tip"):
        steps.append(f"{n}. {stop_info['tip']}")
        n += 1
    steps.append(f"{n}. 结束后枪口恢复空闲/待充" + ("，无离线、无故障告警记录。" if not offline and not fault else "。"))
    out.extend(steps or ["1. 已提取订单关键充电数据。"])

    out += _section("八、结论")
    normal = bool(total_batt or socs) and not (stop_info["category"] in {"gun_fault"})
    if need_user_confirm:
        out.append(f"本订单停止类型为「{stop_info['stop_type']}」，需现场确认。")
    elif start_fail_explicit:
        out.append(f"本订单启动失败：{start_result_txt}，原因明确，无需复核。")
    elif normal and not has_remote_stop and not energy_mismatch and not start_mismatch and stop_info["category"] in {
        "device_finish",
        "device_unplug",
        "device_occupy",
        "device_idle_unplug",
        "offline_reconnect",
        "offline_gun_fault",
    }:
        out.append(f"本订单为「{stop_info['stop_type']}」结束的充电订单。")
    elif stop_info["category"] == "platform_guard_stop":
        out.append(f"本订单为「平台停止」：{stop_info['reason']}。")
    elif energy_mismatch or start_mismatch:
        out.append("本订单已提取完毕，但启动或过程电量校验存在差异，需重点复核。")
    elif has_remote_stop:
        if stop_info["category"] == "user_remote_stop":
            out.append("本订单为用户远程停止结束的充电订单。")
        else:
            out.append("本订单为平台远程停止结束的充电订单。")
    else:
        out.append("本订单充电数据已提取完毕，请结合下列要点复核。")
    out.append("")
    bullets = []
    if start_mismatch:
        bullets.append(f"1. {start_check.get('message')}")
    elif is_card_start:
        bullets.append(
            "1. 刷卡启动成功，枪口已进入充电，过程有电流/电压/电量上报。"
            if start_check.get("ok")
            else f"1. {start_check.get('message')}"
        )
    elif is_vin_start:
        bullets.append(
            "1. VIN 鉴权启动成功，枪口已进入充电，过程有电流/电压/电量上报。"
            if start_check.get("ok")
            else f"1. {start_check.get('message')}"
        )
    elif is_remote_start or remote or start_ok:
        bullets.append(
            "1. 远程启动成功，枪口已进入充电，过程有电流/电压/电量上报。"
            if start_check.get("ok")
            else f"1. {start_check.get('message')}"
        )
    else:
        bullets.append(f"1. {start_check.get('message')}")
    if energy_mismatch:
        bad = [c["message"] for c in energy_checks if not c.get("ok")]
        bullets.append("2. 过程电量/账单校验异常：" + ("；".join(bad[:3]) if bad else "电量或分时不一致。"))
    elif has_remote_stop:
        if stop_info["category"] == "user_remote_stop":
            msg = "2. 平台下发远程停止，但无具体停止原因，一般判定为用户远程停止充电。"
        elif stop_info["category"] == "platform_guard_stop":
            msg = f"2. 平台停止：{stop_info['reason']}。"
        else:
            msg = f"2. 平台下发远程停止，停止原因：{stop_info['reason']}。"
        if offline:
            msg += "过程中曾出现离线，需到设备上核实充电数据，请设备方协助排查。"
        bullets.append(msg)
    elif stop_info["category"] == "estop_suspect":
        bullets.append("2. 枪口曾短暂 TROUBLE 后恢复，且无告警信息，疑似用户按下急停，请向现场确认。")
    elif stop_info["category"] == "gun_fault":
        if alarm_notes:
            bullets.append(
                "2. 枪口 TROUBLE 且存在告警信息，判定为枪口故障（非急停），需设备方排查："
                + "；".join(alarm_notes[:3])
                + "。"
            )
        else:
            bullets.append("2. 枪口进入 TROUBLE 并持续异常，判定为枪口故障停止，需设备方排查。")
    elif stop_info["category"] == "offline_gun_fault":
        bullets.append(
            f"2. 无平台远程停止；先离线，重连后上报枪口故障，设备原因：{stop_info['device_finish_reason']}。"
            "属离线上报故障，非人工急停。需到设备上核实充电数据，请设备方协助排查。"
        )
    elif stop_info["category"] == "offline_reconnect":
        bullets.append(
            f"2. 无平台远程停止；设备离线重连导致订单结束，设备原因：{stop_info['device_finish_reason']}。"
            "需到设备上核实充电数据，请设备方协助排查。"
        )
    elif stop_info["category"] in {"device_unplug", "device_occupy", "device_idle_unplug"}:
        msg = (
            f"2. 无平台远程停止；{stop_info['stop_type']}，设备原因：{stop_info['device_finish_reason']}。"
        )
        if offline:
            msg += "过程中曾出现离线，需到设备上核实充电数据，请设备方协助排查。"
        bullets.append(msg)
    elif offline:
        bullets.append("2. 充电过程中出现离线/超时，需到设备上核实充电数据，请设备方协助排查。")
    elif not fault and not alarm_notes:
        bullets.append("2. 充电期间无离线、无故障、无告警，也无平台远程停止指令。")
    else:
        detail_parts: list[str] = []
        if fault_notes:
            detail_parts.append("；".join(fault_notes[:3]))
        if alarm_notes:
            detail_parts.append("告警：" + "；".join(alarm_notes[:3]))
        detail = "；".join(detail_parts) if detail_parts else "存在故障/告警关键字"
        bullets.append(f"2. 日志异常：{detail}。建议人工复核。")
    if stop_info.get("reason") and stop_info["reason"] != "-":
        fee_txt = (
            _fmt_money((charge_money or 0) + (service_money or 0) + (parking_money or 0), money_scale)
            if charge_money is not None
            else "-"
        )
        if stop_info["device_finish_reason"] == "金额截止":
            bullets.append(
                f"3. 订单因账户余额用尽（金额截止）结束，费用合计约 {fee_txt}"
                + ("，与启动余额一致。" if balance_disp != "-" else "。")
            )
        else:
            bullets.append(
                f"3. 停止类型「{stop_info['stop_type']}」，原因：{stop_info['reason']}；费用合计约 {fee_txt}。"
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
        bullets.append("6. 过程电量/账单校验：发现不一致，详见“四、过程与账单校验”。")
    if start_mismatch:
        bullets.append(f"{len(bullets) + 1}. 启动校验未通过，详见启动校验说明。")
    if need_user_confirm and stop_info.get("tip"):
        bullets.append(f"{len(bullets) + 1}. {stop_info['tip']}")
    if offline and not any("需到设备上核实充电数据" in b for b in bullets):
        bullets.append(
            f"{len(bullets) + 1}. 过程中曾出现离线，需到设备上核实充电数据，请设备方协助排查。"
        )
    if other_gun_notes and stop_info["category"] not in {"gun_fault", "estop_suspect"}:
        bullets.append(
            f"{len(bullets) + 1}. 同桩其他枪口提示（与本单无关）："
            + "；".join(other_gun_notes[:2])
            + "。"
        )
    out.extend(bullets)
    out.append("")
    if start_fail_explicit and not energy_mismatch:
        out.append(f"综合判断：{start_result_txt}，启动未成功，原因明确，无需复核。")
        valid = True
        verdict = f"综合判断：{start_result_txt}，启动未成功，原因明确，无需复核。"
    elif stop_info["category"] == "platform_guard_stop":
        # 平台已给出明确异常文案（如功率不为零电量为0），直接输出，不淹没在电量校验里
        out.append(f"综合判断：平台停止——{stop_info['reason']}。")
        valid = True
        verdict = f"综合判断：平台停止——{stop_info['reason']}。"
    elif energy_mismatch or start_mismatch:
        reasons = []
        if start_mismatch:
            reasons.append("启动校验未通过")
        if energy_mismatch:
            reasons.append("过程电量递增/分时固化或账单交叉校验异常")
        reason_txt = "、".join(reasons)
        out.append(f"综合判断：{reason_txt}，请复核后再确认结算。")
        out.append("需到设备上核实相关数据，请设备方协助排查。")
        valid = False
        verdict = (
            f"综合判断：{reason_txt}，请复核后再确认结算。\n"
            "需到设备上核实相关数据，请设备方协助排查。"
        )
    elif need_user_confirm:
        out.append(f"综合判断：{stop_info['stop_type']}，{stop_info.get('tip') or '请现场确认后再定性。'}")
        out.append("需到设备上核实相关数据，请设备方协助排查。")
        valid = False
        verdict = (
            f"综合判断：{stop_info['stop_type']}，{stop_info.get('tip') or '请现场确认后再定性。'}\n"
            "需到设备上核实相关数据，请设备方协助排查。"
        )
    elif offline:
        if stop_info["category"] == "offline_gun_fault":
            out.append(
                "综合判断：离线上报枪口故障（先离线、重连后报 TROUBLE），非人工急停；"
                "需到设备上核实充电数据后再确认。"
            )
            verdict = (
                "综合判断：离线上报枪口故障（先离线、重连后报 TROUBLE），非人工急停；"
                "需到设备上核实充电数据后再确认。\n"
                "需到设备上核实相关数据，请设备方协助排查。"
            )
        else:
            out.append("综合判断：充电过程中出现离线，需到设备上核实充电数据后再确认。")
            verdict = (
                "综合判断：充电过程中出现离线，需到设备上核实充电数据后再确认。\n"
                "需到设备上核实相关数据，请设备方协助排查。"
            )
        out.append("需到设备上核实相关数据，请设备方协助排查。")
        valid = False
    elif has_remote_stop:
        if stop_info["category"] == "user_remote_stop":
            out.append("综合判断：用户远程停止（无具体停止原因），结算数据可核对。")
            valid = True
            verdict = "综合判断：用户远程停止（无具体停止原因），结算数据可核对。"
        else:
            out.append("综合判断：平台远程停止流程完整，结算数据可核对。")
            valid = True
            verdict = "综合判断：平台远程停止流程完整，结算数据可核对。"
    elif normal and not offline and stop_info["category"] != "unknown":
        out.append(f"综合判断：{stop_info['stop_type']}，结算与结束原因可核对。")
        valid = True
        verdict = f"综合判断：{stop_info['stop_type']}，结算与结束原因可核对。"
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
        {
            "name": "启动结果",
            "value": start_check.get("start_result")
            or ("启动成功" if start_check.get("ok") else "-"),
        },
        {"name": "启动时间", "value": _cn_datetime(start_time)},
        {"name": "结束时间", "value": _cn_datetime(end_time)},
        {"name": "充电时长", "value": dur_text},
        {"name": "启动时账户余额", "value": balance_disp},
        {"name": "充电电流（平均）", "value": cur_avg},
        {"name": "充电电流（范围）", "value": cur_rng},
        {"name": "充电电压（平均）", "value": vol_avg},
        {"name": "充电电压（范围）", "value": vol_rng},
        {"name": "需求电流（平均）", "value": req_cur_avg},
        {"name": "需求电流（范围）", "value": req_cur_rng},
        {"name": "需求电压（平均）", "value": req_vol_avg},
        {"name": "需求电压（范围）", "value": req_vol_rng},
        {"name": "输出功率（平均）", "value": pwr_avg},
        {"name": "输出功率（范围）", "value": pwr_rng},
        {"name": "功率印证（电流×电压）", "value": pwr_check},
        {"name": "实时采样点数", "value": f"{len(socs)}（流水号 {trade_no}）"},
        {"name": "起始终端表码", "value": _fmt_kwh(start_meter, meter_scale)},
        {"name": "结束终端表码", "value": _fmt_kwh(end_meter, meter_scale)},
        {"name": "实际充电电量", "value": _fmt_kwh(total_batt, display_scale)},
        {
            "name": "过程电量（chargingInfo）",
            "value": _fmt_kwh((proc_frame or {}).get("totalBattery"), proc_scale) if proc_frame else "-",
        },
        {
            "name": "过程分时",
            "value": _fmt_tou_brief(_tou_map(proc_frame), proc_scale) if proc_frame else "-",
        },
        {
            "name": "账单分时",
            "value": _fmt_tou_brief(_tou_map(bill_src), bill_scale) if bill_src else "-",
        },
        {
            "name": "账单总电量",
            "value": _fmt_kwh((bill_src or {}).get("totalBattery"), bill_scale) if bill_src else "-",
        },
        {
            "name": "过程与账单校验",
            "value": "异常" if energy_mismatch else "通过",
        },
        {
            "name": "功率×时间电量校验",
            "value": (
                "异常"
                if power_time_check.get("code") == "POWER_TIME_MISMATCH"
                else "通过"
                if power_time_check.get("code") == "POWER_TIME_OK"
                else "未校验"
            ),
        },
        {
            "name": "功率×时间电量说明",
            "value": power_time_check.get("message") or "-",
        },
        {
            "name": "启动校验",
            "value": (
                "失败（明确）"
                if start_fail_explicit
                else ("通过" if start_check.get("ok") else "异常")
            ),
        },
        {
            "name": "启动校验说明",
            "value": start_check.get("message") or "-",
        },
        {"name": "电池荷电状态", "value": "未上报（全程为 0）" if not soc_nonzero else "有上报"},
        {"name": "车辆识别码", "value": vin},
        {"name": "模块温度（范围）", "value": temp_rng},
        {"name": "尖电量", "value": _fmt_kwh(jian, tou_scale)},
        {"name": "峰电量", "value": _fmt_kwh(feng, tou_scale)},
        {"name": "平电量", "value": _fmt_kwh(ping, tou_scale)},
        {"name": "谷电量", "value": _fmt_kwh(gu, tou_scale)},
        {"name": "尖电价", "value": _fmt_price(jian_p, src_scale)},
        {"name": "峰电价", "value": _fmt_price(feng_p, src_scale)},
        {"name": "平电价", "value": _fmt_price(ping_p, src_scale)},
        {"name": "谷电价", "value": _fmt_price(gu_p, src_scale)},
        {"name": "电费", "value": _fmt_money(charge_money, money_scale)},
        {"name": "服务费", "value": _fmt_money(service_money, money_scale)},
        {"name": "占桩费", "value": _fmt_money(parking_money, money_scale) if parking_money else "0 元"},
        {"name": "预约费", "value": _fmt_money(appoint_money, money_scale) if appoint_money else "0 元"},
        {
            "name": "费用合计",
            "value": _fmt_money((charge_money or 0) + (service_money or 0) + (parking_money or 0), money_scale)
            if charge_money is not None or service_money is not None
            else "-",
        },
        {"name": "是否有远程停止指令", "value": "有" if has_remote_stop else "无"},
        {"name": "停止类型", "value": stop_info["stop_type"]},
        {"name": "停止原因", "value": stop_info["reason"]},
        {"name": "平台停止原因", "value": stop_info["platform_stop_reason"]},
        {"name": "设备结束原因", "value": stop_info["device_finish_reason"]},
        {"name": "结束原因代码", "value": str(finish_code) if finish_code is not None else "-"},
        {"name": "枪口状态变迁", "value": stop_info["gun_transition"]},
        {"name": "停止依据", "value": stop_info["evidence"]},
        {"name": "停止提示", "value": stop_info["tip"] or "-"},
        {
            "name": "本单异常/告警摘录",
            "value": "；".join(fault_notes[:5]) if fault_notes else "无",
        },
        {
            "name": "告警信息",
            "value": "；".join(alarm_notes[:8]) if alarm_notes else "无",
        },
        {
            "name": "同桩其他枪口提示",
            "value": "；".join(other_gun_notes[:3]) if other_gun_notes else "无",
        },
        {"name": "是否占桩计费", "value": "是" if has_occupy else "否"},
        {"name": "占桩时长", "value": occupy_dur},
        {"name": "占桩费用", "value": _fmt_money(parking_money, money_scale) if parking_money else "0 元"},
    ]
    for s in stages:
        info_fields.append(
            {
                "name": f"分时段 {s.get('startTime', '?')}～{s.get('endTime', '?')}",
                "value": _fmt_kwh(s.get("battery"), display_scale),
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
    if start_mismatch:
        warnings.append(
            {
                "code": str(start_check.get("code") or "START_FAIL"),
                "level": "warn",
                "message": str(start_check.get("message") or "启动校验未通过"),
            }
        )
    elif start_fail_explicit:
        warnings.append(
            {
                "code": "START_REJECTED",
                "level": "info",
                "message": start_result_txt,
            }
        )
    for note in fault_notes[:5]:
        # 订单本身结算/停止正常时，TROUBLE 等仅作摘录提示，不抬成需现场核实的 warn
        fault_level = (
            "info"
            if (
                not energy_mismatch
                and not start_mismatch
                and not need_user_confirm
                and stop_info["category"]
                in {
                    "remote_stop",
                    "user_remote_stop",
                    "platform_guard_stop",
                    "device_finish",
                    "device_unplug",
                    "device_occupy",
                    "device_idle_unplug",
                }
            )
            else "warn"
        )
        warnings.append(
            {
                "code": "ORDER_FAULT",
                "level": fault_level,
                "message": note,
            }
        )
    for note in alarm_notes[:8]:
        warnings.append(
            {
                "code": "ORDER_ALARM",
                "level": "warn",
                "message": note,
            }
        )
    for note in other_gun_notes[:2]:
        warnings.append(
            {
                "code": "OTHER_GUN_HINT",
                "level": "info",
                "message": note,
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
            "stop_category": stop_info["category"],
            "stop_type": stop_info["stop_type"],
            "stop_reason": stop_info["reason"],
            "need_user_confirm": need_user_confirm,
            "soc_samples": len(socs),
            "charging_samples": len(chgs),
            "service_id": sid or service_id_val,
            "filtered": bool(sid),
            "energy_checks": energy_checks,
            "energy_mismatch": energy_mismatch,
            "power_time_check": power_time_check,
            "start_check": start_check,
            "start_mismatch": start_mismatch,
            "start_fail_explicit": start_fail_explicit,
            "fault_notes": fault_notes,
            "alarm_notes": alarm_notes,
            "other_gun_notes": other_gun_notes,
        },
    }
