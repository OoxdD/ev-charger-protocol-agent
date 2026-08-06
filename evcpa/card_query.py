"""从设备历史报文中提取刷卡 / VIN 卡号。

流程：
1. 先筛选报文中的 cardNo
2. 再判断该卡是否鉴权/启动成功
3. 成功 → 输出 cardNo + 刷卡时间
4. 失败 → 输出 cardNo + 报文失败整句（如：账户余额不足，卡号:000000003EC71C0D）

卡类型展示：刷卡 / VIN
- 一般以 000000 开头 → 刷卡
- 固定 17 位 → VIN
- 失败原因交叉验证（VIN… → VIN；卡未注册/未注册/作废卡/账户余额不足 → 刷卡）
"""

from __future__ import annotations

import json
import re
from typing import Any

_TS = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")

# 白名单用于识别失败行；输出时保留报文整句
_FAIL_REASONS = (
    "VIN卡账户余额不足",
    "VIN卡未注册",
    "账户余额不足",
    "卡未注册",
    "未注册",
    "作废卡",
)

_FAIL_CARD = re.compile(
    r"(?P<full>(?P<reason>"
    + "|".join(re.escape(x) for x in sorted(_FAIL_REASONS, key=len, reverse=True))
    + r")\s*[，,]\s*卡号\s*[：:]\s*(?P<card>[A-Za-z0-9]{4,32}))"
)

_CARD_NO_FIELD = re.compile(
    r'(?<![A-Za-z0-9_])["\']?cardNo["\']?\s*[:=]\s*["\']?(?P<card>[A-Za-z0-9]{4,32})["\']?',
    re.IGNORECASE,
)

_JSON_OBJ = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}")

_SUCCESS_LINE_HINTS = (
    "验证:通过",
    "验证：通过",
    "鉴权成功",
    "鉴权通过",
    "刷卡鉴权成功",
    "刷卡启动成功",
    "刷卡充电服务信息成功",
    "创建卡充电服务信息成功",
    "创建VIN码充电服务信息成功",
    "创建VIN充电服务信息成功",
    "VIN鉴权成功",
    "VIN验证启动成功",
)

_SKIP_LINE = ("切换卡号", "10进制", "16进制", "十六进制")


def _clean_card(raw: str | None) -> str | None:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s or len(s) < 4:
        return None
    if set(s) <= {"0", "f", "F"}:
        return None
    if s.lower() in {"ffffffffffffffff", "null", "none", "-"}:
        return None
    return s


def classify_card(card_no: str) -> str:
    """按卡号形态区分类型（展示用：刷卡 / VIN）。"""
    s = (card_no or "").strip()
    if s.startswith("000000"):
        return "刷卡"
    if len(s) == 17:
        return "VIN"
    return "其他"


def classify_by_fail_reason(reason: str | None) -> str | None:
    """按失败原因交叉验证卡类型。"""
    r = (reason or "").strip()
    if not r:
        return None
    # 整句或关键词
    head = r.split("，")[0].split(",")[0].strip()
    if head.startswith("VIN") or "VIN卡" in r:
        return "VIN"
    if any(
        head.startswith(x) or head == x
        for x in ("卡未注册", "未注册", "作废卡", "账户余额不足")
    ):
        return "刷卡"
    return None


def resolve_card_type(card_no: str, reason: str | None = None) -> str:
    """卡号形态 + 失败原因交叉得到最终类型（刷卡 / VIN）。"""
    by_no = classify_card(card_no)
    by_reason = classify_by_fail_reason(reason)
    if by_reason and by_no == by_reason:
        return by_no
    if by_reason == "VIN":
        return "VIN"
    if by_no == "刷卡":
        return "刷卡"
    if by_no == "VIN":
        return "VIN"
    if by_reason == "刷卡":
        return "刷卡"
    return by_no if by_no != "其他" else (by_reason or "其他")


def _pick_card_no_only(obj: Any) -> str | None:
    if not isinstance(obj, dict):
        return None
    candidates = [obj]
    data = obj.get("data")
    if isinstance(data, dict):
        candidates.append(data)
    for src in candidates:
        for key, val in src.items():
            if str(key).lower() == "cardno":
                card = _clean_card(val)
                if card:
                    return card
    return None


def _ts_key(ts: str) -> str:
    return (ts or "")[:19]


def _line_has_success(ln: str) -> bool:
    if "验证:不通过" in ln or "验证：不通过" in ln:
        return False
    if any(h in ln for h in _SUCCESS_LINE_HINTS):
        return True
    if re.search(r'["\']result["\']\s*:\s*1\b', ln):
        return True
    return False


def _line_cards(ln: str) -> list[str]:
    cards: list[str] = []
    seen: set[str] = set()
    for m in _CARD_NO_FIELD.finditer(ln):
        card = _clean_card(m.group("card"))
        if card and card not in seen:
            seen.add(card)
            cards.append(card)
    for jm in _JSON_OBJ.finditer(ln):
        try:
            obj = json.loads(jm.group(0))
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        card = _pick_card_no_only(obj)
        if card and card not in seen:
            seen.add(card)
            cards.append(card)
    return cards


def extract_card_auth_events(text: str) -> list[dict[str, Any]]:
    """先筛 cardNo，再判成功/失败并输出。"""
    if not text or not text.strip():
        return []

    first_time: dict[str, str] = {}
    success_time: dict[str, str] = {}
    # cardNo -> (失败整句, 时间)
    fail_info: dict[str, tuple[str, str]] = {}

    for ln in text.splitlines():
        if any(s in ln for s in _SKIP_LINE):
            continue
        ts_m = _TS.match(ln.strip())
        ts = ts_m.group(1) if ts_m else ""
        tkey = _ts_key(ts)

        cards = _line_cards(ln)
        for card in cards:
            if card not in first_time and tkey:
                first_time[card] = tkey

        for m in _FAIL_CARD.finditer(ln):
            full = (m.group("full") or "").strip()
            phrase_card = _clean_card(m.group("card"))
            if not full or not phrase_card:
                continue
            targets: list[str] = []
            if phrase_card in first_time or phrase_card in cards:
                targets.append(phrase_card)
            else:
                for c, ft in first_time.items():
                    if ft == tkey or c in cards:
                        targets.append(c)
                for c in cards:
                    if c not in targets:
                        targets.append(c)
            if not targets:
                targets = [phrase_card]
                if phrase_card not in first_time and tkey:
                    first_time[phrase_card] = tkey
            for card in targets:
                if card not in fail_info:
                    fail_info[card] = (full, tkey or first_time.get(card, ""))

        if _line_has_success(ln):
            for card in cards:
                if card not in success_time:
                    success_time[card] = tkey or first_time.get(card, "")

    events: list[dict[str, Any]] = []
    all_cards = set(first_time) | set(fail_info) | set(success_time)
    for card in all_cards:
        if card in fail_info:
            reason_full, fts = fail_info[card]
            card_type = resolve_card_type(card, reason_full)
            events.append(
                {
                    "time": fts or first_time.get(card, ""),
                    "start_type": card_type,
                    "card_type": card_type,
                    "ok": False,
                    "card_no": card,
                    "cardNo": card,
                    "reason": reason_full,
                    "swipe_time": None,
                    "source": "fail",
                    "display": f"失败，{reason_full}",
                }
            )
        elif card in success_time:
            st = success_time[card] or first_time.get(card, "")
            card_type = resolve_card_type(card)
            events.append(
                {
                    "time": st,
                    "start_type": card_type,
                    "card_type": card_type,
                    "ok": True,
                    "card_no": card,
                    "cardNo": card,
                    "reason": None,
                    "swipe_time": st,
                    "source": "success",
                    "display": f"成功，卡号: {card}，刷卡时间: {st}",
                }
            )

    events.sort(key=lambda e: (e.get("time") or "", 0 if e.get("ok") else 1, e.get("card_no") or ""))
    return events


def summarize_card_auth(events: list[dict[str, Any]]) -> dict[str, Any]:
    ok_n = sum(1 for e in events if e.get("ok"))
    fail_n = sum(1 for e in events if not e.get("ok"))
    swipe_n = sum(1 for e in events if e.get("card_type") in {"刷卡", "IC实体卡"} or e.get("start_type") in {"刷卡", "IC实体卡"})
    vin_n = sum(1 for e in events if e.get("card_type") in {"VIN", "VIN卡"} or e.get("start_type") in {"VIN", "VIN卡"})
    return {
        "total": len(events),
        "success": ok_n,
        "failed": fail_n,
        "card_start": swipe_n,
        "vin_start": vin_n,
        "ic_card": swipe_n,
        "vin_card": vin_n,
    }
