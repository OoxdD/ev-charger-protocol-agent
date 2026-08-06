"""卡号查询解析单测。"""

from __future__ import annotations

from pathlib import Path

from evcpa.card_query import (
    classify_by_fail_reason,
    classify_card,
    extract_card_auth_events,
    resolve_card_type,
    summarize_card_auth,
)

SAMPLE = """
2026-07-20 10:01:00.000 设备启充请求，{"cardNo":"00000000DDE4BF6B"}
2026-07-20 10:01:02.111 卡未注册，卡号: 00000000DDE4BF6B
2026-07-20 10:02:00.000 设备启充请求，{"cardNo":"3527460N0BC4ECXGL"}
2026-07-20 10:02:03.222 VIN卡账户余额不足，卡号: 3527460N0BC4ECXGL
2026-07-20 10:03:00.000 {"cardNo":"LZYTDGBW7H1021627"}
2026-07-20 10:03:04.333 作废卡，卡号: LZYTDGBW7H1021627
2026-07-20 10:04:05.000 创建卡充电服务信息成功 {"cardNo":"AABBCCDDEEFF0011"}
2026-07-20 10:06:09.000 cardNo=LFV2A21K8G3123456 刷卡启动成功
2026-07-20 10:07:00.000 设备启充请求，{"cardNo":"ONLY_REQUEST"}
"""

DESKTOP_SWIPE = Path(r"c:\Users\OXD\Desktop\刷卡.txt")


def test_classify_card():
    assert classify_card("000000003EC71C0D") == "刷卡"
    assert classify_card("3527460N0BC4ECXGL") == "VIN"
    assert classify_card("AABBCCDDEEFF0011") == "其他"


def test_cross_validate_by_fail_reason():
    assert classify_by_fail_reason("卡未注册") == "刷卡"
    assert classify_by_fail_reason("未注册") == "刷卡"
    assert classify_by_fail_reason("账户余额不足，卡号:000000003EC71C0D") == "刷卡"
    assert classify_by_fail_reason("VIN卡账户余额不足") == "VIN"
    assert classify_by_fail_reason("VIN卡未注册") == "VIN"
    assert resolve_card_type("00000000DDE4BF6B", "卡未注册，卡号: 00000000DDE4BF6B") == "刷卡"
    assert resolve_card_type("3527460N0BC4ECXGL", "VIN卡账户余额不足，卡号: 3527460N0BC4ECXGL") == "VIN"
    assert resolve_card_type("00000000VINFAKE1", "VIN卡未注册，卡号: 00000000VINFAKE1") == "VIN"


def test_fail_outputs_full_reason_sentence():
    events = extract_card_auth_events(SAMPLE)
    fails = {e["cardNo"]: e for e in events if not e["ok"]}
    assert fails["00000000DDE4BF6B"]["reason"] == "卡未注册，卡号: 00000000DDE4BF6B"
    assert fails["00000000DDE4BF6B"]["card_type"] == "刷卡"
    assert fails["3527460N0BC4ECXGL"]["reason"] == "VIN卡账户余额不足，卡号: 3527460N0BC4ECXGL"
    assert fails["3527460N0BC4ECXGL"]["card_type"] == "VIN"
    assert fails["LZYTDGBW7H1021627"]["reason"] == "作废卡，卡号: LZYTDGBW7H1021627"
    assert fails["LZYTDGBW7H1021627"]["card_type"] == "VIN"


def test_success_outputs_card_and_time():
    events = extract_card_auth_events(SAMPLE)
    oks = {e["cardNo"]: e for e in events if e["ok"]}
    assert "AABBCCDDEEFF0011" in oks
    assert oks["LFV2A21K8G3123456"]["card_type"] == "VIN"


def test_cardno_without_result_skipped():
    events = extract_card_auth_events(SAMPLE)
    assert "ONLY_REQUEST" not in {e["cardNo"] for e in events}


def test_desktop_swipe_full_reason():
    if not DESKTOP_SWIPE.is_file():
        return
    text = DESKTOP_SWIPE.read_text(encoding="utf-8")
    events = extract_card_auth_events(text)
    assert events
    ic = next(e for e in events if e["cardNo"] == "000000003EC71C0D")
    assert ic["card_type"] == "刷卡"
    assert ic["reason"] == "账户余额不足，卡号:000000003EC71C0D"


def test_summarize():
    s = summarize_card_auth(extract_card_auth_events(SAMPLE))
    assert s["failed"] == 3
    assert s["success"] == 2


def test_empty():
    assert extract_card_auth_events("") == []
