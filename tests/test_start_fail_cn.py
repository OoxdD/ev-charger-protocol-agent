# -*- coding: utf-8 -*-
from pathlib import Path

from evcpa.order_report import (
    _check_start_success,
    _extract_start_result_phrase,
    analyze_order_log,
)


def test_extract_start_fail_phrases():
    assert (
        _extract_start_result_phrase(
            "2026-07-16 06:56:50.834 > 【p】 [p]启动失败，2 枪不可用"
        )
        == "启动失败，2 枪不可用"
    )
    assert (
        _extract_start_result_phrase(
            "2026-05-28 11:38:58 [x] [p]启动失败，2 枪口未插枪"
        )
        == "启动失败，2 枪口未插枪"
    )
    assert (
        _extract_start_result_phrase(
            "2026-07-07 21:51:24 [x] [p]启动失败，枪为非插枪状态，serviceId:497090596"
        )
        == "启动失败，枪为非插枪状态"
    )


def test_start_fail_cn_message_used_directly():
    r = _check_start_success(
        start_ok=False,
        is_card_start=False,
        is_vin_start=False,
        is_remote_start=True,
        has_remote_cmd=True,
        gun_events=[
            ("2026-07-16 06:56:25", "2", "OCCUPYING"),
            ("2026-07-16 06:56:55", "2", "OCCUPYING"),
        ],
        gun="2",
        socs=[],
        chgs=[],
        start_result_msgs=["启动失败，2 枪不可用"],
    )
    assert r["ok"] is False
    assert r["message"] == "启动失败，2 枪不可用"
    assert r["start_result"] == "启动失败，2 枪不可用"
    assert any("OCCUPYING" in e for e in r["evidence"])


def test_this_order_occupying_start_fail():
    sample = Path(r"c:\Users\OXD\Downloads\10100020220051712007.txt")
    if not sample.exists() or sample.stat().st_size == 0:
        return
    text = sample.read_text(encoding="utf-8", errors="ignore")
    r = analyze_order_log(text, service_id="502185333")
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert fields["启动结果"] == "启动失败，2 枪不可用"
    assert fields["启动校验说明"] == "启动失败，2 枪不可用"
    assert fields["启动校验"] == "失败（明确）"
    assert r["extras"]["start_check"]["ok"] is False
    assert r["extras"].get("start_fail_explicit") is True
    assert r["extras"].get("start_mismatch") is False
    assert r["valid"] is True
    assert "无需复核" in (r.get("verdict") or "")
    assert "请复核" not in (r.get("verdict") or "")
    assert "OCCUPYING" in str(r["extras"]["start_check"].get("evidence") or [])
