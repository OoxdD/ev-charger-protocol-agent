# -*- coding: utf-8 -*-
from pathlib import Path

from evcpa.order_report import (
    _check_start_success,
    _extract_remote_start_result_phrase,
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


def test_extract_remote_start_result_timeout():
    ln = "2026-07-30 02:32:35.109 > 【9920260309121703】 【MsgHandler】远程启动结果返回 code:9 msg:充电启动超时"
    assert _extract_remote_start_result_phrase(ln) == "启动失败，充电启动超时"
    assert _extract_start_result_phrase(ln) == "启动失败，充电启动超时"


def test_remote_start_timeout_explicit_fail():
    """远程启动结果返回超时 → 明确启动失败，无需复核。"""
    text = "\n".join(
        [
            '2026-07-30 02:31:12 [x] RemoteCmd>>>>>>>>:{"remoteCmd":"17","deviceNo":"P1","interfaceCode":"2","data":{"serviceId":510855428,"interfaceCode":"2"}}',
            "2026-07-30 02:31:13 [x] 2枪:READY_CHARGE",
            "2026-07-30 02:31:45 [x] 2枪:CHARGING",
            "2026-07-30 02:32:25 [x] 2枪:OCCUPYING",
            "2026-07-30 02:32:30 [x] 2枪:IDLE",
            "2026-07-30 02:32:35 [x] 【MsgHandler】远程启动结果返回 code:9 msg:充电启动超时",
            '2026-07-30 02:32:38 [x] --recordInfo:{"serviceId":510855428,"interfaceCode":"2","tradeNo":"T510855428","totalBattery":0,"chargeMoney":0,"deviceChargeFinishReasonMsg":"断开连接","deviceChargeFinishReasonCode":"101000"}',
        ]
    )
    r = analyze_order_log(text, service_id="510855428")
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert fields["启动结果"] == "启动失败，充电启动超时"
    assert fields["启动校验"] == "失败（明确）"
    assert fields["启动校验说明"] == "启动失败，充电启动超时"
    assert r["extras"].get("start_fail_explicit") is True
    assert r["valid"] is True
    assert "启动失败，充电启动超时" in (r.get("verdict") or "")
    assert "无需复核" in (r.get("verdict") or "")
    assert any("启动失败，充电启动超时" in p for p in (r.get("result_points") or []))


def test_auto_focus_single_remote_start_among_multi():
    """同桩另一枪过程上报造成假多单时，自动锁定唯一远程启动单。"""
    text = "\n".join(
        [
            '>>>>>>>>RemoteCmd>>>>>>>>:{"remoteCmd":"17","deviceNo":"P1","interfaceCode":"2","data":{"serviceId":510855428}}',
            '--chargingInfo:{"deviceNo":"P1","interfaceCode":"1","serviceId":510745176,"tradeNo":"T1","totalBattery":32060,"chargeMoney":12434}',
            '【MsgHandler】远程启动结果返回 code:9 msg:充电启动超时',
            '--recordInfo:{"deviceNo":"P1","interfaceCode":"2","serviceId":510855428,"tradeNo":"T2","totalBattery":0,"chargeMoney":0,"deviceChargeFinishReasonMsg":"断开连接"}',
        ]
    )
    r = analyze_order_log(text)
    assert r.get("mode") != "multi_order_choice"
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert "510855428" in str(fields.get("服务ID", ""))
    assert fields["启动结果"] == "启动失败，充电启动超时"


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
