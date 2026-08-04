# -*- coding: utf-8 -*-
"""充电过程短时离线重连判定。"""

from __future__ import annotations

from evcpa.order_report import _classify_mid_charge_offline, analyze_order_log


def test_classify_brief_offline_reconnect_benign():
    events = [
        ("2026-08-01 10:00:00", "down"),
        ("2026-08-01 10:01:20", "up"),
    ]
    chgs = [
        {"uploadTime": 1780000000, "totalBattery": 10000, "chargeMoney": 5000},  # placeholder
    ]
    # Use ISO via _parse_log_time path: feed string times through synthetic unix
    # Prefer direct ISO-like via endTime strings in helper by using uploadTime as parsed —
    # helper uses _parse_log_time; use 14-digit style via createTime strings instead.
    chgs = [
        {
            "endTime": "2026-08-01 09:59:50",
            "uploadTime": "2026-08-01 09:59:50",
            "totalBattery": 10000,
            "chargeMoney": 5000,
        },
        {
            "endTime": "2026-08-01 10:01:30",
            "uploadTime": "2026-08-01 10:01:30",
            "totalBattery": 10500,
            "chargeMoney": 5200,
        },
    ]
    r = _classify_mid_charge_offline(
        offline_events=events,
        chgs=chgs,
        charge_start_ts="2026-08-01 09:50:00",
        charge_end_ts="2026-08-01 10:30:00",
        scale=1000,
    )
    assert r["relevant"] is True
    assert r["benign"] is True
    assert r["gap_sec"] == 80
    assert "属正常" in (r["message"] or "")


def test_classify_long_offline_not_benign():
    events = [
        ("2026-08-01 10:00:00", "down"),
        ("2026-08-01 10:05:00", "up"),
    ]
    chgs = [
        {
            "uploadTime": "2026-08-01 09:59:50",
            "totalBattery": 10000,
            "chargeMoney": 5000,
        },
        {
            "uploadTime": "2026-08-01 10:05:10",
            "totalBattery": 10500,
            "chargeMoney": 5200,
        },
    ]
    r = _classify_mid_charge_offline(
        offline_events=events,
        chgs=chgs,
        charge_start_ts="2026-08-01 09:50:00",
        charge_end_ts="2026-08-01 10:30:00",
    )
    assert r["relevant"] is True
    assert r["benign"] is False
    assert r["gap_sec"] == 300


def test_classify_energy_jump_not_benign():
    events = [
        ("2026-08-01 10:00:00", "down"),
        ("2026-08-01 10:01:00", "up"),
    ]
    chgs = [
        {
            "uploadTime": "2026-08-01 09:59:50",
            "totalBattery": 10000,
            "chargeMoney": 5000,
        },
        {
            "uploadTime": "2026-08-01 10:01:10",
            "totalBattery": 20000,  # +10 kWh in 1 min → 差距过大
            "chargeMoney": 10000,
        },
    ]
    r = _classify_mid_charge_offline(
        offline_events=events,
        chgs=chgs,
        charge_start_ts="2026-08-01 09:50:00",
        charge_end_ts="2026-08-01 10:30:00",
    )
    assert r["relevant"] is True
    assert r["benign"] is False


def test_analyze_order_brief_offline_is_normal():
    text = "\n".join(
        [
            '2026-08-01 09:50:00 [x] RemoteCmd>>>>>>>>:{"remoteCmd":"17","deviceNo":"P1","interfaceCode":"1","data":{"serviceId":9001,"interfaceCode":"1"}}',
            "2026-08-01 09:50:01 [x] 远程启动充电响应，成功",
            "2026-08-01 09:50:05 [x] 1枪:CHARGING",
            '2026-08-01 09:59:50 [x] --chargingInfo:{"serviceId":9001,"interfaceCode":"1","tradeNo":"T9001","totalBattery":10000,"chargeMoney":5000,"uploadTime":"2026-08-01 09:59:50"}',
            "2026-08-01 10:00:00 [x] 设备离线",
            "2026-08-01 10:01:20 [x] 设备重复登录",
            "2026-08-01 10:01:20 [x] 恢复上线",
            '2026-08-01 10:01:30 [x] --chargingInfo:{"serviceId":9001,"interfaceCode":"1","tradeNo":"T9001","totalBattery":10500,"chargeMoney":5200,"uploadTime":"2026-08-01 10:01:30"}',
            "2026-08-01 10:20:00 [x] 1枪:IDLE",
            '2026-08-01 10:20:01 [x] --recordInfo:{"serviceId":9001,"interfaceCode":"1","tradeNo":"T9001","totalBattery":10500,"chargeMoney":5200,"deviceChargeFinishReasonMsg":"用户停止","deviceChargeFinishReasonCode":1}',
        ]
    )
    r = analyze_order_log(text, service_id="9001")
    assert r["extras"]["offline_benign"] is True
    assert r["extras"]["offline_alarm"] is False
    assert r["valid"] is True
    assert "属正常" in (r["extras"].get("offline_note") or "")
    assert "需到设备上核实充电数据后再确认" not in (r.get("verdict") or "")
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert "属正常" in str(fields.get("过程离线"))


def test_analyze_order_long_offline_still_alarms():
    text = "\n".join(
        [
            '2026-08-01 09:50:00 [x] RemoteCmd>>>>>>>>:{"remoteCmd":"17","deviceNo":"P1","interfaceCode":"1","data":{"serviceId":9002,"interfaceCode":"1"}}',
            "2026-08-01 09:50:01 [x] 远程启动充电响应，成功",
            "2026-08-01 09:50:05 [x] 1枪:CHARGING",
            '2026-08-01 09:59:50 [x] --chargingInfo:{"serviceId":9002,"interfaceCode":"1","tradeNo":"T9002","totalBattery":10000,"chargeMoney":5000,"uploadTime":"2026-08-01 09:59:50"}',
            "2026-08-01 10:00:00 [x] 设备离线",
            "2026-08-01 10:08:00 [x] 设备重复登录",
            '2026-08-01 10:08:10 [x] --chargingInfo:{"serviceId":9002,"interfaceCode":"1","tradeNo":"T9002","totalBattery":10500,"chargeMoney":5200,"uploadTime":"2026-08-01 10:08:10"}',
            "2026-08-01 10:20:00 [x] 1枪:IDLE",
            '2026-08-01 10:20:01 [x] --recordInfo:{"serviceId":9002,"interfaceCode":"1","tradeNo":"T9002","totalBattery":10500,"chargeMoney":5200,"deviceChargeFinishReasonMsg":"用户停止","deviceChargeFinishReasonCode":1}',
        ]
    )
    r = analyze_order_log(text, service_id="9002")
    assert r["extras"]["offline_benign"] is False
    assert r["extras"]["offline_alarm"] is True
    assert r["valid"] is False
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert "需复核" in str(fields.get("过程离线"))
    assert r["extras"]["offline_info"]["gap_sec"] == 480