# -*- coding: utf-8 -*-
from evcpa.order_report import _extract_alarm_notes_from_line, analyze_order_log


def test_extract_alarm_code_content():
    ln = "2023-12-20 00:04:37.775 [x] [pile]告警上报，告警码：1  内容：BMS通讯异常"
    notes = _extract_alarm_notes_from_line(ln)
    assert notes
    assert "告警码 1" in notes[0]
    assert "BMS通讯异常" in notes[0]


def test_extract_alarm_dcode_pcode():
    ln = "2025-05-22 22:12:04.205 > 【p】 [p]告警上报：车辆连接异常 dCode:8 pCode:5009"
    notes = _extract_alarm_notes_from_line(ln)
    assert notes
    assert "车辆连接异常" in notes[0]
    assert "dCode=8" in notes[0]
    assert "pCode=5009" in notes[0]


def test_extract_alarmmsg_nonzero_bytes():
    ln = (
        '2024-12-09 01:00:00 [x] [pile]-----alarmmsg-----:{"alarmBytes":'
        '"00 00 00 00 00 00 00 20 00 00","alarmInfo":"x","interfaceCode":"1",'
        '"cmd":13,"deviceNo":"P1"}'
    )
    notes = _extract_alarm_notes_from_line(ln)
    assert notes
    assert "告警报文" in notes[0]
    assert "alarmBytes" in notes[0]


def test_ignore_zero_alarmmsg_and_offline_send_alarm():
    zero = (
        '2024-02-13 21:26:12 [x] [pile]-----alarmmsg-----:{"alarmBytes":'
        '"00 00 00 00","alarmInfo":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",'
        '"cmd":13,"deviceNo":"P1"}'
    )
    assert _extract_alarm_notes_from_line(zero) == []
    offline = "2026-07-22 14:55:47 [x] 设备离线 200 秒未重连，发送告警"
    assert _extract_alarm_notes_from_line(offline) == []


def test_ignore_weijing_raw_0d_hex_alarm_frame():
    ln = (
        "2026-07-16 00:05:05.726 > 【101】【上报 0D】 "
        "680D4C5214313031303030323032323030353137313230303700000E0160002607152013030000000000FCFA"
    )
    assert _extract_alarm_notes_from_line(ln) == []


def test_analyze_order_log_outputs_alarm_info():
    text = "\n".join(
        [
            '2026-07-15 20:13:51 [x] RemoteCmd>>>>>>>>:{"remoteCmd":"17","data":{"serviceId":"900","interfaceCode":"1"}}',
            "2026-07-15 20:14:00 [x] 1枪:CHARGING",
            '2026-07-15 20:14:10 [x] --chargingInfo:{"serviceId":900,"interfaceCode":"1","totalBattery":100,"chargeMoney":10}',
            '2026-07-15 20:14:20 [x] --socInfo:{"serviceId":900,"interfaceCode":"1","batteryChargerOutputCurrent":1000,"batteryChargerOutputVoltage":400000}',
            "2026-07-15 20:15:00 [x] 告警上报，告警码：34  内容：充电枪锁定异常",
            '2026-07-15 20:16:00 [x] --recordInfo:{"serviceId":900,"interfaceCode":"1","totalBattery":100,"chargeMoney":10,"deviceChargeFinishReasonMsg":"用户停止"}',
            "2026-07-15 20:16:01 [x] 1枪:IDLE",
        ]
    )
    r = analyze_order_log(text, service_id="900")
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert "充电枪锁定异常" in fields["告警信息"]
    assert any(w.get("code") == "ORDER_ALARM" for w in r.get("warnings") or [])
    assert r["extras"]["alarm_notes"]
    assert "告警信息：" in (r.get("report_text") or "")
