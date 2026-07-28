# -*- coding: utf-8 -*-
from evcpa.order_report import analyze_order_log


def test_require_current_voltage_in_order_fields():
    text = "\n".join(
        [
            '2026-07-15 20:13:51 [x] RemoteCmd>>>>>>>>:{"remoteCmd":"17","data":{"serviceId":"910","interfaceCode":"1"}}',
            "2026-07-15 20:14:00 [x] 1枪:CHARGING",
            '2026-07-15 20:14:10 [x] --socInfo:{"serviceId":910,"interfaceCode":"1","batteryChargerOutputCurrent":100000,"batteryChargerOutputVoltage":400000,"requireCurrent":111200,"requireVoltage":342800}',
            '2026-07-15 20:14:20 [x] --socInfo:{"serviceId":910,"interfaceCode":"1","batteryChargerOutputCurrent":105000,"batteryChargerOutputVoltage":405000,"requireCurrent":120000,"requireVoltage":350000}',
            '2026-07-15 20:14:30 [x] --chargingInfo:{"serviceId":910,"interfaceCode":"1","totalBattery":200,"chargeMoney":15}',
            '2026-07-15 20:15:00 [x] --recordInfo:{"serviceId":910,"interfaceCode":"1","totalBattery":200,"chargeMoney":15}',
            "2026-07-15 20:15:01 [x] 1枪:IDLE",
        ]
    )
    r = analyze_order_log(text, service_id="910")
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert "需求电流（平均）" in fields
    assert "需求电压（平均）" in fields
    assert fields["需求电流（平均）"] != "-"
    assert fields["需求电压（平均）"] != "-"
    assert "111.20" in fields["需求电流（范围）"] or "120.00" in fields["需求电流（范围）"]
    assert "342.8" in fields["需求电压（范围）"] or "350.0" in fields["需求电压（范围）"]
    assert "requireCurrent" in (r.get("report_text") or "") or "需求电流" in (r.get("report_text") or "")
