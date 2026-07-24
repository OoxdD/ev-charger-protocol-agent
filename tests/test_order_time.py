# -*- coding: utf-8 -*-
from evcpa.order_report import analyze_order_log

# 无枪状态、无 chargeDuration、仅有 unix 起止时间
TEXT_UNIX = """
2026-07-22 11:56:34 [x] INFO - RemoteCmd>>>>>>>>:{"remoteCmd":17,"deviceNo":"P1","interfaceCode":1,"data":{"serviceId":"506046347","memberMobile":"138"}}
2026-07-22 11:56:35 [x] INFO - 远程启动充电响应，成功
2026-07-22 12:01:47 [x] INFO - --recordInfo:{"deviceNo":"P1","interfaceCode":1,"serviceId":"506046347","tradeNo":"0000000506046347","totalBattery":1382,"chargeMoney":1451,"serviceMoney":552,"startTime":1784692594,"endTime":1784692907,"chargeStartMeterBattery":2323205,"chargeEndMeterBattery":2324587,"deviceChargeFinishReasonMsg":"充满停止"}
"""

# 仅有账单 BCD 时间、无 duration
TEXT_BILL = """
2026-07-22 11:56:34 [x] INFO - RemoteCmd>>>>>>>>:{"remoteCmd":17,"deviceNo":"P1","interfaceCode":1,"data":{"serviceId":"1","memberMobile":"138"}}
2026-07-22 11:56:35 [x] INFO - 远程启动充电响应，成功
2026-07-22 12:01:47 [x] INFO - 上报账单[cmd=0x8]:{"accuracyFlag":4,"deviceNo":"P1","interfaceCode":1,"serviceId":"1","tradeNo":"0000000506046347","totalBattery":13820,"pingBattery":13820,"jianBattery":0,"fengBattery":0,"guBattery":0,"chargeMoney":14511,"serviceMoney":5528,"startTime":"260722115634","endTime":"260722120147","startMeterBattery":23232050,"endMeterBattery":23245870,"deviceChargeFinishReasonMsg":"充满停止"}
"""


def test_unix_times_without_gun_or_duration():
    r = analyze_order_log(TEXT_UNIX)
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert fields["启动时间"] != "-", fields
    assert fields["结束时间"] != "-", fields
    assert fields["充电时长"] != "-", fields


def test_bill_bcd_times_compute_duration():
    r = analyze_order_log(TEXT_BILL)
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert "2026" in fields["启动时间"]
    assert "11:56:34" in fields["启动时间"] or "11时" in fields["启动时间"]
    assert fields["充电时长"] != "-"
    assert "313" in fields["充电时长"] or "5 分钟" in fields["充电时长"]
