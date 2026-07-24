# -*- coding: utf-8 -*-
from evcpa.order_report import _analyze_stop, analyze_order_log


def test_remote_stop_cmd18_uses_stop_reason_msg():
    text = "\n".join(
        [
            '2026-07-22 11:56:32 [x] INFO - RemoteCmd>>>>>>>>:{"remoteCmd":"17","deviceNo":"P1","interfaceCode":"1","data":{"serviceId":"100"}}',
            "2026-07-22 11:56:33 [x] INFO - 远程启动充电响应，成功",
            "2026-07-22 11:56:34 [x] INFO - 1枪:CHARGING",
            '2026-07-22 12:01:44 [x] INFO - RemoteCmd>>>>>>>>:{"remoteCmd":"18","deviceNo":"P1","interfaceCode":"1","data":{"serviceId":"100","stopReasonMsg":"用户APP结束充电"}}',
            '2026-07-22 12:01:47 [x] INFO - --recordInfo:{"deviceNo":"P1","interfaceCode":1,"serviceId":"100","tradeNo":"1","totalBattery":1000,"chargeMoney":100,"serviceMoney":0,"chargeDuration":300,"deviceChargeFinishReasonMsg":"远程停止","deviceChargeFinishReasonCode":6}',
            "2026-07-22 12:01:50 [x] INFO - 1枪:READY_CHARGE",
        ]
    )
    r = analyze_order_log(text, service_id="100")
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert r["extras"]["has_remote_stop"] is True
    assert r["extras"]["stop_category"] == "remote_stop"
    assert fields["停止类型"] == "平台远程停止"
    assert "用户APP结束充电" in fields["停止原因"]
    assert "用户APP结束充电" in fields["平台停止原因"]
    assert "remoteCmd=18" not in fields["是否有远程停止指令"]
    assert any("平台下发远程停止，" in p and "remoteCmd" not in p for p in r["result_points"])


def test_device_unplug_ready_charge():
    text = "\n".join(
        [
            '2026-07-22 11:56:32 [x] INFO - RemoteCmd>>>>>>>>:{"remoteCmd":"17","deviceNo":"P1","interfaceCode":"1","data":{"serviceId":"100"}}',
            "2026-07-22 11:56:33 [x] INFO - 远程启动充电响应，成功",
            "2026-07-22 11:56:34 [x] INFO - 1枪:CHARGING",
            "2026-07-22 12:00:00 [x] INFO - 1枪:READY_CHARGE",
            '2026-07-22 12:00:01 [x] INFO - --recordInfo:{"deviceNo":"P1","interfaceCode":1,"serviceId":"100","tradeNo":"1","totalBattery":1000,"chargeMoney":100,"serviceMoney":0,"chargeDuration":200,"deviceChargeFinishReasonMsg":"枪断开","deviceChargeFinishReasonCode":1}',
        ]
    )
    r = analyze_order_log(text, service_id="100")
    assert r["extras"]["has_remote_stop"] is False
    assert r["extras"]["stop_category"] == "device_unplug"
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert "跳枪" in fields["停止类型"]
    assert fields["设备结束原因"] == "枪断开"


def test_idle_unplug_and_estop_suspect():
    idle = _analyze_stop(
        has_remote_stop=False,
        remote_stop_msg=None,
        finish_msg="未知",
        finish_code=None,
        gun_events=[
            ("t1", "1", "CHARGING"),
            ("t2", "1", "IDLE"),
        ],
        gun="1",
    )
    assert idle["category"] == "device_idle_unplug"

    estop = _analyze_stop(
        has_remote_stop=False,
        remote_stop_msg=None,
        finish_msg="急停",
        finish_code=None,
        gun_events=[
            ("t1", "1", "CHARGING"),
            ("t2", "1", "TROUBLE"),
            ("t3", "1", "READY_CHARGE"),
        ],
        gun="1",
    )
    assert estop["category"] == "estop_suspect"
    assert "急停" in estop["tip"]

    fault = _analyze_stop(
        has_remote_stop=False,
        remote_stop_msg=None,
        finish_msg="设备故障",
        finish_code=None,
        gun_events=[
            ("t1", "1", "CHARGING"),
            ("t2", "1", "TROUBLE"),
            ("t3", "1", "TROUBLE"),
            ("t4", "1", "TROUBLE"),
            ("t5", "1", "TROUBLE"),
            ("t6", "1", "TROUBLE"),
        ],
        gun="1",
    )
    assert fault["category"] == "gun_fault"
