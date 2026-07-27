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


def test_offline_then_trouble_is_offline_gun_fault_not_estop():
    """先离线、重连后才报 TROUBLE：判离线上报枪口故障，绝不能判急停。"""
    r = _analyze_stop(
        has_remote_stop=False,
        remote_stop_msg=None,
        finish_msg="结束代码 254",
        finish_code=254,
        gun_events=[
            ("t1", "1", "CHARGING"),
            ("t2", "1", "TROUBLE"),
            ("t3", "1", "TROUBLE"),
            ("t4", "1", "IDLE"),
        ],
        gun="1",
        offline_reconnect=True,
    )
    assert r["category"] == "offline_gun_fault"
    assert r["stop_type"] == "离线上报枪口故障"
    assert "急停" not in r["stop_type"]
    assert "非人工急停" in (r.get("tip") or "")


def test_offline_gun_fault_from_log_file_pattern():
    text = "\n".join(
        [
            '2026-07-25 04:52:17 [x] --chargingInfo:{"deviceNo":"P1","interfaceCode":1,"serviceId":"507","tradeNo":"T1","totalBattery":1000,"chargeMoney":100,"serviceMoney":0}',
            "2026-07-25 04:52:18 [x] 1枪:CHARGING",
            "2026-07-25 06:03:12 [x] exceptionCaught: null, io.netty.handler.timeout.ReadTimeoutException",
            "2026-07-25 06:06:12 [x] 设备离线 180 秒未重连，发送告警",
            "2026-07-25 06:15:04 [x] 设备登录 ip:1.2.3.4 桩:#1",
            "2026-07-25 06:15:14 [x] 1枪:TROUBLE",
            "2026-07-25 06:15:44 [x] 1枪:TROUBLE",
            "2026-07-25 06:16:03 [x] 1枪:IDLE",
            '2026-07-25 06:16:31 [x] --recordInfo:{"deviceNo":"P1","interfaceCode":1,"serviceId":"507","tradeNo":"T1","totalBattery":267131,"chargeMoney":104182,"serviceMoney":53426,"chargeDuration":5000,"deviceChargeFinishReasonCode":254}',
        ]
    )
    r = analyze_order_log(text, service_id="507")
    assert r["extras"]["stop_category"] == "offline_gun_fault"
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert fields["停止类型"] == "离线上报枪口故障"
    assert "急停" not in fields["停止类型"]
    assert "非人工急停" in (fields.get("停止提示") or "")
    assert "急停" not in (r.get("verdict") or "")

def test_offline_reconnect_beats_idle_unplug():
    """掉电/离线重连后常直接报 IDLE，不能误判为拔枪。"""
    r = _analyze_stop(
        has_remote_stop=False,
        remote_stop_msg=None,
        finish_msg="60非正常停止(掉电)",
        finish_code="60",
        gun_events=[
            ("t1", "2", "CHARGING"),
            ("t2", "2", "IDLE"),
        ],
        gun="2",
        offline_reconnect=True,
    )
    assert r["category"] == "offline_reconnect"
    assert "离线" in r["stop_type"]
    assert "掉电" in r["reason"]


def test_offline_finish_msg_without_flag():
    r = _analyze_stop(
        has_remote_stop=False,
        remote_stop_msg=None,
        finish_msg="60非正常停止(掉电)",
        finish_code="60",
        gun_events=[
            ("t1", "2", "CHARGING"),
            ("t2", "2", "IDLE"),
        ],
        gun="2",
    )
    assert r["category"] == "offline_reconnect"


def test_other_gun_trouble_not_this_order_fault():
    """同桩其他枪 TROUBLE 不应写成含糊的「异常相关记录」。"""
    text = "\n".join(
        [
            '2026-07-25 09:57:40 [x] --chargingInfo:{"deviceNo":"P1","interfaceCode":1,"serviceId":"507","tradeNo":"T1","totalBattery":1000,"chargeMoney":100,"serviceMoney":0}',
            "2026-07-25 09:58:00 [x] 1枪:CHARGING",
            "2026-07-25 10:00:00 [x] 1枪:IDLE",
            "2026-07-25 10:00:01 [x] 2枪:TROUBLE",
            '2026-07-25 10:00:02 [x] --recordInfo:{"deviceNo":"P1","interfaceCode":1,"serviceId":"507","tradeNo":"T1","totalBattery":1000,"chargeMoney":100,"serviceMoney":0,"chargeDuration":120,"deviceChargeFinishReasonCode":"1282","jianBattery":0,"fengBattery":0,"pingBattery":1000,"guBattery":0}',
        ]
    )
    r = analyze_order_log(text, service_id="507")
    assert "异常相关记录" not in (r.get("report_text") or "")
    assert r["extras"].get("fault_notes") == []
    assert any("2枪" in n and "非本单" in n for n in (r["extras"].get("other_gun_notes") or []))
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert fields.get("本单异常/告警摘录") == "无"


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


def test_precharge_trouble_then_charging_ignored():
    """开充前短暂 TROUBLE，随后正常 CHARGING，不应判急停/故障。"""
    from evcpa.order_report import _analyze_stop, _trouble_followed_by_charging

    events = [
        ("t0", "2", "READY_CHARGE"),
        ("t1", "2", "TROUBLE"),
        ("t2", "2", "CHARGING"),
        ("t3", "2", "CHARGING"),
        ("t4", "2", "IDLE"),
    ]
    assert _trouble_followed_by_charging(events, "2") is True
    stop = _analyze_stop(
        has_remote_stop=True,
        remote_stop_msg="用户停止",
        finish_msg="远程停止",
        finish_code=None,
        gun_events=events,
        gun="2",
    )
    assert stop["category"] == "remote_stop"

    # 无远程停止时：开充前 TROUBLE 已忽略，按拔枪/跳枪等后续状态判
    stop2 = _analyze_stop(
        has_remote_stop=False,
        remote_stop_msg=None,
        finish_msg="结束",
        finish_code=None,
        gun_events=events,
        gun="2",
    )
    assert stop2["category"] not in {"estop_suspect", "gun_fault"}


def test_post_unplug_trouble_not_this_order():
    """充电结束拔枪后，本枪后续 TROUBLE/故障不归属前一订单。"""
    text = "\n".join(
        [
            '2026-07-25 10:00:00 [x] --chargingInfo:{"deviceNo":"P1","interfaceCode":1,"serviceId":"507","tradeNo":"T1","totalBattery":1000,"chargeMoney":100,"serviceMoney":0}',
            "2026-07-25 10:00:01 [x] 1枪:CHARGING",
            "2026-07-25 10:05:00 [x] 1枪:IDLE",
            '2026-07-25 10:05:01 [x] --recordInfo:{"deviceNo":"P1","interfaceCode":1,"serviceId":"507","tradeNo":"T1","totalBattery":1000,"chargeMoney":100,"serviceMoney":0,"chargeDuration":300,"deviceChargeFinishReasonMsg":"用户拔枪","deviceChargeFinishReasonCode":1}',
            # 拔枪之后的新会话异常——与本单无关
            "2026-07-25 10:20:00 [x] 1枪:READY_CHARGE",
            "2026-07-25 10:20:05 [x] 1枪:TROUBLE",
            "2026-07-25 10:20:10 [x] 1枪:TROUBLE",
            "2026-07-25 10:20:15 [x] 1枪:TROUBLE",
            "2026-07-25 10:20:20 [x] 1枪:TROUBLE",
            "2026-07-25 10:20:25 [x] 1枪:TROUBLE",
            "2026-07-25 10:20:30 [x] 故障 1枪 绝缘异常",
        ]
    )
    r = analyze_order_log(text, service_id="507")
    assert r["extras"]["stop_category"] == "device_idle_unplug"
    assert r["extras"].get("fault_notes") == []
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert fields.get("本单异常/告警摘录") == "无"
    assert fields.get("停止类型") == "设备跳枪停止（直接拔枪）"


def test_analyze_stop_ignores_post_unplug_trouble():
    """_analyze_stop：拔枪后持续 TROUBLE 不得改判为枪口故障。"""
    r = _analyze_stop(
        has_remote_stop=False,
        remote_stop_msg=None,
        finish_msg="用户拔枪",
        finish_code=1,
        gun_events=[
            ("t1", "1", "CHARGING"),
            ("t2", "1", "IDLE"),
            ("t3", "1", "TROUBLE"),
            ("t4", "1", "TROUBLE"),
            ("t5", "1", "TROUBLE"),
            ("t6", "1", "TROUBLE"),
            ("t7", "1", "TROUBLE"),
        ],
        gun="1",
    )
    assert r["category"] == "device_idle_unplug"
