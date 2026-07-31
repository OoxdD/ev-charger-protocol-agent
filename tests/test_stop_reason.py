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


def test_remote_stop_without_reason_is_user_remote_stop():
    """远程停止无具体 stopReasonMsg → 一般判定为用户远程停止。"""
    text = "\n".join(
        [
            '2026-07-15 20:13:51 [x] RemoteCmd>>>>>>>>:{"remoteCmd":"17","deviceNo":"P1","interfaceCode":"2","data":{"serviceId":"501","tradeNo":"T1"}}',
            "2026-07-15 20:14:26 [x] 启动充电响应:成功",
            "2026-07-15 20:14:33 [x] 1枪:IDLE|2枪:CHARGING| nid:x",
            '2026-07-15 20:14:34 [x] --chargingInfo:{"serviceId":501,"interfaceCode":"2","tradeNo":"T1","totalBattery":20,"chargeMoney":15}',
            '2026-07-15 21:16:21 [x] RemoteCmd>>>>>>>>:{"remoteCmd":"18","deviceNo":"P1","interfaceCode":"2","data":{"serviceId":501,"interfaceCode":"2"}}',
            "2026-07-15 21:16:33 [x] 1枪:IDLE|2枪:OCCUPYING| nid:x",
            '2026-07-15 21:16:40 [x] --recordInfo:{"serviceId":501,"interfaceCode":"2","tradeNo":"T1","totalBattery":28710,"chargeMoney":20000,"deviceChargeFinishReasonMsg":"平台主动停止","deviceChargeFinishReasonCode":47}',
        ]
    )
    r = analyze_order_log(text, service_id="501")
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert r["extras"]["has_remote_stop"] is True
    assert r["extras"]["stop_category"] == "user_remote_stop"
    assert fields["停止类型"] == "用户远程停止"
    assert "用户远程停止" in fields["停止原因"]
    assert fields["平台停止原因"] == "-"
    assert fields["设备结束原因"] == "平台主动停止"
    assert any("用户远程停止" in p for p in r["result_points"])
    assert r["extras"]["stop_reason"] == fields["停止原因"]


def test_power_nonzero_energy_zero_platform_guard_stop():
    """有功率但电量为0，平台写出中文异常并下发停止 → 直接输出该异常原因。"""
    text = "\n".join(
        [
            '2026-07-30 18:28:43 [x] RemoteCmd>>>>>>>>:{"remoteCmd":"17","deviceNo":"P1","interfaceCode":"1","data":{"serviceId":"511","interfaceCode":"1"}}',
            "2026-07-30 18:28:44 [x] 远程启动充电响应，成功",
            "2026-07-30 18:28:45 [x] 1枪:CHARGING",
            '2026-07-30 18:29:29 [x] --socInfo:{"serviceId":511,"interfaceCode":"1","batteryChargerOutPower":39872,"batteryChargerOutputCurrent":101200,"batteryChargerOutputVoltage":394500,"tradeNo":"T1"}',
            '2026-07-30 18:29:29 [x] --chargingInfo:{"serviceId":511,"interfaceCode":"1","tradeNo":"T1","totalBattery":0,"chargeMoney":0}',
            "2026-07-30 18:31:14 [x] 设备充电功率不为零，电量为0，停止充电，511",
            '2026-07-30 18:31:16 [x] RemoteCmd>>>>>>>>:{"remoteCmd":"18","deviceNo":"P1","interfaceCode":"1","data":{"serviceId":511,"interfaceCode":"1","chargeFinishReason":99}}',
            "2026-07-30 18:31:16 [x] 远程停止充电响应，成功",
            '2026-07-30 18:31:20 [x] --recordInfo:{"serviceId":511,"interfaceCode":"1","tradeNo":"T1","totalBattery":0,"chargeMoney":0,"deviceChargeFinishReasonMsg":"结束充电，APP远程停止","deviceChargeFinishReasonCode":6}',
            "2026-07-30 18:31:21 [x] 1枪:IDLE",
        ]
    )
    r = analyze_order_log(text, service_id="511")
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert r["extras"]["stop_category"] == "platform_guard_stop"
    assert fields["停止类型"] == "平台停止"
    assert fields["停止原因"] == "设备充电功率不为零，电量为0，停止充电"
    assert "设备充电功率不为零，电量为0，停止充电" in fields["平台停止原因"]
    assert "用户远程停止" not in fields["停止类型"]
    assert "设备充电功率不为零，电量为0，停止充电" in (r.get("verdict") or "")


def test_energy_increment_zero_platform_guard_stop():
    """盛弘 JSON：电量增量一直为0，平台写出原因并下发停止 → 直接输出该文案。"""
    text = "\n".join(
        [
            '2026-07-28 08:28:33 [x] RemoteCmd>>>>>>>>:{"remoteCmd":"17","deviceNo":"4402202404140015","interfaceCode":"1","data":{"serviceId":509738145,"interfaceCode":"1"}}',
            "2026-07-28 08:28:34 [x] 远程启动充电响应，成功",
            "2026-07-28 08:28:35 [x] 1枪:CHARGING",
            '2026-07-28 10:12:27 [x] 设备充电电量增量为0，serviceId:509738145  连续次数:2',
            "2026-07-28 10:15:28 [x] 设备充电电量增量一直为0，停止充电，509738145",
            '2026-07-28 10:15:29 [x] RemoteCmd>>>>>>>>:{"remoteCmd":"18","deviceNo":"4402202404140015","interfaceCode":"1","data":{"serviceId":509738145,"interfaceCode":"1"}}',
            "2026-07-28 10:15:29 [x] 远程停止充电响应，成功",
            '2026-07-28 10:15:40 [x] --recordInfo:{"serviceId":509738145,"interfaceCode":"1","tradeNo":"T1","totalBattery":2125,"chargeMoney":2125,"deviceChargeFinishReasonMsg":"后台停止","deviceChargeFinishReasonCode":311}',
            "2026-07-28 10:15:41 [x] 1枪:IDLE",
        ]
    )
    r = analyze_order_log(text, service_id="509738145")
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert r["extras"]["stop_category"] == "platform_guard_stop"
    assert fields["停止类型"] == "平台停止"
    assert fields["停止原因"] == "设备充电电量增量一直为0，停止充电"
    assert fields["平台停止原因"] == "设备充电电量增量一直为0，停止充电"
    assert "用户远程停止" not in fields["停止类型"]
    assert "设备充电电量增量一直为0，停止充电" in (r.get("verdict") or "")


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
    assert "无告警" in estop["tip"] or "无告警" in estop["evidence"]

    # 短暂 TROUBLE + 有告警 → 真实枪口故障，非急停
    fault_with_alarm = _analyze_stop(
        has_remote_stop=False,
        remote_stop_msg=None,
        finish_msg="设备故障",
        finish_code=None,
        gun_events=[
            ("t1", "1", "CHARGING"),
            ("t2", "1", "TROUBLE"),
            ("t3", "1", "READY_CHARGE"),
        ],
        gun="1",
        alarm_notes=["2026-07-25 10:00:00　告警码 34：充电枪锁定异常"],
    )
    assert fault_with_alarm["category"] == "gun_fault"
    assert "急停" not in fault_with_alarm["stop_type"]
    assert "告警" in fault_with_alarm["tip"]
    assert "设备方" in fault_with_alarm["tip"]

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


def test_brief_trouble_with_alarm_in_order_log_is_gun_fault_not_estop():
    text = "\n".join(
        [
            '2026-07-25 10:00:00 [x] --chargingInfo:{"serviceId":"801","interfaceCode":1,"totalBattery":500,"chargeMoney":10}',
            "2026-07-25 10:00:01 [x] 1枪:CHARGING",
            '2026-07-25 10:01:00 [x] --socInfo:{"serviceId":"801","interfaceCode":1,"batteryChargerOutputCurrent":1000,"batteryChargerOutputVoltage":400000}',
            "2026-07-25 10:05:00 [x] 告警上报，告警码：34  内容：充电枪锁定异常",
            "2026-07-25 10:05:01 [x] 1枪:TROUBLE",
            "2026-07-25 10:05:10 [x] 1枪:READY_CHARGE",
            '2026-07-25 10:05:20 [x] --recordInfo:{"serviceId":"801","interfaceCode":1,"totalBattery":500,"chargeMoney":10,"deviceChargeFinishReasonMsg":"故障停止"}',
        ]
    )
    r = analyze_order_log(text, service_id="801")
    assert r["extras"]["stop_category"] == "gun_fault"
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert fields["停止类型"] == "枪口故障停止"
    assert "急停" not in fields["停止类型"]
    assert "充电枪锁定异常" in fields["告警信息"]
    assert "设备方" in (fields.get("停止提示") or "")


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
    assert fields.get("停止类型") == "设备跳枪停止"


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
