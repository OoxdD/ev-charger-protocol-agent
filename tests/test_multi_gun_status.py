from evcpa.order_report import (
    _charging_duration_from_gun_events,
    _parse_gun_statuses,
    analyze_order_log,
)


def test_parse_multi_gun_pipe_status():
    ln = "2026-07-15 20:14:33.731 > [101] 1枪:IDLE|2枪:CHARGING| nid:wj2n_s10_5002"
    assert _parse_gun_statuses(ln) == [("1", "IDLE"), ("2", "CHARGING")]


def test_parse_single_gun_status_still_works():
    assert _parse_gun_statuses("1枪：CHARGING") == [("1", "CHARGING")]
    assert _parse_gun_statuses("2枪:READY_CHARGE") == [("2", "READY_CHARGE")]
    # 星星等无冒号格式
    assert _parse_gun_statuses("1枪CHARGING") == [("1", "CHARGING")]
    assert _parse_gun_statuses("1枪OCCUPYING") == [("1", "OCCUPYING")]


def test_charging_duration_sums_charging_intervals_only():
    events = [
        ("2026-07-27 22:00:25.433", "1", "OCCUPYING"),
        ("2026-07-27 22:00:29.771", "1", "CHARGING"),
        ("2026-07-27 22:13:25.298", "1", "OCCUPYING"),
        ("2026-07-27 22:16:30.237", "1", "CHARGING"),
        ("2026-07-27 22:16:32.164", "1", "OCCUPYING"),
        ("2026-07-27 22:16:35.889", "1", "CHARGING"),
        ("2026-07-27 22:17:25.212", "1", "OCCUPYING"),
        ("2026-07-27 23:06:41.293", "1", "IDLE"),
    ]
    sec, first, last = _charging_duration_from_gun_events(events, "1")
    assert sec is not None
    # 775.527 + 1.927 + 49.323 ≈ 827
    assert 820 <= sec <= 835
    assert first and first.startswith("2026-07-27 22:00:29")
    assert last and last.startswith("2026-07-27 22:17:25")
    # 订单墙钟约 66 分钟，不应被误用
    assert sec < 30 * 60


def test_report_duration_uses_charging_not_order_wall_clock():
    text = "\n".join(
        [
            '2026-07-27 22:00:21 [x] >>>>>>>>RemoteCmd>>>>>>>>:{"remoteCmd":"17","data":{"serviceId":2607270934469961234,"interfaceCode":"1","tradeNo":"S2607270934469961234"}}',
            "2026-07-27 22:00:26 [x] 启动充电响应:成功",
            "2026-07-27 22:00:29 [x] 1枪CHARGING nid:x",
            '2026-07-27 22:05:00 [x] --chargingInfo:{"serviceId":2607270934469961234,"interfaceCode":"1","tradeNo":"S2607270934469961234","totalBattery":500,"chargeMoney":100}',
            "2026-07-27 22:13:25 [x] 1枪OCCUPYING nid:x",
            '2026-07-27 23:05:58 [x] --recordInfo:{"serviceId":2607270934469961234,"interfaceCode":"1","tradeNo":"S2607270934469961234","totalBattery":701,"chargeMoney":200,"startTime":"2026-07-27 22:00:21","endTime":"2026-07-27 23:05:58","chargeDuration":3937}',
            "2026-07-27 23:06:41 [x] 1枪IDLE nid:x",
        ]
    )
    r = analyze_order_log(text, service_id="2607270934469961234")
    fields = {f["name"]: f["value"] for f in r["fields"]}
    dur = fields.get("充电时长", "")
    # 22:00:29→22:13:25 ≈ 776 秒，约 13 分钟；不应是订单 66 分钟 / 3937 秒
    assert "3937" not in dur
    assert "约 13 分钟" in dur or "约 12 分钟" in dur or "约 14 分钟" in dur
    assert "776" in dur or "775" in dur or "777" in dur


def test_multi_gun_pipe_line_feeds_stop_analysis():
    text = "\n".join(
        [
            '2026-07-15 20:13:51 [x] >>>>>>>>RemoteCmd>>>>>>>>:{"remoteCmd":"17","data":{"serviceId":501967397,"interfaceCode":"2","tradeNo":"0000000501967397"}}',
            "2026-07-15 20:14:26 [x] 启动充电响应:成功",
            '2026-07-15 20:14:34 [x] --chargingInfo:{"serviceId":501967397,"interfaceCode":"2","tradeNo":"0000000501967397","totalBattery":20,"chargeMoney":15,"startTime":1784117631,"endTime":1784117674}',
            "2026-07-15 20:14:33 [x] 1枪:IDLE|2枪:CHARGING| nid:x",
            "2026-07-15 21:16:21 [x] >>>>>>>>RemoteCmd>>>>>>>>:"
            '{"remoteCmd":"18","data":{"serviceId":501967397,"interfaceCode":"2","stopReasonMsg":"平台主动停止"}}',
            "2026-07-15 21:16:33 [x] 1枪:IDLE|2枪:OCCUPYING| nid:x",
            '2026-07-15 21:16:40 [x] --recordInfo:{"serviceId":501967397,"interfaceCode":"2","tradeNo":"0000000501967397","totalBattery":28710,"chargeMoney":20000}',
        ]
    )
    r = analyze_order_log(text, service_id="501967397")
    assert r["mode"] == "charging_report"
    assert r["extras"]["has_remote_stop"] is True
    assert r["extras"]["stop_category"] == "user_remote_stop"
    start = r["extras"].get("start_check") or {}
    assert start.get("ok") is True or "CHARGING" in str(start)
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert "远程" in fields.get("启动方式", "")
    assert fields.get("停止类型") == "用户远程停止"