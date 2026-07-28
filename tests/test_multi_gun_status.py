from evcpa.order_report import _parse_gun_statuses, analyze_order_log


def test_parse_multi_gun_pipe_status():
    ln = "2026-07-15 20:14:33.731 > [101] 1枪:IDLE|2枪:CHARGING| nid:wj2n_s10_5002"
    assert _parse_gun_statuses(ln) == [("1", "IDLE"), ("2", "CHARGING")]


def test_parse_single_gun_status_still_works():
    assert _parse_gun_statuses("1枪：CHARGING") == [("1", "CHARGING")]
    assert _parse_gun_statuses("2枪:READY_CHARGE") == [("2", "READY_CHARGE")]


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