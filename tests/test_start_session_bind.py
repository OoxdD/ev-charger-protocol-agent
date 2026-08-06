"""启动结果须绑定本单枪口与会话时间窗。"""

from __future__ import annotations

from evcpa.order_report import (
    _filter_start_result_events,
    _start_phrase_gun,
    analyze_order_log,
)


def test_start_phrase_gun():
    assert _start_phrase_gun("启动失败，2 枪口未插枪") == "2"
    assert _start_phrase_gun("启动失败，2 枪不可用") == "2"
    assert _start_phrase_gun("启动失败，枪为非插枪状态") is None
    assert _start_phrase_gun("启动成功") is None


def test_filter_drops_other_gun_and_after_session():
    events = [
        ("2026-08-05 12:11:51", "远程启动充电响应，成功"),  # 无枪号，保留
        ("2026-08-05 12:40:30", "启动失败，2 枪口未插枪"),
        ("2026-08-05 12:40:47", "启动失败，2 枪口未插枪"),
    ]
    # 1 枪订单，会话在 12:37 结束：应丢掉 2 枪后续失败
    msgs = _filter_start_result_events(
        events,
        iface_gun="1",
        status_gun="1",
        session_start="2026-08-05 12:09:00",
        session_end="2026-08-05 12:37:53",
    )
    assert all("2 枪" not in m for m in msgs)
    assert "启动失败，2 枪口未插枪" not in msgs


def test_order_not_polluted_by_later_other_gun_start_fail():
    """1 枪正常充电结束后，2 枪后续启动失败不得判为本单启动失败。"""
    text = "\n".join(
        [
            "2026-08-05 12:11:10 [x] 1枪：CHARGING",
            '2026-08-05 12:11:10 [x] --socInfo:{"serviceId":514879788,"interfaceCode":"1","tradeNo":"T1","batteryChargerOutputCurrent":200000,"batteryChargerOutputVoltage":400000,"soc":26}',
            '2026-08-05 12:11:10 [x] --chargingInfo:{"serviceId":514879788,"interfaceCode":"1","tradeNo":"T1","totalBattery":1500,"chargeMoney":600,"startTime":1785902968,"endTime":1785903070}',
            "2026-08-05 12:37:44 [x] 1枪：OCCUPYING",
            '2026-08-05 12:37:52 [x] --recordInfo:{"serviceId":514879788,"interfaceCode":"1","tradeNo":"T1","totalBattery":35446,"chargeMoney":14841,"startTime":1785902968,"endTime":1785904662,"deviceChargeFinishReasonMsg":"结束充电，APP远程停止","isChargeFinish":1}',
            "2026-08-05 12:37:53 [x] 1枪：IDLE",
            "2026-08-05 12:38:28 [x] 2枪：IDLE",
            '2026-08-05 12:40:30 [x] >>>>>>>>RemoteCmd>>>>>>>>:{"remoteCmd":"17","interfaceCode":"2","data":{"serviceId":514903369,"interfaceCode":"2"}}',
            "2026-08-05 12:40:30 [x] 启动失败，2 枪口未插枪",
        ]
    )
    r = analyze_order_log(text, service_id="514879788")
    fields = {f["name"]: f["value"] for f in r.get("fields", [])}
    assert "启动失败" not in str(fields.get("启动结果") or "")
    assert "启动失败" not in (r.get("verdict") or "")
    assert "2 枪口未插枪" not in (r.get("summary") or "")
    assert float(str(fields.get("实际充电电量") or "0").split()[0]) > 30
