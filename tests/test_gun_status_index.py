"""interfaceCode 与状态行「N枪」0/1 起始对齐。"""

from __future__ import annotations

from evcpa.order_report import (
    _collect_status_gun_ids,
    _iface_to_status_gun,
    analyze_order_log,
)


def test_iface_to_status_gun_zero_based():
    status = {"0", "1"}
    assert _iface_to_status_gun("1", status) == "0"
    assert _iface_to_status_gun("2", status) == "1"
    assert _iface_to_status_gun("1", set()) == "1"


def test_iface_to_status_gun_one_based():
    status = {"1", "2"}
    assert _iface_to_status_gun("1", status) == "1"
    assert _iface_to_status_gun("2", status) == "2"


def test_collect_status_gun_ids():
    lines = [
        "2026-08-04 11:53:50 [x] 0枪：CHARGING-0003",
        "2026-08-04 11:53:50 [x] 1枪：CHARGING-0003",
    ]
    assert _collect_status_gun_ids(lines) == {"0", "1"}


def test_zero_based_gun_duration_not_stolen_by_other_gun():
    """interfaceCode=1 对应 0枪；不可误用 1枪（他枪）的短 CHARGING 段。"""
    text = "\n".join(
        [
            "2026-08-04 11:53:00.000 [p] 0枪：READY_CHARGE-0006",
            "2026-08-04 11:53:50.000 [p] 0枪：CHARGING-0003",
            "2026-08-04 11:53:50.100 [p] 1枪：CHARGING-0003",
            '2026-08-04 11:53:50.200 [p] --chargingInfo:{"deviceNo":"P1","interfaceCode":"1","serviceId":514236631,"tradeNo":"T1153","startTime":1785815580,"endTime":1785815630,"totalBattery":190,"chargeMoney":121,"chargeStartMeterBattery":1000,"chargeEndMeterBattery":1190}',
            "2026-08-04 11:57:50.000 [p] 1枪：OCCUPYING-0005",
            '2026-08-04 12:11:00.000 [p] --chargingInfo:{"deviceNo":"P1","interfaceCode":"1","serviceId":514236631,"tradeNo":"T1153","startTime":1785815580,"endTime":1785816660,"totalBattery":15020,"chargeMoney":9612,"chargeStartMeterBattery":1000,"chargeEndMeterBattery":16020}',
            "2026-08-04 12:11:50.000 [p] 0枪：OCCUPYING-0005",
            '2026-08-04 12:12:00.000 [p] --recordInfo:{"deviceNo":"P1","interfaceCode":"1","serviceId":514236631,"tradeNo":"T1153","startTime":1785815580,"endTime":1785816660,"totalBattery":15020,"chargeMoney":9612,"chargeStartMeterBattery":1000,"chargeEndMeterBattery":16020,"deviceChargeFinishReasonMsg":"充满自动停止","isChargeFinish":1}',
        ]
    )
    r = analyze_order_log(text, service_id="514236631")
    fields = {f["name"]: f["value"] for f in r.get("fields", [])}
    assert fields.get("枪口号") == "1 枪"
    # 0枪充电约 18 分钟；绝不能误用他枪的 4 分钟（240 秒）
    dur = fields.get("充电时长") or ""
    assert "4 分钟" not in dur
    import re

    m = re.search(r"(\d+)\s*秒", dur)
    assert m is not None
    sec = int(m.group(1))
    assert sec >= 1000
    assert sec < 1300
