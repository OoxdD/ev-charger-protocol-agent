# -*- coding: utf-8 -*-
from evcpa.order_report import (
    _check_inactive_tou_frozen,
    _check_process_energy_series,
    _check_start_success,
)


def test_energy_series_detects_total_decrease():
    chgs = [
        {"totalBattery": 1000, "jianBattery": 1000, "fengBattery": 0, "pingBattery": 0, "guBattery": 0},
        {"totalBattery": 2000, "jianBattery": 2000, "fengBattery": 0, "pingBattery": 0, "guBattery": 0},
        {"totalBattery": 1500, "jianBattery": 1500, "fengBattery": 0, "pingBattery": 0, "guBattery": 0},
    ]
    checks = _check_process_energy_series(chgs)
    bad = [c for c in checks if not c["ok"]]
    assert bad and bad[0]["code"] == "ENERGY_DECREASE"
    assert "回落" in bad[0]["message"]


def test_energy_series_ok_when_monotonic():
    chgs = [
        {"totalBattery": 100, "pingBattery": 100, "jianBattery": 0, "fengBattery": 0, "guBattery": 0},
        {"totalBattery": 500, "pingBattery": 500, "jianBattery": 0, "fengBattery": 0, "guBattery": 0},
        {"totalBattery": 900, "pingBattery": 900, "jianBattery": 0, "fengBattery": 0, "guBattery": 0},
    ]
    checks = _check_process_energy_series(chgs)
    assert all(c["ok"] for c in checks)


def test_inactive_tou_frozen_flags_locked_slot_change():
    # 尖段先涨，随后平段增长（尖应锁定）；若尖再变动则异常
    chgs = [
        {"totalBattery": 1000, "jianBattery": 1000, "fengBattery": 0, "pingBattery": 0, "guBattery": 0},
        {"totalBattery": 2000, "jianBattery": 2000, "fengBattery": 0, "pingBattery": 0, "guBattery": 0},
        {"totalBattery": 2500, "jianBattery": 2000, "fengBattery": 0, "pingBattery": 500, "guBattery": 0},
        {"totalBattery": 3000, "jianBattery": 2100, "fengBattery": 0, "pingBattery": 900, "guBattery": 0},
    ]
    checks = _check_inactive_tou_frozen(chgs)
    bad = [c for c in checks if not c["ok"]]
    assert bad and bad[0]["code"] == "TOU_INACTIVE_CHANGED"
    assert "尖" in bad[0]["message"]


def test_inactive_tou_frozen_ok():
    chgs = [
        {"totalBattery": 1000, "jianBattery": 1000, "fengBattery": 0, "pingBattery": 0, "guBattery": 0},
        {"totalBattery": 2000, "jianBattery": 2000, "fengBattery": 0, "pingBattery": 0, "guBattery": 0},
        {"totalBattery": 2500, "jianBattery": 2000, "fengBattery": 0, "pingBattery": 500, "guBattery": 0},
        {"totalBattery": 3000, "jianBattery": 2000, "fengBattery": 0, "pingBattery": 1000, "guBattery": 0},
    ]
    checks = _check_inactive_tou_frozen(chgs)
    assert all(c["ok"] for c in checks)


def test_start_success_requires_charging_and_process_data():
    ok = _check_start_success(
        start_ok=True,
        is_card_start=False,
        is_vin_start=False,
        is_remote_start=True,
        has_remote_cmd=True,
        gun_events=[("2026-07-01 10:00:00", "1", "CHARGING")],
        gun="1",
        socs=[{"batteryChargerOutputCurrent": 100000, "batteryChargerOutputVoltage": 400000}],
        chgs=[{"totalBattery": 100}],
    )
    assert ok["ok"] is True
    assert ok["code"] == "START_OK"

    bad = _check_start_success(
        start_ok=False,
        is_card_start=False,
        is_vin_start=False,
        is_remote_start=False,
        has_remote_cmd=False,
        gun_events=[("2026-07-01 10:00:00", "1", "IDLE")],
        gun="1",
        socs=[],
        chgs=[],
    )
    assert bad["ok"] is False
    assert bad["code"] == "START_FAIL"
    assert "过程数据" in bad["message"]


def test_start_success_by_process_data_without_start_ack():
    """无启动充电响应，但有电流/电压/电量过程数据 → 仍判启动成功。"""
    ok = _check_start_success(
        start_ok=False,
        is_card_start=False,
        is_vin_start=False,
        is_remote_start=False,
        has_remote_cmd=False,
        gun_events=[],
        gun="1",
        socs=[{"batteryChargerOutputCurrent": 80000, "batteryChargerOutputVoltage": 350000}],
        chgs=[{"totalBattery": 500}],
    )
    assert ok["ok"] is True
    assert ok["code"] == "START_OK"
    assert "电流/电压" in ok["message"] or "电量" in ok["message"]


def test_start_success_by_energy_only_without_ack():
    ok = _check_start_success(
        start_ok=False,
        is_card_start=False,
        is_vin_start=False,
        is_remote_start=False,
        has_remote_cmd=False,
        gun_events=[],
        gun=None,
        socs=[],
        chgs=[{"totalBattery": 1200}],
    )
    assert ok["ok"] is True
    assert ok["code"] == "START_OK"
