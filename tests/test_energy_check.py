# -*- coding: utf-8 -*-
from evcpa.order_report import _check_process_vs_bill


def test_accuracy_flag_wan_fen_bill_vs_meter():
    """蔚景账单 accuracyFlag=4（万分位）与表计千分位应对齐为同一 kWh。"""
    from evcpa.order_report import _accuracy_scale, _check_process_vs_bill, _fmt_kwh

    bill = {
        "accuracyFlag": 4,
        "totalBattery": 13820,
        "jianBattery": 0,
        "fengBattery": 0,
        "pingBattery": 13820,
        "guBattery": 0,
    }
    assert _accuracy_scale(bill) == 10000
    assert _fmt_kwh(13820, 10000) == "1.382 kwh"
    # 表计用千分位：2323205→2323.205，差额 1.382
    checks = _check_process_vs_bill(
        None, bill, 2323205, 2324587, meter_scale=1000
    )
    meter = next(c for c in checks if c["code"].startswith("METER"))
    assert meter["ok"] is True
    assert "1.382" in meter["message"]


def test_total_close_within_tolerance():
    proc = {"totalBattery": 9528, "jianBattery": 0, "fengBattery": 0, "pingBattery": 9528, "guBattery": 0}
    bill = {"totalBattery": 9541, "jianBattery": 0, "fengBattery": 0, "pingBattery": 9541, "guBattery": 0}
    checks = _check_process_vs_bill(proc, bill, 107735, 117277)
    assert all(c["ok"] for c in checks if c["code"] in {"TOTAL_OK", "METER_OK", "TOU_DOM_OK"})


def test_tou_dominant_mismatch():
    proc = {"totalBattery": 2350, "jianBattery": 2350, "fengBattery": 0, "pingBattery": 0, "guBattery": 0}
    bill = {"totalBattery": 33710, "jianBattery": 0, "fengBattery": 0, "pingBattery": 0, "guBattery": 33710}
    checks = _check_process_vs_bill(proc, bill, None, None)
    codes = {c["code"] for c in checks if not c["ok"]}
    assert "TOU_DOM_MISMATCH" in codes
    assert "TOTAL_MISMATCH" in codes


def test_ignore_sub_kwh_diff():
    proc = {"totalBattery": 1000, "pingBattery": 1000, "jianBattery": 0, "fengBattery": 0, "guBattery": 0}
    bill = {"totalBattery": 1500, "pingBattery": 1500, "jianBattery": 0, "fengBattery": 0, "guBattery": 0}
    checks = _check_process_vs_bill(proc, bill, None, None)
    total = next(c for c in checks if c["code"].startswith("TOTAL"))
    assert total["ok"] is True
