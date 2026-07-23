# -*- coding: utf-8 -*-
from evcpa.order_report import _check_process_vs_bill


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
