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


def test_prefer_record_over_raw_bill_without_total():
    """原始 0x5 账单无 totalBattery 时，应用 recordInfo 结算电量；过程取最后一帧。"""
    from evcpa.order_report import _pick_bill_energy_src, _pick_proc_frame

    record = {
        "totalBattery": 23791,
        "jianBattery": 23791,
        "fengBattery": 0,
        "pingBattery": 0,
        "guBattery": 0,
        "chargeEndMeterBattery": 4058738,
    }
    bill = {
        "cmd": "0x5",
        "stopMeter": 40587380,
        "periodInfos": [{"battery": 237910}],
    }
    src = _pick_bill_energy_src(record, bill)
    assert src is record
    assert src["totalBattery"] == 23791

    chgs = [
        {"totalBattery": 0, "jianBattery": 0, "chargeEndMeterBattery": 4034947},
        {"totalBattery": 23754, "jianBattery": 23754, "chargeEndMeterBattery": 4058701},
        {"totalBattery": 27330, "jianBattery": 27330, "chargeEndMeterBattery": 4062277},
    ]
    proc = _pick_proc_frame(chgs, src)
    assert proc["totalBattery"] == 27330
    # 无功率时仍按 1 kWh 容差 → 差值约 3.5 判异常
    checks = _check_process_vs_bill(proc, src, 4034947, 4058738)
    codes = {c["code"] for c in checks if not c.get("ok")}
    assert "TOTAL_MISMATCH" in codes


def test_high_power_widens_total_tolerance():
    """末帧大功率时，过程与账单差超过 1 kWh 仍可视为合理。"""
    from evcpa.order_report import _energy_tol_kwh, _estimate_power_kw

    # ~122.5 kW → 容差约 4.08 kWh
    soc = {
        "batteryChargerOutputCurrent": 229980,
        "batteryChargerOutputVoltage": 532700,
    }
    pk = _estimate_power_kw(soc)
    assert pk is not None and 110 < pk < 140
    tol, desc = _energy_tol_kwh(pk)
    assert tol > 1.0
    assert "分钟" in desc

    proc = {
        "totalBattery": 27330,
        "jianBattery": 27330,
        "fengBattery": 0,
        "pingBattery": 0,
        "guBattery": 0,
    }
    bill = {
        "totalBattery": 23791,
        "jianBattery": 23791,
        "fengBattery": 0,
        "pingBattery": 0,
        "guBattery": 0,
    }
    checks = _check_process_vs_bill(
        proc, bill, 4034947, 4058738, last_power_kw=pk
    )
    total = next(c for c in checks if c["code"].startswith("TOTAL"))
    assert total["ok"] is True
    assert "容差" in total["message"]
