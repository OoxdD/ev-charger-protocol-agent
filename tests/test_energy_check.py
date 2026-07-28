# -*- coding: utf-8 -*-
from evcpa.order_report import _check_process_vs_bill


def test_zero_meters_skip_meter_vs_bill():
    """起止表码均为 0（未上报）时，不应因差额 0 vs 账单电量误报 METER_MISMATCH。"""
    bill = {
        "totalBattery": 14300,
        "jianBattery": 0,
        "fengBattery": 0,
        "pingBattery": 14300,
        "guBattery": 0,
        "chargeStartMeterBattery": 0,
        "chargeEndMeterBattery": 0,
    }
    checks = _check_process_vs_bill(None, bill, 0, 0, meter_scale=1000)
    meter = next(c for c in checks if str(c.get("code", "")).startswith("METER"))
    assert meter["ok"] is True
    assert meter["code"] == "METER_SKIP"
    assert not any(c.get("code") == "METER_MISMATCH" for c in checks)


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


def test_energy_vs_power_time_ok():
    from evcpa.order_report import _check_energy_vs_power_time

    # 40 kW × 1 h = 40 kWh，实际 38 在容差内
    r = _check_energy_vs_power_time(energy_kwh=38.0, power_kw=40.0, duration_sec=3600)
    assert r["ok"] is True
    assert r["code"] == "POWER_TIME_OK"


def test_energy_vs_power_time_mismatch():
    from evcpa.order_report import _check_energy_vs_power_time

    # 40 kW × 1 h = 40，实际 10 明显不合理
    r = _check_energy_vs_power_time(energy_kwh=10.0, power_kw=40.0, duration_sec=3600)
    assert r["ok"] is False
    assert r["code"] == "POWER_TIME_MISMATCH"


def test_energy_vs_power_time_in_order_report():
    from evcpa.order_report import analyze_order_log

    text = "\n".join(
        [
            '2026-07-15 20:00:00 [x] RemoteCmd>>>>>>>>:{"remoteCmd":"17","data":{"serviceId":"920","interfaceCode":"1"}}',
            "2026-07-15 20:00:01 [x] 1枪:CHARGING",
            # ~40 kW，持续约 1 小时 → 期望约 40 kWh；账单 38 合理
            '2026-07-15 20:10:00 [x] --socInfo:{"serviceId":920,"interfaceCode":"1","batteryChargerOutputCurrent":100000,"batteryChargerOutputVoltage":400000,"batteryChargerOutPower":40000}',
            '2026-07-15 20:30:00 [x] --socInfo:{"serviceId":920,"interfaceCode":"1","batteryChargerOutputCurrent":100000,"batteryChargerOutputVoltage":400000,"batteryChargerOutPower":40000}',
            '2026-07-15 20:50:00 [x] --chargingInfo:{"serviceId":920,"interfaceCode":"1","totalBattery":38000,"chargeMoney":100,"chargeDuration":3600}',
            '2026-07-15 21:00:00 [x] --recordInfo:{"serviceId":920,"interfaceCode":"1","totalBattery":38000,"chargeMoney":100,"chargeDuration":3600,"chargeStartMeterBattery":0,"chargeEndMeterBattery":38000}',
            "2026-07-15 21:00:01 [x] 1枪:IDLE",
        ]
    )
    r = analyze_order_log(text, service_id="920")
    pt = (r.get("extras") or {}).get("power_time_check") or {}
    assert pt.get("code") == "POWER_TIME_OK"
    fields = {f["name"]: f["value"] for f in r["fields"]}
    assert fields.get("功率×时间电量校验") == "通过"
