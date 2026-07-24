# -*- coding: utf-8 -*-
from pathlib import Path
from evcpa.order_report import analyze_order_log

SAMPLE = Path(r"c:\Users\OXD\Downloads\S2607240896483729312.txt")


def test_wanma_vin_order_filtered_and_unfiltered():
    if not SAMPLE.exists():
        return
    text = SAMPLE.read_text(encoding="utf-8", errors="ignore")

    r0 = analyze_order_log(text)
    assert r0["mode"] == "charging_report"
    assert r0["extras"]["has_remote_stop"] is False
    fields0 = {f["name"]: f["value"] for f in r0["fields"]}
    assert fields0["启动方式"].startswith("VIN")
    assert fields0["是否有远程停止指令"] == "无"
    assert "跳枪" in fields0["停止类型"] or fields0["停止类型"].startswith("设备")
    assert r0["valid"] is True

    r1 = analyze_order_log(text, service_id="507235304")
    assert r1["mode"] == "charging_report"
    assert r1["extras"]["has_remote_stop"] is False
    fields1 = {f["name"]: f["value"] for f in r1["fields"]}
    assert fields1["启动方式"].startswith("VIN")
    assert fields1["是否有远程停止指令"] == "无"
    assert r1["valid"] is True
    assert "需复核" not in (r1.get("verdict") or "")
