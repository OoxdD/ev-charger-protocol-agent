# -*- coding: utf-8 -*-
from evcpa.agent import ProtocolAgent


WANMA_4004 = (
    "9955BBAA0440C56D3C0001012024111155555502012E00002805000089860100"
    "D0340A00000F00020095636A1C800100109A636A6D060000540C431A"
)


def test_analyze_wanma_4004_with_slots():
    tagged = f"【上报 0x4004】 {WANMA_4004}"
    data = ProtocolAgent().analyze_payload(text=tagged)
    assert data["protocol"] == "wanma"
    assert data["valid"] is True
    assert data["frame_type"] == "0x4004"
    assert not any(w.get("code") == "BODY_ALIGN" for w in (data.get("warnings") or []))

    fields = {f["name"]: f["value"] for f in data["fields"]}
    assert fields["gun_no"] == 1
    assert fields["soc"] == 46
    assert fields["charge_time_sec"] == 1320
    assert fields["charge_energy"] == 99.977
    assert fields["charge_money"] == 66.888
    assert fields["need_time_min"] == 15
    assert fields["slot_count"] == 2
    assert fields["slot_0_energy"] == 98.332
    assert fields["slot_16_energy"] == 1.645
    assert fields["slot_energy_sum"] == 99.977
