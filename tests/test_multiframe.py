from __future__ import annotations

from pathlib import Path

from evcpa.agent import ProtocolAgent
from evcpa.framing import split_frames
from evcpa.utils import parse_hex, to_hex

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_split_ykc_sticky_frames():
    hb = parse_hex((SAMPLES / "ykc_heartbeat.hex").read_text(encoding="utf-8"))
    login = parse_hex((SAMPLES / "ykc_login.hex").read_text(encoding="utf-8"))
    realtime = parse_hex(
        "684000000013202509145201010126072200204915322025091452010101"
        "030201F40DC600520000000000000000125400000000500000000000000000000000000002BE"
    )
    raw = hb + login + realtime
    frames = split_frames(raw)
    assert len(frames) == 3
    assert all(f.protocol_hint == "ykc" for f in frames)
    assert len(frames[0].data) == len(hb)
    assert len(frames[2].data) == len(realtime)


def test_analyze_payload_multi_frame_order():
    hb = parse_hex((SAMPLES / "ykc_heartbeat.hex").read_text(encoding="utf-8"))
    realtime = parse_hex(
        "684000000013202509145201010126072200204915322025091452010101"
        "030201F40DC600520000000000000000125400000000500000000000000000000000000002BE"
    )
    raw = hb + realtime
    data = ProtocolAgent().analyze_payload(hex_text=to_hex(raw, spaced=False))
    assert data["mode"] == "charging_report"
    assert data["extras"]["frame_count"] == 2
    assert data["extras"]["order_count"] >= 1
    fields = {f["name"]: f["value"] for f in data["fields"]}
    assert str(fields["订单流水号"]).startswith("20250914520101")
    assert fields["解析帧数"] == "2"


def test_analyze_payload_single_still_works():
    hx = (SAMPLES / "ykc_login.hex").read_text(encoding="utf-8")
    data = ProtocolAgent().analyze_payload(hex_text=hx)
    assert data.get("mode") != "charging_report" or data.get("extras", {}).get("source") != "protocol_frames"
    assert data["protocol"] == "ykc"
    assert data["frame_type"] == "0x01"
