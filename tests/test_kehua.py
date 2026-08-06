"""科华协议 V4.09 解析测试。"""

from __future__ import annotations

from pathlib import Path

from evcpa.agent import ProtocolAgent
from evcpa.framing import classify_frame, split_frames
from evcpa.protocols.kehua import KehuaParser
from evcpa.utils import parse_hex

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _load(name: str) -> bytes:
    return parse_hex((SAMPLES / name).read_text(encoding="utf-8"))


def test_detect_login_frame():
    raw = _load("kehua_login.hex")
    p = KehuaParser()
    assert p.detect_score(raw, None) >= 0.9
    r = p.parse(raw, None)
    assert r.valid
    assert r.frame_type == "0x01"
    by_name = {f.name: f.value for f in r.fields}
    assert by_name["device_sn"] == "561510005490J5C00001"
    assert by_name["gun_count"] == 2
    assert by_name["crc"] == "0xFB5C"


def test_heartbeat_and_agent_auto():
    raw = _load("kehua_heartbeat.hex")
    agent = ProtocolAgent()
    r = agent.analyze_hex((SAMPLES / "kehua_heartbeat.hex").read_text(encoding="utf-8"))
    assert r.protocol.value == "kehua"
    assert r.frame_type == "0x02"
    by_name = {f.name: f.value for f in r.fields}
    assert by_name["heartbeat_seq"] == 0x384B


def test_realtime_tlv_scales():
    raw = _load("kehua_realtime.hex")
    r = KehuaParser().parse(raw, None)
    assert r.valid
    by_name = {f.name: f for f in r.fields}
    assert by_name["charge_voltage"].value == 380.0
    assert by_name["charge_current"].value == 41.68
    assert by_name["soc"].value == 0x55
    assert by_name["charge_energy"].value == 14.06


def test_framing_split_kehua():
    login = _load("kehua_login.hex")
    hb = _load("kehua_heartbeat.hex")
    blob = login + hb
    frames = split_frames(blob)
    assert len(frames) == 2
    assert frames[0].protocol_hint == "kehua"
    assert frames[1].protocol_hint == "kehua"
    assert classify_frame(login) == "kehua"
