from __future__ import annotations

from pathlib import Path

from evcpa.agent import ProtocolAgent
from evcpa.models import ProtocolId
from evcpa.utils import crc16_modbus, parse_hex

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"

EXPECTED_PROTOCOL_IDS = {
    "ykc",
    "xingxing",
    "shenghong",
    "huawei",
    "infypower",
    "ocpp",
    "cec",
    "teld",
    "sgcc",
    "csg",
    "xiaoju",
    "aoneng",
    "putian",
    "kehua",
    "kstar",
    "abb",
    "evercharge",
    "kamaisi",
    "dakuyun",
    "youyichong",
    "iec104",
    "nari",
    "zhichong",
    "anyue",
    "wallbox",
    "phoenix",
    "lvtong",
    "ascii68",
}


def test_list_protocols():
    agent = ProtocolAgent()
    ids = {p["id"] for p in agent.list_protocols()}
    assert ids == EXPECTED_PROTOCOL_IDS


def test_ykc_login_sample():
    agent = ProtocolAgent()
    hx = (SAMPLES / "ykc_login.hex").read_text(encoding="utf-8")
    result = agent.analyze_hex(hx)
    assert result.protocol == ProtocolId.YKC
    assert result.frame_type == "0x01"
    assert result.valid is True
    pile = next(f for f in result.fields if f.name == "pile_code")
    assert pile.value.startswith("320102")


def test_ykc_crc():
    raw = parse_hex((SAMPLES / "ykc_heartbeat.hex").read_text(encoding="utf-8"))
    assert crc16_modbus(raw[2:-2]) == int.from_bytes(raw[-2:], "little")


def test_xingxing_json():
    agent = ProtocolAgent()
    text = (SAMPLES / "xingxing_status.json").read_text(encoding="utf-8")
    result = agent.analyze_json(text)
    assert result.protocol == ProtocolId.XINGXING
    assert result.confidence >= 0.5


def test_shenghong_json():
    agent = ProtocolAgent()
    text = (SAMPLES / "shenghong_status.json").read_text(encoding="utf-8")
    result = agent.analyze_json(text)
    assert result.protocol == ProtocolId.SHENGHONG


def test_huawei_json():
    agent = ProtocolAgent()
    text = (SAMPLES / "huawei_event.json").read_text(encoding="utf-8")
    result = agent.analyze_json(text)
    assert result.protocol == ProtocolId.HUAWEI


def test_infypower_json():
    agent = ProtocolAgent()
    text = (SAMPLES / "infypower_module.json").read_text(encoding="utf-8")
    result = agent.analyze_json(text)
    assert result.protocol == ProtocolId.INFYPOWER


def test_ocpp_boot():
    agent = ProtocolAgent()
    text = (SAMPLES / "ocpp_boot.json").read_text(encoding="utf-8")
    result = agent.analyze_json(text)
    assert result.protocol == ProtocolId.OCPP
    assert result.frame_type == "BootNotification"
    assert result.confidence >= 0.9


def test_cec_start_result():
    agent = ProtocolAgent()
    text = (SAMPLES / "cec_start_result.json").read_text(encoding="utf-8")
    result = agent.analyze_json(text)
    assert result.protocol == ProtocolId.CEC
    assert result.confidence >= 0.85


def test_teld_realtime():
    agent = ProtocolAgent()
    text = (SAMPLES / "teld_realtime.json").read_text(encoding="utf-8")
    result = agent.analyze_json(text)
    assert result.protocol == ProtocolId.TELD


def test_sgcc_status():
    agent = ProtocolAgent()
    text = (SAMPLES / "sgcc_status.json").read_text(encoding="utf-8")
    result = agent.analyze_json(text)
    assert result.protocol == ProtocolId.SGCC


def test_iec104_json():
    agent = ProtocolAgent()
    text = (SAMPLES / "iec104_interrogation.json").read_text(encoding="utf-8")
    result = agent.analyze_json(text)
    assert result.protocol == ProtocolId.IEC104


def test_iec104_start_dt_hex():
    agent = ProtocolAgent()
    hx = (SAMPLES / "iec104_start_dt.hex").read_text(encoding="utf-8")
    result = agent.analyze_hex(hx)
    assert result.protocol == ProtocolId.IEC104
    assert result.frame_type == "U"


def test_force_protocol():
    agent = ProtocolAgent()
    text = (SAMPLES / "xingxing_status.json").read_text(encoding="utf-8")
    result = agent.analyze(json_text=text, protocol="xingxing")
    assert result.protocol == ProtocolId.XINGXING
    assert result.confidence >= 0.99


def test_ykc_not_misdetected_as_iec104():
    agent = ProtocolAgent()
    hx = (SAMPLES / "ykc_login.hex").read_text(encoding="utf-8")
    result = agent.analyze_hex(hx)
    assert result.protocol == ProtocolId.YKC


def test_ascii68_not_misdetected_as_ykc():
    agent = ProtocolAgent()
    # 运营平台日志中的 ASCII 桩号帧（曾被误判为云快充并报 CRC 失败）
    hx = "680C92F0093330303130323837390000020100B9BC"
    result = agent.analyze_hex(hx)
    assert result.protocol == ProtocolId.ASCII68
    assert result.confidence >= 0.7
    pile = next(f for f in result.fields if f.name == "pile_code")
    assert pile.value == "300102879"
    assert not any(w.code == "CRC_FAIL" for w in result.warnings)
