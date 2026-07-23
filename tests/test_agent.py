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
    "weijing",
    "wanma",
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


def test_ykc_v17_realtime_full_fields():
    """V1.7 0x13 应完整解析电压电流 SOC 等字段。"""
    agent = ProtocolAgent()
    hx = (
        "684000000013202509145201010126072200204915322025091452010101"
        "030201F40DC600520000000000000000125400000000500000000000000000000000000002BE"
    )
    result = agent.analyze_hex(hx)
    assert result.protocol == ProtocolId.YKC
    assert result.frame_type == "0x13"
    assert result.valid is True
    by_name = {f.name: f for f in result.fields}
    assert by_name["trade_no"].value.startswith("20250914520101")
    assert by_name["status"].meaning == "充电"
    assert by_name["output_voltage"].value == 357.2
    assert by_name["output_current"].value == 19.8
    assert by_name["soc"].value == 18
    assert result.protocol_name == "云快充"


def test_ykc_frame_type_table_v17():
    from evcpa.knowledge.ykc import YKC_FRAME_TYPES

    assert YKC_FRAME_TYPES[0x31][0].startswith("充电桩主动申请")
    assert YKC_FRAME_TYPES[0x3D][0] == "交易记录"
    assert YKC_FRAME_TYPES[0x34][0].startswith("运营平台远程控制启机")


def test_ykc_crc():
    raw = parse_hex((SAMPLES / "ykc_heartbeat.hex").read_text(encoding="utf-8"))
    assert crc16_modbus(raw[2:-2]) == int.from_bytes(raw[-2:], "little")


def test_weijing_heartbeat_sample():
    from evcpa.utils import crc16_xmodem

    agent = ProtocolAgent()
    hx = (SAMPLES / "weijing_heartbeat.hex").read_text(encoding="utf-8")
    result = agent.analyze_hex(hx)
    assert result.protocol == ProtocolId.WEIJING
    assert result.frame_type == "0x0C"
    assert result.valid is True
    by_name = {f.name: f for f in result.fields}
    assert by_name["pile_code"].value == "1234567890"
    assert by_name["gun_count"].value == 2
    assert by_name["gun_status_2"].meaning == "充电中"
    raw = parse_hex(hx)
    assert crc16_xmodem(raw[:-2]) == int.from_bytes(raw[-2:], "big")


def test_weijing_login_sample():
    agent = ProtocolAgent()
    hx = (SAMPLES / "weijing_login.hex").read_text(encoding="utf-8")
    result = agent.analyze_hex(hx)
    assert result.protocol == ProtocolId.WEIJING
    assert result.frame_type == "0x01"
    assert result.valid is True
    by_name = {f.name: f for f in result.fields}
    assert by_name["pile_type"].meaning == "直流充电桩"
    assert by_name["rated_power"].value == 120.0
    assert by_name["comm_protocol_ver"].value == "2.6"


def test_weijing_not_confused_with_ykc():
    agent = ProtocolAgent()
    wj = agent.analyze_hex((SAMPLES / "weijing_heartbeat.hex").read_text(encoding="utf-8"))
    ykc = agent.analyze_hex((SAMPLES / "ykc_heartbeat.hex").read_text(encoding="utf-8"))
    assert wj.protocol == ProtocolId.WEIJING
    assert ykc.protocol == ProtocolId.YKC


def test_weijing_aes_remote_start_header_only():
    agent = ProtocolAgent()
    hx = (SAMPLES / "weijing_remote_start_aes.hex").read_text(encoding="utf-8")
    result = agent.analyze_hex(hx)
    assert result.protocol == ProtocolId.WEIJING
    assert result.frame_type == "0x06"
    assert result.valid is True
    codes = {w.code for w in result.warnings}
    assert "ENCRYPTED_BODY" in codes
    by_name = {f.name: f for f in result.fields}
    assert by_name["pile_code"].value == "1234563890"
    assert by_name["encrypt_flag"].meaning == "AES"


def test_wanma_login_sample():
    from evcpa.utils import crc32_iso_hdlc

    agent = ProtocolAgent()
    hx = (SAMPLES / "wanma_login.hex").read_text(encoding="utf-8")
    result = agent.analyze_hex(hx)
    assert result.protocol == ProtocolId.WANMA
    assert result.frame_type == "0x0001"
    assert result.valid is True
    by_name = {f.name: f for f in result.fields}
    assert by_name["device_id"].value.startswith("330102")
    assert by_name["hardware_sn"].value.startswith("WANMA-SN-TEST")
    assert by_name["proto_major"].value == 1
    raw = parse_hex(hx)
    assert crc32_iso_hdlc(raw[:-4]) == int.from_bytes(raw[-4:], "little")


def test_wanma_keepalive_sample():
    agent = ProtocolAgent()
    hx = (SAMPLES / "wanma_keepalive.hex").read_text(encoding="utf-8")
    result = agent.analyze_hex(hx)
    assert result.protocol == ProtocolId.WANMA
    assert result.frame_type == "0x0005"
    assert result.frame_type_name == "平台保活"
    assert result.valid is True


def test_wanma_not_confused_with_ykc_or_weijing():
    agent = ProtocolAgent()
    wanma = agent.analyze_hex((SAMPLES / "wanma_login.hex").read_text(encoding="utf-8"))
    ykc = agent.analyze_hex((SAMPLES / "ykc_login.hex").read_text(encoding="utf-8"))
    weijing = agent.analyze_hex((SAMPLES / "weijing_heartbeat.hex").read_text(encoding="utf-8"))
    assert wanma.protocol == ProtocolId.WANMA
    assert ykc.protocol == ProtocolId.YKC
    assert weijing.protocol == ProtocolId.WEIJING


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


def test_weijing_platform_log_not_misdetected_as_ykc():
    agent = ProtocolAgent()
    # 运营平台日志中的 ASCII 桩号帧（曾被误判为云快充；实为蔚景帧结构）
    hx = "680C92F0093330303130323837390000020100B9BC"
    result = agent.analyze_hex(hx)
    assert result.protocol == ProtocolId.WEIJING
    assert result.confidence >= 0.7
    pile = next(f for f in result.fields if f.name == "pile_code")
    assert pile.value == "300102879"
    assert not any(w.code == "CRC_FAIL" for w in result.warnings)
