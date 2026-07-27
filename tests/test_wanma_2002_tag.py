# -*- coding: utf-8 -*-
from evcpa.agent import ProtocolAgent
from evcpa.utils import parse_hex


WANMA_2002 = (
    "9955BBAA0220C66D5C000100202411115555550255A290000B143900706F890A23040000"
    "F401F40100000000000000000000000000000001012E5C0366032800091B1A9B161D409C"
    "4001210000000000A079E32D0000000089C4CCDA"
)


def test_parse_hex_strips_report_tag_with_4digit_cmd():
    """【上报 0x2002】 中的命令字不能拼进报文 hex。"""
    tagged = f"【上报 0x2002】 {WANMA_2002}"
    assert parse_hex(tagged) == parse_hex(WANMA_2002)
    assert parse_hex(tagged)[:4] == bytes.fromhex("9955BBAA")


def test_analyze_wanma_2002_with_log_tag():
    tagged = f"【上报 0x2002】 {WANMA_2002}"
    r = ProtocolAgent().analyze_hex(tagged)
    assert r.protocol.value == "wanma"
    assert r.valid is True
    fields = {f.name: f.value for f in r.fields}
    assert fields["msg_code"] == "0x2002"
    assert fields["device_id"] == "2024111155555502"
    # 尾部 00 填充导致的非 16 对齐不应再提示
    assert not any(w.code == "BODY_ALIGN" for w in r.warnings)
    assert "发现" not in (r.summary or "")
    # 数据域应解出枪口电气量（本样本为 0.01V / 0.01A）
    assert fields["gun_no"] == 1
    assert fields["output_voltage"] == 235.98
    assert fields["output_current"] == 261.15
    assert fields["rated_voltage"] == 500
    assert fields["rated_current"] == 500


def test_analyze_payload_wanma_2002_trace_tag():
    """带【上报】标签走抓包日志路径时，不得强制云快充。"""
    tagged = f"【上报 0x2002】 {WANMA_2002}"
    data = ProtocolAgent().analyze_payload(text=tagged)
    assert data["protocol"] == "wanma"
    assert data["valid"] is True
    assert data.get("mode") != "multi_frame"
    assert data["frame_type"] == "0x2002"
    names = {f["name"]: f["value"] for f in data["fields"]}
    assert names["output_voltage"] == 235.98
    assert names["gun_no"] == 1
