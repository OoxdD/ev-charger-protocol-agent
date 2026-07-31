from __future__ import annotations

from pathlib import Path

from evcpa.agent import ProtocolAgent
from evcpa.crypto.sm4 import sm4_ecb_decrypt, sm4_ecb_encrypt
from evcpa.csg_session import aggregate_csg_session
from evcpa.framing import split_frames
from evcpa.models import AnalysisResult, FieldItem, ProtocolId
from evcpa.protocols.csg import CsgParser
from evcpa.protocols.csg_business import parse_a3_charge_record, parse_business_payload
from evcpa.protocols.shenghong import ShenghongParser
from evcpa.utils import parse_hex

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_shenghong_heartbeat_detect_and_parse():
    hx = (SAMPLES / "shenghong_heartbeat.hex").read_text(encoding="utf-8")
    raw = parse_hex(hx)
    p = ShenghongParser()
    assert p.detect_score(raw, None) >= 0.7
    r = p.parse(raw, None)
    assert r.protocol.value == "shenghong"
    assert r.frame_type == "102"
    fields = {f.name: f.value for f in r.fields}
    assert str(fields.get("pile_code", "")).startswith("SH20240001")


def test_shenghong_status_work_status():
    hx = (SAMPLES / "shenghong_status.hex").read_text(encoding="utf-8")
    raw = parse_hex(hx)
    r = ShenghongParser().parse(raw, None)
    assert r.frame_type == "104"
    work = next(f for f in r.fields if f.name == "work_status")
    assert work.value == 2
    assert work.meaning == "充电进行中"


def test_shenghong_cmd222_energy_milli_kwh():
    """CMD 222 电量/表码为 0.001 kWh，不可按 CMD 202 的 0.01 缩放。"""
    hx = (SAMPLES / "shenghong_cmd222.hex").read_text(encoding="utf-8")
    r = ShenghongParser().parse(parse_hex(hx), None)
    assert r.frame_type == "222"
    fields = {f.name: f.value for f in r.fields}
    assert fields["session_energy"] == 74.872
    assert fields["meter_before"] == 2242.981
    assert fields["meter_after"] == 2317.853
    assert round(fields["meter_after"] - fields["meter_before"], 3) == 74.872
    assert fields["session_money"] == 47.16


def test_shenghong_session_not_ykc_empty_report():
    """盛弘多帧抓包应走盛弘会话汇总，而非空壳云快充订单报告。"""
    from evcpa.shenghong_session import aggregate_shenghong_session
    from evcpa.models import AnalysisResult, FieldItem, ProtocolId

    results = [
        AnalysisResult(
            protocol=ProtocolId.SHENGHONG,
            protocol_name="盛弘",
            confidence=1.0,
            frame_type="104",
            frame_type_name="状态",
            valid=True,
            summary="status",
            fields=[
                FieldItem(name="pile_code", value="8820231205010203"),
                FieldItem(name="gun_no", value=1),
                FieldItem(name="work_status", value=2, meaning="充电进行中"),
                FieldItem(name="session_energy", value=1.23, unit="kWh"),
                FieldItem(name="session_fee", value=1.5, unit="元"),
                FieldItem(name="ac_a_voltage", value=220.0, unit="V"),
                FieldItem(name="ac_a_current", value=16.0, unit="A"),
                FieldItem(name="card_or_user", value="00000000000000000000000493480851"),
                FieldItem(name="start_or_reserve_time", value="2026-07-01 19:53:50"),
                FieldItem(name="start_way", value=1, meaning="后台启动"),
            ],
            extras={"log_ts": "2026-07-01 19:54:02.778"},
        ),
        AnalysisResult(
            protocol=ProtocolId.SHENGHONG,
            protocol_name="盛弘",
            confidence=1.0,
            frame_type="202",
            frame_type_name="充电记录",
            valid=True,
            summary="bill",
            fields=[
                FieldItem(name="pile_code", value="8820231205010203"),
                FieldItem(name="gun_no", value=1),
                FieldItem(name="card_no", value="00000000000000000000000493480851"),
                FieldItem(name="start_time", value="2026-07-01 19:53:50"),
                FieldItem(name="end_time", value="2026-07-01 21:56:00"),
                FieldItem(name="duration_sec", value=7329),
                FieldItem(name="soc_start", value=20),
                FieldItem(name="soc_end", value=80),
                FieldItem(name="session_energy", value=13.59, unit="kWh"),
                FieldItem(name="session_money", value=14.81, unit="元"),
                FieldItem(name="stop_reason", value=101016, meaning="达到用户设定充电条件停止"),
            ],
            extras={"log_ts": "2026-07-01 21:56:10.000"},
        ),
    ]
    report = aggregate_shenghong_session(results)
    assert report["protocol"] == "shenghong"
    assert report["valid"] is True
    orders = (report.get("extras") or {}).get("orders") or []
    assert len(orders) == 1
    assert orders[0]["session_energy"] == 13.59
    assert orders[0]["card_no"] == "493480851"
    fmap = {f["name"]: f["value"] for f in report["fields"]}
    assert fmap["充电桩编号"] == "8820231205010203"
    assert fmap["枪口号"] == "1 枪"
    assert "13.59" in str(fmap["实际充电电量"])
    assert "14.81" in str(fmap["费用合计"])
    assert "达到用户设定" in str(fmap["设备结束原因"])
    assert fmap["充电时长"] == "122 分 9 秒"
    assert fmap["SOC"] == "20% → 80%"
    names = [f["name"] for f in report["fields"]]
    assert names.index("SOC") == names.index("充电时长") + 1
    assert fmap["启动校验"] == "通过"
    assert fmap["枪口是否进入充电"] == "是"
    assert fmap["过程是否有电流/电压上报"] == "是"
    assert fmap["过程是否有电量上报"] == "是"
    assert "进入充电" in str(fmap["启动校验说明"])
    assert fmap["是否有远程停止指令"] == "无"
    assert fmap["停止类型"] == "设备停止"
    # 过程量/帧统计在项目表可见，但不进结论摘要堆砌
    assert "解析帧数" in fmap
    summary = report.get("summary") or ""
    assert "解析帧数" not in summary
    assert "帧类型" not in summary
    assert any("进入充电" in p for p in (report.get("result_points") or []))


def test_shenghong_cmd5_remote_stop_detected():
    """CMD=5 命令地址 2 + 0x55 应识别为平台远程停止，停止类型非设备停止。"""
    from evcpa.shenghong_session import aggregate_shenghong_session

    hx = "AAF51900000605000000000001020000000104005500000062"
    r5 = ShenghongParser().parse(parse_hex(hx), None)
    assert r5.frame_type == "5"
    f5 = {f.name: f.value for f in r5.fields}
    assert f5["ctrl_addr"] == 2
    assert f5["ctrl_param"] == 0x55
    assert f5["is_remote_stop"] is True
    r5.extras = {"log_ts": "2026-07-28 03:34:56.387"}

    results = [
        AnalysisResult(
            protocol=ProtocolId.SHENGHONG,
            protocol_name="盛弘",
            confidence=1.0,
            frame_type="104",
            frame_type_name="状态",
            valid=True,
            summary="status",
            fields=[
                FieldItem(name="pile_code", value="2026061511500001"),
                FieldItem(name="gun_no", value=1),
                FieldItem(name="work_status", value=2, meaning="充电进行中"),
                FieldItem(name="session_energy", value=10.0, unit="kWh"),
                FieldItem(name="dc_voltage", value=400.0, unit="V"),
                FieldItem(name="dc_current", value=50.0, unit="A"),
                FieldItem(name="start_way", value=1, meaning="后台启动"),
            ],
            extras={"log_ts": "2026-07-28 03:30:00.000"},
        ),
        r5,
        AnalysisResult(
            protocol=ProtocolId.SHENGHONG,
            protocol_name="盛弘",
            confidence=1.0,
            frame_type="222",
            frame_type_name="充电记录",
            valid=True,
            summary="bill",
            fields=[
                FieldItem(name="pile_code", value="2026061511500001"),
                FieldItem(name="gun_no", value=1),
                FieldItem(name="start_time", value="2026-07-28 02:01:54"),
                FieldItem(name="end_time", value="2026-07-28 03:34:54"),
                FieldItem(name="duration_sec", value=5580),
                FieldItem(name="session_energy", value=74.872, unit="kWh"),
                FieldItem(name="session_money", value=47.16, unit="元"),
                FieldItem(name="stop_reason", value=311, meaning="后台终止"),
            ],
            extras={"log_ts": "2026-07-28 03:34:59.741"},
        ),
    ]
    report = aggregate_shenghong_session(results)
    fmap = {f["name"]: f["value"] for f in report["fields"]}
    assert fmap["是否有远程停止指令"] == "有"
    assert fmap["停止类型"] == "用户远程停止"
    assert "CMD=5" in str(fmap["停止原因"])
    assert "后台终止" in str(fmap["设备结束原因"])
    assert "CMD=5" in str(fmap["停止依据"])
    assert fmap["停止充电指令次数"] == "1"


def test_csg_proto_id_frame():
    hx = (SAMPLES / "csg_proto_id.hex").read_text(encoding="utf-8")
    raw = parse_hex(hx)
    p = CsgParser()
    assert p.detect_score(raw, None) >= 0.7
    r = p.parse(raw, None)
    assert r.frame_type == "PROTO_ID"
    assert any(f.name == "pile_code" for f in r.fields)


def test_csg_business_type_130():
    hx = (SAMPLES / "csg_business_130.hex").read_text(encoding="utf-8")
    raw = parse_hex(hx)
    r = CsgParser().parse(raw, None)
    assert r.frame_type == "130"
    rec = next(f for f in r.fields if f.name == "record_type")
    assert rec.value == 17
    assert "充电过程" in (rec.meaning or "")


def test_agent_auto_detect_shenghong_and_csg():
    agent = ProtocolAgent()
    sh = agent.analyze_hex((SAMPLES / "shenghong_heartbeat.hex").read_text(encoding="utf-8"))
    assert sh.protocol.value == "shenghong"
    csg = agent.analyze_hex((SAMPLES / "csg_business_130.hex").read_text(encoding="utf-8"))
    assert csg.protocol.value == "csg"


def test_csg_log_cmd_without_0x_prefix():
    from evcpa.protocol_log import extract_frames_from_protocol_log, looks_like_protocol_trace_log

    text = (
        "2026-07-26 10:03:00.089 [cmd=00] [上行] 68040043000000\n"
        "2026-07-26 10:03:00.144 [cmd=01] [上行] 682B0000000000018F01000000000000000000000000000000000000000000000000000000000000000000000000\n"
    )
    assert looks_like_protocol_trace_log(text)
    frames = extract_frames_from_protocol_log(text)
    assert len(frames) == 2
    assert frames[0].cmd_hint == "00"
    data = ProtocolAgent().analyze_payload(text=text)
    assert data["protocol"] == "csg"


def test_sm4_ecb_standard_vector():
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    pt = bytes.fromhex("0123456789abcdeffedcba9876543210")
    ct = sm4_ecb_encrypt(key, pt)
    assert ct.hex() == "681edf34d206965e86b3e94f536e4246"
    assert sm4_ecb_decrypt(key, ct) == pt


def _build_min_a3() -> bytes:
    """构造可被 parse_a3 识别的最小明文头（后续填 0）。"""
    pile = bytes.fromhex("20 25 07 26 12 34 56 78".replace(" ", ""))
    gun = bytes([2])
    trade = bytes.fromhex("20 25 07 26 10 03 00 00 00 00 00 00 00 00 00 01".replace(" ", ""))
    pay = bytes([0xFF] * 8)
    phys = bytes([0xFF] * 8)
    tou = bytes([0])
    # CP56: 2026-07-26 10:03:00.000
    start = bytes([0x00, 0x00, 3, 10, 26, 7, 26])
    end = bytes([0x00, 0x00, 30, 10, 26, 7, 26])
    body = pile + gun + trade + pay + phys + tou + start + end
    # pad to cover total_kwh offset (~150)
    body = body + bytes(200)
    # total_kwh at offset 146
    body = bytearray(body)
    body[146:150] = (1234).to_bytes(4, "little")  # 12.34 kWh
    body[150:152] = bytes.fromhex("0001")
    body[255:259] = (5600).to_bytes(4, "little")  # 56.00 元
    body[259:261] = (3).to_bytes(2, "little")  # 充满停止
    return bytes(body)


def test_parse_a3_plaintext():
    biz = _build_min_a3()
    parsed = parse_a3_charge_record(biz)
    assert parsed is not None
    assert parsed["pile_code"] == "2025072612345678"
    assert parsed["gun_no"] == 2
    assert parsed["total_kwh"] == 12.34
    assert parsed["total_fee"] == 56.0
    assert parsed["stop_reason"] == "充满自动停止"


def test_parse_business_sm4_roundtrip(monkeypatch):
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    plain = _build_min_a3()
    # 桩号明文 + 其后加密
    enc = plain[:8] + sm4_ecb_encrypt(key, plain[8:])
    monkeypatch.setenv("EVCPA_CSG_SM4_KEY", key.hex())
    out = parse_business_payload(2, enc)
    assert out.get("encrypted") is False
    assert out.get("trade_no", "").startswith("20250726")
    assert out.get("total_kwh") == 12.34


def test_csg_session_telemetry_orders():
    """无明文业务时，由遥测还原订单。"""
    results: list[AnalysisResult] = []

    def me(ts: str, gun: int, vals: list[int]) -> AnalysisResult:
        fields = [FieldItem(name="gun_no", value=gun)]
        for i, v in enumerate(vals):
            fields.append(FieldItem(name=f"me_{i}", value=v))
        return AnalysisResult(
            protocol=ProtocolId.CSG,
            protocol_name="南方电网",
            confidence=1.0,
            frame_type="11",
            frame_type_name="me",
            valid=True,
            summary="me",
            fields=fields,
            extras={"log_ts": ts},
        )

    def md(ts: str, gun: int, raw: int) -> AnalysisResult:
        return AnalysisResult(
            protocol=ProtocolId.CSG,
            protocol_name="南方电网",
            confidence=1.0,
            frame_type="132",
            frame_type_name="md",
            valid=True,
            summary="md",
            fields=[FieldItem(name="gun_no", value=gun), FieldItem(name="md_0", value=raw)],
            extras={"log_ts": ts},
        )

    def rec(ts: str) -> AnalysisResult:
        return AnalysisResult(
            protocol=ProtocolId.CSG,
            protocol_name="南方电网",
            confidence=1.0,
            frame_type="130",
            frame_type_name="biz",
            valid=True,
            summary="rec",
            fields=[FieldItem(name="record_type", value=2), FieldItem(name="gun_no", value=0)],
            extras={
                "log_ts": ts,
                "business": {"record_type": 2, "encrypted": True, "pile_code": "4342021042100003"},
            },
        )

    # 充电中：V=5000(500V), I=1000(100A), SOC=50, status=3
    charging = [5000, 1000, 0, 50, 0, 0, 3]
    idle = [0, 0, 0, 50, 0, 0, 2]
    results = [
        md("2026-07-26 10:00:00.000", 2, 100000),
        me("2026-07-26 10:00:00.100", 2, charging),
        me("2026-07-26 10:10:00.100", 2, charging),
        md("2026-07-26 10:10:00.200", 2, 101500),
        me("2026-07-26 10:11:00.100", 2, idle),
        rec("2026-07-26 10:11:30.000"),
    ]
    report = aggregate_csg_session(results)
    orders = (report.get("extras") or {}).get("orders") or []
    assert len(orders) >= 1
    assert orders[0]["gun_no"] == 2
    assert orders[0]["total_kwh"] == 15.0
    assert "订单充电数据" in (report.get("report_text") or "")
