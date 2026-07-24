from __future__ import annotations

from pathlib import Path

from evcpa.agent import ProtocolAgent
from evcpa.protocol_log import extract_frames_from_protocol_log, looks_like_protocol_trace_log

SAMPLE = Path(r"c:\Users\OXD\Downloads\S2607220589354473186.txt")


def test_protocol_trace_detect_and_extract():
    if not SAMPLE.exists():
        return
    text = SAMPLE.read_text(encoding="utf-8", errors="ignore")
    assert looks_like_protocol_trace_log(text)
    frames = extract_frames_from_protocol_log(text)
    assert len(frames) > 1000
    cmds = {f.cmd_hint for f in frames}
    assert "13" in cmds
    assert "3B" in cmds


def test_protocol_trace_order_aggregate():
    if not SAMPLE.exists():
        return
    text = SAMPLE.read_text(encoding="utf-8", errors="ignore")
    agent = ProtocolAgent()
    # 未指定筛选：多订单应提示选择
    choice = agent.analyze_payload(text=text)
    assert choice["mode"] == "multi_order_choice"
    assert choice["extras"]["need_order_filter"] is True
    assert choice["extras"]["order_count"] >= 3
    orders = choice["extras"]["orders"]
    assert any(o.get("trade_no") for o in orders)

    trade = next(o["trade_no"] for o in orders if o.get("trade_no"))
    data = agent.analyze_payload(text=text, trade_no=trade)
    assert data["mode"] == "charging_report"
    assert data["valid"] is True
    assert data["extras"]["order_count"] == 1
    assert data["extras"]["filtered"] is True
    fields = {f["name"]: f["value"] for f in data["fields"]}
    assert fields["充电桩编号"] == "24001031030207"
    assert trade in str(fields["订单流水号"]) or trade.lstrip("0") in str(fields["订单流水号"]).lstrip("0")
    assert "kWh" in str(fields["实际充电电量"])


def test_protocol_trace_filter_not_found():
    if not SAMPLE.exists():
        return
    text = SAMPLE.read_text(encoding="utf-8", errors="ignore")
    data = ProtocolAgent().analyze_payload(text=text, trade_no="9999999999999999")
    assert data["mode"] == "charging_report"
    assert data["valid"] is False
    assert data["extras"].get("order_count") == 0
