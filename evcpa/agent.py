from __future__ import annotations

import json
from typing import Any

from evcpa.detect import detect_best
from evcpa.frame_order import aggregate_frame_order, has_order_signal
from evcpa.framing import split_frames
from evcpa.models import AnalysisResult, ProtocolId, WarningItem
from evcpa.protocol_log import extract_frames_from_protocol_log, looks_like_protocol_trace_log
from evcpa.protocols import all_parsers
from evcpa.utils import looks_like_json, parse_hex, safe_json_loads, to_hex

# 抓包日志中心跳帧可不做完整业务解析，仅计数
_LINK_CMD_HINTS = {"03", "04"}
_PRIORITY_CMD_HINTS = {
    "13",
    "15",
    "17",
    "19",
    "21",
    "23",
    "25",
    "31",
    "32",
    "33",
    "34",
    "35",
    "36",
    "3B",
    "3D",
    "40",
    "41",
    "42",
}


class ProtocolAgent:
    """充电桩报文分析智能体：自动识别协议并输出结构化解读。"""

    def __init__(self) -> None:
        self.parsers = all_parsers()
        self._by_id = {p.protocol_id: p for p in self.parsers}

    def list_protocols(self) -> list[dict[str, str]]:
        return [
            {"id": p.protocol_id.value, "name": p.protocol_name}
            for p in self.parsers
        ]

    def analyze(
        self,
        *,
        hex_text: str | None = None,
        json_text: str | None = None,
        protocol: str | None = None,
    ) -> AnalysisResult:
        raw: bytes | None = None
        json_obj: Any | None = None

        if hex_text:
            raw = parse_hex(hex_text)
        if json_text:
            json_obj = safe_json_loads(json_text)
            if json_obj is None and looks_like_json(json_text):
                return AnalysisResult(
                    protocol=ProtocolId.UNKNOWN,
                    protocol_name="未知",
                    confidence=0.0,
                    valid=False,
                    summary="JSON 解析失败",
                    warnings=[WarningItem(code="BAD_JSON", level="error", message="无法解析 JSON")],
                )

        # 若只给了 hex，但内容是 ASCII JSON
        if raw is not None and json_obj is None:
            try:
                as_text = raw.decode("utf-8")
                if looks_like_json(as_text):
                    json_obj = safe_json_loads(as_text)
            except Exception:
                pass

        preferred = None
        if protocol:
            try:
                preferred = ProtocolId(protocol.lower())
            except ValueError:
                return AnalysisResult(
                    protocol=ProtocolId.UNKNOWN,
                    protocol_name="未知",
                    confidence=0.0,
                    valid=False,
                    summary=f"不支持的协议标识: {protocol}",
                    warnings=[
                        WarningItem(
                            code="BAD_PROTOCOL",
                            level="error",
                            message=f"可选: {[p.protocol_id.value for p in self.parsers]}",
                        )
                    ],
                )

        parser, score, candidates = detect_best(raw, json_obj, preferred=preferred, parsers=self.parsers)
        if parser is None:
            return AnalysisResult(
                protocol=ProtocolId.UNKNOWN,
                protocol_name="未知",
                confidence=0.0,
                valid=False,
                summary="未能识别协议，请指定 --protocol 或检查报文格式",
                warnings=[WarningItem(code="UNDETECTED", level="error", message="无匹配协议")],
                raw_hex=to_hex(raw) if raw else None,
                raw_json=json_obj if isinstance(json_obj, dict) else None,
                extras={"candidates": candidates},
            )

        result = parser.parse(raw, json_obj)
        result.confidence = score if preferred is None else max(result.confidence, score)
        result.extras = {**result.extras, "candidates": candidates}
        return result

    def analyze_payload(
        self,
        *,
        hex_text: str | None = None,
        json_text: str | None = None,
        text: str | None = None,
        protocol: str | None = None,
    ) -> dict[str, Any]:
        """分析入口：协议抓包日志 / 多帧 hex 自动拆包并汇总订单。"""
        blob = text or hex_text
        if blob and looks_like_protocol_trace_log(blob):
            return self._analyze_protocol_trace_log(blob, protocol=protocol)

        if hex_text and not json_text:
            try:
                raw = parse_hex(hex_text)
            except ValueError as e:
                # 可能是夹杂时间戳的抓包文本
                if looks_like_protocol_trace_log(hex_text):
                    return self._analyze_protocol_trace_log(hex_text, protocol=protocol)
                return {
                    "protocol": "unknown",
                    "protocol_name": "未知",
                    "confidence": 0.0,
                    "valid": False,
                    "summary": str(e),
                    "warnings": [{"code": "BAD_HEX", "level": "error", "message": str(e)}],
                    "fields": [],
                }
            frames = split_frames(raw)
            if len(frames) >= 2:
                return self._analyze_multi_frames(frames, protocol=protocol)
            if len(frames) == 1:
                one = self.analyze(
                    hex_text=to_hex(frames[0].data, spaced=False),
                    protocol=protocol or frames[0].protocol_hint,
                )
                return one.to_pretty_dict()
        result = self.analyze(hex_text=hex_text, json_text=json_text, protocol=protocol)
        return result.to_pretty_dict()

    def _analyze_protocol_trace_log(self, text: str, *, protocol: str | None = None) -> dict[str, Any]:
        log_frames = extract_frames_from_protocol_log(text)
        if not log_frames:
            return {
                "protocol": "unknown",
                "protocol_name": "未知",
                "confidence": 0.0,
                "valid": False,
                "summary": "识别为协议抓包日志，但未提取到有效 0x68 帧",
                "warnings": [{"code": "NO_FRAMES", "level": "error", "message": "无匹配【上报/下发】帧行"}],
                "fields": [],
            }

        results: list[AnalysisResult] = []
        skipped_link = 0
        pile = next((f.pile for f in log_frames if f.pile), None)

        for lf in log_frames:
            cmd = (lf.cmd_hint or "").upper()
            if cmd in _LINK_CMD_HINTS:
                skipped_link += 1
                # 用轻量占位结果计入统计
                results.append(
                    AnalysisResult(
                        protocol=ProtocolId.YKC,
                        protocol_name="云快充",
                        confidence=0.9,
                        frame_type=f"0x{cmd}",
                        frame_type_name="心跳" if cmd == "03" else "心跳应答",
                        direction="pile->platform" if cmd == "03" else "platform->pile",
                        valid=True,
                        summary=f"链路帧 0x{cmd}（日志行 {lf.line_no}）",
                        fields=[],
                        raw_hex=to_hex(lf.data),
                        extras={"log_ts": lf.ts, "log_line": lf.line_no, "skipped_detail": True},
                    )
                )
                continue

            forced = protocol or "ykc"
            r = self.analyze(hex_text=lf.hex_text, protocol=forced)
            r.extras = {
                **(r.extras or {}),
                "log_ts": lf.ts,
                "log_line": lf.line_no,
                "log_dir": lf.direction,
            }
            results.append(r)

        if has_order_signal(results):
            report = aggregate_frame_order(results, meta={"pile": pile, "source": "protocol_trace_log"})
            report["extras"] = {
                **(report.get("extras") or {}),
                "source": "protocol_trace_log",
                "extracted_frames": len(log_frames),
                "link_placeholder": skipped_link,
            }
            return report

        return self._analyze_multi_frames(
            [
                type("F", (), {"data": lf.data, "offset": lf.line_no, "protocol_hint": "ykc"})()
                for lf in log_frames
                if (lf.cmd_hint or "").upper() not in _LINK_CMD_HINTS
            ],
            protocol=protocol or "ykc",
        )

    def _analyze_multi_frames(
        self,
        frames: list[Any],
        *,
        protocol: str | None = None,
    ) -> dict[str, Any]:
        results: list[AnalysisResult] = []
        for fr in frames:
            forced = protocol or fr.protocol_hint
            r = self.analyze(hex_text=to_hex(fr.data, spaced=False), protocol=forced)
            r.extras = {**(r.extras or {}), "frame_offset": fr.offset, "frame_len": len(fr.data)}
            results.append(r)

        if has_order_signal(results):
            report = aggregate_frame_order(results)
            report["extras"] = {
                **(report.get("extras") or {}),
                "candidates": results[0].extras.get("candidates") if results else [],
            }
            return report

        first = results[0]
        warnings: list[dict[str, Any]] = []
        for r in results:
            for w in r.warnings:
                warnings.append(
                    {
                        "code": w.code,
                        "level": w.level,
                        "message": f"[{r.frame_type}] {w.message}",
                    }
                )
        fields = [
            {
                "name": f"帧{i} {r.frame_type_name or r.frame_type or ''}",
                "value": r.summary,
            }
            for i, r in enumerate(results, 1)
        ]
        return {
            "mode": "multi_frame",
            "protocol": first.protocol.value,
            "protocol_name": first.protocol_name,
            "confidence": first.confidence,
            "frame_type": None,
            "frame_type_name": f"多帧解析（{len(results)} 帧）",
            "valid": all(r.valid for r in results),
            "summary": f"共拆出并解析 {len(results)} 帧，未识别到完整订单关键帧，已逐帧列出。",
            "conclusion": f"共解析 {len(results)} 帧协议报文。",
            "verdict": "综合判断：多帧已全部解析，可在帧明细中逐条查看。",
            "result_points": [
                f"{i}. {r.frame_type_name or r.frame_type}: {r.summary}" for i, r in enumerate(results, 1)
            ],
            "fields": fields,
            "warnings": warnings,
            "extras": {
                "source": "protocol_frames",
                "frame_count": len(results),
                "frames": [r.to_pretty_dict() for r in results],
            },
        }

    def analyze_hex(self, hex_text: str, protocol: str | None = None) -> AnalysisResult:
        return self.analyze(hex_text=hex_text, protocol=protocol)

    def analyze_json(
        self, data: str | dict[str, Any] | list[Any], protocol: str | None = None
    ) -> AnalysisResult:
        if isinstance(data, (dict, list)):
            return self.analyze(json_text=json.dumps(data, ensure_ascii=False), protocol=protocol)
        return self.analyze(json_text=data, protocol=protocol)

    def explain(self, result: AnalysisResult) -> str:
        lines = [
            f"协议: {result.protocol_name} ({result.protocol.value})",
            f"置信度: {result.confidence:.0%}",
            f"结论: {result.summary}",
        ]
        if result.frame_type:
            lines.append(f"帧类型: {result.frame_type_name or ''} [{result.frame_type}]")
        if result.direction:
            lines.append(f"方向: {result.direction}")
        if result.warnings:
            lines.append("告警/问题:")
            for w in result.warnings:
                lines.append(f"  - [{w.level}] {w.code}: {w.message}")
        if result.warnings or not result.valid:
            lines.append("需到设备上核实相关数据，请设备方协助排查。")
        if result.fields:
            lines.append("关键字段:")
            for f in result.fields[:30]:
                lines.append(f"  - {f.display_name}: {f.display_value()}")
            if len(result.fields) > 30:
                lines.append(f"  ... 另有 {len(result.fields) - 30} 个字段")
        return "\n".join(lines)
