from __future__ import annotations

import json
from typing import Any

from evcpa.detect import detect_best
from evcpa.models import AnalysisResult, ProtocolId, WarningItem
from evcpa.protocols import all_parsers
from evcpa.utils import looks_like_json, parse_hex, safe_json_loads, to_hex


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
        if result.fields:
            lines.append("关键字段:")
            for f in result.fields[:30]:
                lines.append(f"  - {f.display_name}: {f.display_value()}")
            if len(result.fields) > 30:
                lines.append(f"  ... 另有 {len(result.fields) - 30} 个字段")
        return "\n".join(lines)
