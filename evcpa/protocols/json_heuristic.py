"""JSON / 品牌关键字启发式解析基类，供冷门厂商快速扩展。"""

from __future__ import annotations

from typing import Any, ClassVar

from evcpa.knowledge.alarms import COMMON_ALARM_HINTS, VENDOR_STATUS_MAP
from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.utils import to_hex


class JsonHeuristicParser(ProtocolParser):
    """通用 JSON 启发式解析器。子类只需声明关键字与品牌词。"""

    protocol_id: ProtocolId
    protocol_name: str
    KEYS: ClassVar[set[str]] = set()
    KEYWORDS: ClassVar[tuple[str, ...]] = ()
    STATUS_VENDOR: ClassVar[str] = ""
    BINARY_MAGIC: ClassVar[bytes | None] = None
    BINARY_SCORE: ClassVar[float] = 0.4
    SUMMARY_PREFIX: ClassVar[str] = ""

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        if isinstance(json_obj, dict):
            keys = set(json_obj.keys())
            hit = len(keys & self.KEYS)
            score = min(0.18 + hit * 0.11, 0.82)
            text = str(json_obj).lower()
            for kw in self.KEYWORDS:
                if kw.lower() in text:
                    score += 0.12
                    break
            return min(score, 1.0)
        if raw and self.BINARY_MAGIC and raw.startswith(self.BINARY_MAGIC):
            return self.BINARY_SCORE
        return 0.0

    def parse(self, raw: bytes | None, json_obj: Any | None) -> AnalysisResult:
        if isinstance(json_obj, dict):
            return self._parse_json(json_obj)
        if raw:
            return AnalysisResult(
                protocol=self.protocol_id,
                protocol_name=self.protocol_name,
                confidence=self.detect_score(raw, None),
                summary=f"疑似{self.protocol_name}私有二进制帧，建议对照厂商文档细化",
                fields=[FieldItem(name="raw", value=to_hex(raw), meaning="原始报文")],
                raw_hex=to_hex(raw),
                valid=True,
            )
        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=0.0,
            valid=False,
            summary="无有效输入",
        )

    def _parse_json(self, obj: dict[str, Any]) -> AnalysisResult:
        fields: list[FieldItem] = []
        warnings: list[WarningItem] = []
        status_map = VENDOR_STATUS_MAP.get(self.STATUS_VENDOR, {})

        def walk(prefix: str, node: Any) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    path = f"{prefix}.{k}" if prefix else k
                    meaning = None
                    if k in ("status", "Status", "gunStatus", "chargeStatus", "connectorStatus", "pileStatus"):
                        meaning = status_map.get(v, status_map.get(str(v)))
                    if isinstance(v, dict):
                        fields.append(FieldItem(name=path, value="object", meaning=meaning))
                        walk(path, v)
                    elif isinstance(v, list):
                        fields.append(FieldItem(name=path, value=f"list[{len(v)}]", meaning=meaning))
                        if v and not isinstance(v[0], (dict, list)):
                            fields.append(FieldItem(name=f"{path}[0]", value=v[0]))
                    else:
                        low = str(k).lower()
                        if low in COMMON_ALARM_HINTS and v not in (0, False, None, "0", "normal", "OK"):
                            warnings.append(
                                WarningItem(code=str(k), level="warn", message=COMMON_ALARM_HINTS[low])
                            )
                        fields.append(FieldItem(name=path, value=v, meaning=meaning))
            elif isinstance(node, list):
                for i, item in enumerate(node[:15]):
                    walk(f"{prefix}[{i}]", item)

        walk("", obj)

        cmd = (
            obj.get("cmd")
            or obj.get("Cmd")
            or obj.get("Action")
            or obj.get("action")
            or obj.get("method")
            or obj.get("msgType")
            or obj.get("MessageType")
        )
        device = (
            obj.get("deviceId")
            or obj.get("deviceNo")
            or obj.get("pileCode")
            or obj.get("pileNo")
            or obj.get("connectorId")
            or obj.get("ConnectorID")
            or obj.get("stationId")
        )
        prefix = self.SUMMARY_PREFIX or f"{self.protocol_name} JSON 报文"
        summary = prefix
        if cmd:
            summary += f"，指令/动作={cmd}"
        if device:
            summary += f"，设备={device}"

        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(None, obj),
            frame_type=str(cmd) if cmd else None,
            frame_type_name=str(cmd) if cmd else "业务 JSON",
            direction="unknown",
            valid=True,
            summary=summary,
            fields=fields,
            warnings=warnings,
            raw_json=obj,
        )
