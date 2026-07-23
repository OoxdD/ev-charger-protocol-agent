from __future__ import annotations

from typing import Any

from evcpa.knowledge.alarms import VENDOR_STATUS_MAP
from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.utils import read_u16_be, to_hex


_SH_KEYS = {
    "pileSn",
    "gunNo",
    "shCode",
    "shenghong",
    "meterValue",
    "chargeEnergy",
    "soc",
    "workStatus",
}


class ShenghongParser(ProtocolParser):
    """盛宏：二进制帧（常见 0xAA 头）与 JSON 业务字段。"""

    protocol_id = ProtocolId.SHENGHONG
    protocol_name = "盛宏"

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        if isinstance(json_obj, dict):
            keys = {str(k).lower() for k in json_obj.keys()}
            hit = len(keys & {k.lower() for k in _SH_KEYS})
            score = min(0.2 + hit * 0.15, 0.85)
            blob = str(json_obj).lower()
            if "shenghong" in blob or "盛宏" in blob:
                score += 0.15
            return min(score, 1.0)
        if raw and len(raw) >= 6:
            if raw[0] == 0xAA and raw[1] in (0xF5, 0xF6, 0x55):
                return 0.55
            if raw[0] == 0x7E and raw[-1] == 0x7E:
                return 0.35
        return 0.0

    def parse(self, raw: bytes | None, json_obj: Any | None) -> AnalysisResult:
        if isinstance(json_obj, dict):
            return self._parse_json(json_obj)
        if raw:
            return self._parse_bin(raw)
        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=0.0,
            valid=False,
            summary="无有效输入",
        )

    def _parse_json(self, obj: dict[str, Any]) -> AnalysisResult:
        fields = []
        status_map = VENDOR_STATUS_MAP["shenghong"]
        for k, v in obj.items():
            meaning = None
            if k in ("workStatus", "status", "gunStatus"):
                meaning = status_map.get(v)
            fields.append(FieldItem(name=k, value=v, meaning=meaning))
        summary = "盛宏 JSON 报文"
        sn = obj.get("pileSn") or obj.get("deviceId")
        if sn:
            summary += f"，桩号={sn}"
        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(None, obj),
            summary=summary,
            fields=fields,
            raw_json=obj,
            valid=True,
        )

    def _parse_bin(self, raw: bytes) -> AnalysisResult:
        fields: list[FieldItem] = [
            FieldItem(name="header", value=to_hex(raw[:2]), offset=0, length=2, meaning="帧头"),
        ]
        warnings: list[WarningItem] = []
        cmd = None
        if len(raw) >= 4:
            cmd = raw[2]
            fields.append(FieldItem(name="cmd", value=f"0x{cmd:02X}", offset=2, length=1, meaning="命令字"))
        if len(raw) >= 6:
            length = read_u16_be(raw, 3) if len(raw) > 5 else raw[3]
            fields.append(FieldItem(name="length_hint", value=length, meaning="长度域(启发式)"))
        if len(raw) >= 8:
            fields.append(FieldItem(name="payload", value=to_hex(raw[4:-2]), meaning="载荷"))
            fields.append(FieldItem(name="checksum", value=to_hex(raw[-2:]), meaning="校验/尾"))

        summary = f"盛宏二进制帧，长度 {len(raw)} 字节"
        if cmd is not None:
            summary += f"，命令=0x{cmd:02X}"
        if raw[0] not in (0xAA, 0x7E):
            warnings.append(WarningItem(code="HEADER", level="warn", message="帧头非常见盛宏模式，置信度有限"))

        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(raw, None),
            frame_type=f"0x{cmd:02X}" if cmd is not None else None,
            summary=summary,
            fields=fields,
            warnings=warnings,
            raw_hex=to_hex(raw),
            valid=True,
        )
