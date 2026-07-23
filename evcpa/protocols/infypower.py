from __future__ import annotations

from typing import Any

from evcpa.knowledge.alarms import VENDOR_STATUS_MAP
from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.utils import read_u16_le, to_hex


_INFY_KEYS = {
    "moduleId",
    "moduleSn",
    "infy",
    "infypower",
    "rectifier",
    "groupId",
    "dcVoltage",
    "dcCurrent",
    "acVoltage",
    "moduleStatus",
    "faultCode",
}


class InfypowerParser(ProtocolParser):
    """英飞源：充电模块/系统侧 JSON 与二进制帧。"""

    protocol_id = ProtocolId.INFYPOWER
    protocol_name = "英飞源"

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        if isinstance(json_obj, dict):
            keys = {str(k).lower() for k in json_obj.keys()}
            hit = len(keys & {k.lower() for k in _INFY_KEYS})
            score = min(0.2 + hit * 0.14, 0.9)
            blob = str(json_obj).lower()
            if "infy" in blob or "英飞源" in blob or "rectifier" in blob:
                score += 0.15
            return min(score, 1.0)
        if raw and len(raw) >= 8:
            # 常见模块通信：EB 90 或 CAN 桥接封装
            if raw[0] == 0xEB and raw[1] == 0x90:
                return 0.6
            if raw[0] == 0xAA and raw[1] == 0xBB:
                return 0.45
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
        fields: list[FieldItem] = []
        warnings: list[WarningItem] = []
        status_map = VENDOR_STATUS_MAP["infypower"]
        for k, v in obj.items():
            meaning = None
            if k in ("moduleStatus", "status", "workStatus"):
                meaning = status_map.get(v)
            if k in ("faultCode", "alarmCode") and v not in (0, "0", None):
                warnings.append(WarningItem(code=str(v), level="warn", message=f"模块故障/告警码: {v}"))
            fields.append(FieldItem(name=k, value=v, meaning=meaning))

        summary = "英飞源模块/系统报文"
        mid = obj.get("moduleId") or obj.get("moduleSn")
        if mid:
            summary += f"，模块={mid}"
        if "dcVoltage" in obj or "dcCurrent" in obj:
            summary += f"，直流 {obj.get('dcVoltage', '-')}V / {obj.get('dcCurrent', '-')}A"

        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(None, obj),
            summary=summary,
            fields=fields,
            warnings=warnings,
            raw_json=obj,
            valid=True,
        )

    def _parse_bin(self, raw: bytes) -> AnalysisResult:
        fields = [
            FieldItem(name="header", value=to_hex(raw[:2]), offset=0, length=2, meaning="帧头"),
        ]
        warnings: list[WarningItem] = []
        cmd = None
        if len(raw) >= 4:
            cmd = raw[2]
            fields.append(FieldItem(name="cmd", value=f"0x{cmd:02X}", offset=2, length=1, meaning="功能码"))
        if len(raw) >= 8:
            # 启发式：电压电流常以 0.1 精度小端存放
            volt = read_u16_le(raw, 4) / 10.0
            curr = read_u16_le(raw, 6) / 10.0
            fields.append(FieldItem(name="voltage_hint", value=volt, unit="V", meaning="可能的电压字段"))
            fields.append(FieldItem(name="current_hint", value=curr, unit="A", meaning="可能的电流字段"))
        fields.append(FieldItem(name="raw", value=to_hex(raw), meaning="完整原始帧"))

        if raw[:2] not in (b"\xEB\x90", b"\xAA\xBB"):
            warnings.append(WarningItem(code="HEADER", level="warn", message="非典型英飞源帧头，请人工复核"))

        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(raw, None),
            frame_type=f"0x{cmd:02X}" if cmd is not None else None,
            summary=f"英飞源二进制帧，{len(raw)} 字节",
            fields=fields,
            warnings=warnings,
            raw_hex=to_hex(raw),
            valid=True,
        )
