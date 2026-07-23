from __future__ import annotations

from typing import Any

from evcpa.knowledge.alarms import COMMON_ALARM_HINTS, VENDOR_STATUS_MAP
from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.utils import to_hex


_XX_KEYS = {
    "deviceId",
    "connectorId",
    "pileCode",
    "stationId",
    "orderNo",
    "startChargeSeq",
    "OperatorID",
    "EquipAuthSeq",
    "ConnectorStatusInfo",
    "chargeStatus",
    "gunStatus",
}


class XingxingParser(ProtocolParser):
    """星星充电：常见 JSON/MQTT 业务报文 + 少量二进制启发。"""

    protocol_id = ProtocolId.XINGXING
    protocol_name = "星星充电"

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        if isinstance(json_obj, dict):
            keys = set(json_obj.keys())
            hit = len(keys & _XX_KEYS)
            text = str(json_obj).lower()
            score = min(0.25 + hit * 0.12, 0.9)
            if "xingxing" in text or "star" in text or "xxcharge" in text:
                score += 0.1
            if "OperatorID" in keys or "ConnectorStatusInfo" in keys:
                score += 0.15
            return min(score, 1.0)
        if raw and len(raw) >= 4:
            # 部分接入网关使用 AA 55 开头私有帧
            if raw[0] == 0xAA and raw[1] == 0x55:
                return 0.45
        return 0.0

    def parse(self, raw: bytes | None, json_obj: Any | None) -> AnalysisResult:
        if isinstance(json_obj, dict):
            return self._parse_json(json_obj)
        if raw:
            return AnalysisResult(
                protocol=self.protocol_id,
                protocol_name=self.protocol_name,
                confidence=self.detect_score(raw, None),
                summary="识别为星星风格二进制帧（AA 55），建议对照厂商私有文档细化",
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
        status_map = VENDOR_STATUS_MAP["xingxing"]

        for k, v in obj.items():
            meaning = None
            if k in ("chargeStatus", "gunStatus", "status", "Status"):
                meaning = status_map.get(v, status_map.get(str(v)))
            if k.lower() in COMMON_ALARM_HINTS:
                warnings.append(
                    WarningItem(code=k, level="warn", message=COMMON_ALARM_HINTS[k.lower()])
                )
            fields.append(FieldItem(name=k, value=v, meaning=meaning))

        # 嵌套 ConnectorStatusInfo
        csi = obj.get("ConnectorStatusInfo")
        if isinstance(csi, dict):
            st = csi.get("Status")
            fields.append(
                FieldItem(
                    name="ConnectorStatusInfo.Status",
                    value=st,
                    meaning=status_map.get(st, status_map.get(str(st)) if st is not None else None),
                )
            )

        cmd = obj.get("cmd") or obj.get("Cmd") or obj.get("Action") or obj.get("method")
        summary = f"星星充电 JSON 报文"
        if cmd:
            summary += f"，指令={cmd}"
        device = obj.get("deviceId") or obj.get("pileCode") or obj.get("ConnectorID")
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
