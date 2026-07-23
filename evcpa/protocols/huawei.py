from __future__ import annotations

from typing import Any

from evcpa.knowledge.alarms import COMMON_ALARM_HINTS, VENDOR_STATUS_MAP
from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.utils import to_hex


_HW_KEYS = {
    "productId",
    "deviceId",
    "serviceId",
    "properties",
    "chargerStatus",
    "connectorId",
    "transactionId",
    "meterValue",
    "huawei",
    "FusionCharge",
    "eventType",
    "notify_data",
}


class HuaweiParser(ProtocolParser):
    """华为：IoT / FusionCharge 风格 JSON 为主。"""

    protocol_id = ProtocolId.HUAWEI
    protocol_name = "华为"

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        if isinstance(json_obj, dict):
            keys = set(json_obj.keys())
            hit = len(keys & _HW_KEYS)
            score = min(0.2 + hit * 0.12, 0.88)
            text = str(json_obj)
            low = text.lower()
            if "huawei" in low or "fusioncharge" in low or "hw_" in low:
                score += 0.15
            if "services" in keys or "properties" in keys or "productId" in keys:
                score += 0.1
            return min(score, 1.0)
        if raw and raw[:2] == b"\x5A\xA5":
            return 0.4
        return 0.0

    def parse(self, raw: bytes | None, json_obj: Any | None) -> AnalysisResult:
        if isinstance(json_obj, dict):
            return self._parse_json(json_obj)
        if raw:
            return AnalysisResult(
                protocol=self.protocol_id,
                protocol_name=self.protocol_name,
                confidence=self.detect_score(raw, None),
                summary="疑似华为私有二进制帧，建议结合设备物模型进一步解析",
                fields=[FieldItem(name="raw", value=to_hex(raw))],
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
        status_map = VENDOR_STATUS_MAP["huawei"]

        def walk(prefix: str, node: Any) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    path = f"{prefix}.{k}" if prefix else k
                    meaning = None
                    if k in ("chargerStatus", "status", "Status", "connectorStatus"):
                        meaning = status_map.get(v, status_map.get(str(v)))
                    if isinstance(v, dict):
                        fields.append(FieldItem(name=path, value="object", meaning=meaning))
                        walk(path, v)
                    elif isinstance(v, list):
                        fields.append(FieldItem(name=path, value=f"list[{len(v)}]", meaning=meaning))
                        walk(path, v)
                    else:
                        if str(k).lower() in COMMON_ALARM_HINTS and v not in (0, False, None, "0", "normal"):
                            warnings.append(
                                WarningItem(
                                    code=str(k),
                                    level="warn",
                                    message=COMMON_ALARM_HINTS[str(k).lower()],
                                )
                            )
                        fields.append(FieldItem(name=path, value=v, meaning=meaning))
            elif isinstance(node, list):
                for i, item in enumerate(node[:20]):
                    walk(f"{prefix}[{i}]", item)

        walk("", obj)

        event = obj.get("eventType") or obj.get("serviceId") or obj.get("method")
        device = obj.get("deviceId") or obj.get("productId")
        summary = "华为 IoT/FusionCharge 风格报文"
        if event:
            summary += f"，事件/服务={event}"
        if device:
            summary += f"，设备={device}"

        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(None, obj),
            frame_type=str(event) if event else None,
            frame_type_name=str(event) if event else "属性/事件上报",
            summary=summary,
            fields=fields,
            warnings=warnings,
            raw_json=obj,
            valid=True,
        )
