from __future__ import annotations

from typing import Any

from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.utils import to_hex

# OCPP 1.6 / 2.0.1 常见动作
_OCPP16_ACTIONS = {
    "Authorize",
    "BootNotification",
    "Heartbeat",
    "MeterValues",
    "StartTransaction",
    "StopTransaction",
    "StatusNotification",
    "DataTransfer",
    "DiagnosticsStatusNotification",
    "FirmwareStatusNotification",
    "RemoteStartTransaction",
    "RemoteStopTransaction",
    "Reset",
    "UnlockConnector",
    "GetConfiguration",
    "ChangeConfiguration",
    "ClearCache",
    "GetDiagnostics",
    "UpdateFirmware",
    "ReserveNow",
    "CancelReservation",
    "ChangeAvailability",
    "SetChargingProfile",
    "ClearChargingProfile",
    "GetCompositeSchedule",
    "TriggerMessage",
}

_OCPP201_ACTIONS = {
    "BootNotification",
    "Heartbeat",
    "StatusNotification",
    "TransactionEvent",
    "Authorize",
    "MeterValues",
    "NotifyEvent",
    "NotifyReport",
    "RequestStartTransaction",
    "RequestStopTransaction",
    "Reset",
    "UnlockConnector",
    "GetVariables",
    "SetVariables",
    "GetBaseReport",
    "SetChargingProfile",
    "GetTransactionStatus",
}


class OcppParser(ProtocolParser):
    """OCPP 1.6 / 2.0.1 JSON（Call / CallResult / CallError）。"""

    protocol_id = ProtocolId.OCPP
    protocol_name = "OCPP"

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        # Call: [2, "uid", "Action", {...}]
        if isinstance(json_obj, list) and len(json_obj) >= 3:
            msg_type = json_obj[0]
            if msg_type in (2, 3, 4, "2", "3", "4"):
                score = 0.75
                if msg_type in (2, "2") and len(json_obj) >= 4 and isinstance(json_obj[2], str):
                    action = json_obj[2]
                    if action in _OCPP16_ACTIONS or action in _OCPP201_ACTIONS:
                        score = 0.98
                    elif action[:1].isupper():
                        score = 0.88
                return score
        if isinstance(json_obj, dict):
            text = str(json_obj).lower()
            keys = set(json_obj.keys())
            score = 0.0
            if "ocpp" in text or "csms" in text or "chargepoint" in text:
                score += 0.35
            if keys & {"chargePointVendor", "chargePointModel", "meterValue", "transactionId", "connectorId"}:
                score += 0.35
            action = json_obj.get("action") or json_obj.get("Action")
            if isinstance(action, str) and (action in _OCPP16_ACTIONS or action in _OCPP201_ACTIONS):
                score += 0.4
            return min(score, 0.95)
        if raw:
            try:
                text = raw.decode("utf-8", errors="ignore").lstrip()
            except Exception:
                return 0.0
            if text.startswith("[") and ("BootNotification" in text or "StatusNotification" in text):
                return 0.7
        return 0.0

    def parse(self, raw: bytes | None, json_obj: Any | None) -> AnalysisResult:
        if isinstance(json_obj, list):
            return self._parse_call(json_obj)
        if isinstance(json_obj, dict):
            return self._parse_dict(json_obj)
        if raw:
            return AnalysisResult(
                protocol=self.protocol_id,
                protocol_name=self.protocol_name,
                confidence=self.detect_score(raw, None),
                summary="疑似 OCPP 原始报文，建议按 JSON 数组 Call 格式解析",
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

    def _parse_call(self, arr: list[Any]) -> AnalysisResult:
        fields: list[FieldItem] = []
        warnings: list[WarningItem] = []
        msg_type = arr[0]
        type_map = {2: "Call", 3: "CallResult", 4: "CallError", "2": "Call", "3": "CallResult", "4": "CallError"}
        type_name = type_map.get(msg_type, str(msg_type))
        fields.append(FieldItem(name="messageTypeId", value=msg_type, meaning=type_name))

        uid = arr[1] if len(arr) > 1 else None
        fields.append(FieldItem(name="messageId", value=uid, meaning="唯一消息 ID"))

        action = None
        payload: Any = None
        if msg_type in (2, "2") and len(arr) >= 4:
            action = arr[2]
            payload = arr[3]
            fields.append(FieldItem(name="action", value=action, meaning="OCPP 动作"))
        elif msg_type in (3, "3") and len(arr) >= 3:
            payload = arr[2]
        elif msg_type in (4, "4") and len(arr) >= 5:
            fields.append(FieldItem(name="errorCode", value=arr[2], meaning="错误码"))
            fields.append(FieldItem(name="errorDescription", value=arr[3]))
            payload = arr[4]
            warnings.append(
                WarningItem(code=str(arr[2]), level="error", message=str(arr[3]))
            )

        if isinstance(payload, dict):
            for k, v in payload.items():
                fields.append(FieldItem(name=f"payload.{k}", value=v))
        elif payload is not None:
            fields.append(FieldItem(name="payload", value=payload))

        summary = f"OCPP {type_name}"
        if action:
            summary += f"，动作={action}"
        if uid:
            summary += f"，msgId={uid}"

        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(None, arr),
            frame_type=str(action or type_name),
            frame_type_name=str(action or type_name),
            direction="pile->platform" if msg_type in (2, "2") and action in {
                "BootNotification", "Heartbeat", "StatusNotification", "MeterValues",
                "StartTransaction", "StopTransaction", "TransactionEvent",
            } else "unknown",
            valid=msg_type not in (4, "4"),
            summary=summary,
            fields=fields,
            warnings=warnings,
            raw_json={"ocpp": arr},
            extras={"ocpp_version_guess": "2.0.1" if action in _OCPP201_ACTIONS - _OCPP16_ACTIONS else "1.6/2.0"},
        )

    def _parse_dict(self, obj: dict[str, Any]) -> AnalysisResult:
        fields = [FieldItem(name=k, value=v) for k, v in obj.items()]
        action = obj.get("action") or obj.get("Action")
        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(None, obj),
            frame_type=str(action) if action else None,
            frame_type_name=str(action) if action else "OCPP JSON 对象",
            summary=f"OCPP 风格对象报文" + (f"，动作={action}" if action else ""),
            fields=fields,
            raw_json=obj,
            valid=True,
        )
