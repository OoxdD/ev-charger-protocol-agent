from __future__ import annotations

from typing import Any

from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.utils import to_hex

# 中电联 T/CEC 102 系列互联互通常见字段/接口名
_CEC_STRONG_KEYS = {
    "StartChargeSeq",
    "StartChargeSeqStat",
    "EquipAuthSeq",
    "EquipBizSeq",
    "SuccStat",
    "FailReason",
    "ConnectorID",
    "QRCode",
    "TotalPower",
    "ElecMoney",
    "SeviceMoney",
    "TotalMoney",
    "SumPeriod",
    "ChargeDetails",
    "PolicyInfos",
    "StationStatusInfo",
    "ConnectorStatusInfo",
}

_CEC_ACTIONS = {
    "query_token",
    "query_stations_info",
    "query_station_status",
    "query_equip_auth",
    "query_equip_business_policy",
    "query_start_charge",
    "query_equip_charge_status",
    "query_stop_charge",
    "notification_stationStatus",
    "notification_start_charge_result",
    "notification_equip_charge_status",
    "notification_stop_charge_result",
    "notification_charge_order_info",
    "check_charge_orders",
    "notification_orderInfo",
}


class CecParser(ProtocolParser):
    """中电联互联互通（T/CEC 102.* / 运营商平台对接）。"""

    protocol_id = ProtocolId.CEC
    protocol_name = "中电联互联互通"

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        if isinstance(json_obj, dict):
            keys = set(json_obj.keys())
            hit = len(keys & _CEC_STRONG_KEYS)
            score = min(0.1 + hit * 0.12, 0.7)
            text = str(json_obj)
            low = text.lower()
            # 官方接口名命中则显著提高
            for act in _CEC_ACTIONS:
                if act in low or act.replace("_", "") in low.replace("_", ""):
                    score = max(score, 0.92)
                    break
            cmd = str(json_obj.get("cmd") or json_obj.get("Action") or json_obj.get("action") or "")
            if cmd in _CEC_ACTIONS or cmd.lower() in _CEC_ACTIONS:
                score = max(score, 0.95)
            if "StartChargeSeq" in keys or "EquipAuthSeq" in keys or "EquipBizSeq" in keys:
                score = max(score, 0.9)
            if "t/cec" in low or "cec102" in low or "互联互通" in text or "hlht" in low:
                score += 0.15
            # 避免仅靠 OperatorID 抢走星星样例
            if hit <= 1 and "OperatorID" in keys and "StartChargeSeq" not in keys:
                score = min(score, 0.55)
            return min(score, 1.0)
        return 0.0

    def parse(self, raw: bytes | None, json_obj: Any | None) -> AnalysisResult:
        if isinstance(json_obj, dict):
            return self._parse_json(json_obj)
        if raw:
            return AnalysisResult(
                protocol=self.protocol_id,
                protocol_name=self.protocol_name,
                confidence=0.0,
                summary="中电联互联互通通常为 HTTPS JSON，当前输入非 JSON",
                fields=[FieldItem(name="raw", value=to_hex(raw))],
                raw_hex=to_hex(raw),
                valid=False,
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
        for k, v in obj.items():
            if isinstance(v, dict):
                fields.append(FieldItem(name=k, value="object"))
                for sk, sv in v.items():
                    fields.append(FieldItem(name=f"{k}.{sk}", value=sv))
            else:
                fields.append(FieldItem(name=k, value=v))

        succ = obj.get("SuccStat")
        if succ not in (None, 0, "0", "success", "SUCCESS"):
            warnings.append(
                WarningItem(code="SuccStat", level="warn", message=f"业务结果非成功: {succ}")
            )
        fail = obj.get("FailReason")
        if fail not in (None, 0, "0", ""):
            warnings.append(
                WarningItem(code="FailReason", level="warn", message=f"失败原因={fail}")
            )

        cmd = obj.get("cmd") or obj.get("Action") or obj.get("action")
        seq = obj.get("StartChargeSeq") or obj.get("EquipAuthSeq") or obj.get("EquipBizSeq")
        summary = "中电联互联互通 JSON"
        if cmd:
            summary += f"，接口={cmd}"
        if seq:
            summary += f"，业务流水={seq}"

        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(None, obj),
            frame_type=str(cmd) if cmd else None,
            frame_type_name=str(cmd) if cmd else "互联互通业务",
            direction="unknown",
            valid=True,
            summary=summary,
            fields=fields,
            warnings=warnings,
            raw_json=obj,
        )
