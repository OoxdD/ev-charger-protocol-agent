from __future__ import annotations

from typing import Any

from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.utils import crc16_modbus, to_hex

# IEC 60870-5-104 ASDU type ids（节选）
_ASDU_TYPES = {
    1: "M_SP_NA_1 单点信息",
    3: "M_DP_NA_1 双点信息",
    9: "M_ME_NA_1 测量值归一化",
    11: "M_ME_NB_1 测量值标度化",
    13: "M_ME_NC_1 测量值短浮点",
    30: "M_SP_TB_1 带时标单点",
    36: "M_ME_TF_1 带时标短浮点",
    45: "C_SC_NA_1 单点命令",
    46: "C_DC_NA_1 双点命令",
    48: "C_SE_NA_1 设定值归一化",
    100: "C_IC_NA_1 总召唤",
    101: "C_CI_NA_1 计数量召唤",
    103: "C_CS_NA_1 时钟同步",
}


class Iec104Parser(ProtocolParser):
    """IEC 60870-5-104（国网/南网等二次开发常基于此）。"""

    protocol_id = ProtocolId.IEC104
    protocol_name = "IEC104"

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        if isinstance(json_obj, dict):
            text = str(json_obj).lower()
            keys = set(json_obj.keys())
            score = 0.0
            if keys & {"asdu", "cot", "ioa", "typeId", "type_id", "commonAddress", "apdu"}:
                score += 0.55
            if "iec104" in text or "60870" in text or "asdu" in text:
                score += 0.3
            return min(score, 0.9)
        if not raw or len(raw) < 6:
            return 0.0
        if raw[0] != 0x68:
            return 0.0
        # ASCII 桩号协议：第 5 字节为长度且后续为数字串
        if len(raw) > 10:
            n = raw[4]
            if 5 <= n <= 32 and 5 + n <= len(raw) - 2 and raw[5 : 5 + n].isdigit():
                return 0.05
        apdu_len = raw[1]
        # 104: length = remaining bytes; U/S/I frames
        if apdu_len + 2 != len(raw) and not (6 <= len(raw) <= 255):
            # still may be partial
            pass
        # 与云快充区分：YKC 有独立 CRC16，且第 5 字节常为帧类型；104 控制域在 2..5
        score = 0.35
        if apdu_len + 2 == len(raw):
            score += 0.25
        ctrl0 = raw[2]
        # U-format: bit0=1 bit1=1
        if ctrl0 & 0x03 == 0x03:
            score += 0.25
        # S-format: bit0=1 bit1=0
        elif ctrl0 & 0x03 == 0x01:
            score += 0.2
        # I-format: bit0=0，且长度通常 >6
        elif ctrl0 & 0x01 == 0 and len(raw) >= 7:
            score += 0.2
            type_id = raw[6]
            if type_id in _ASDU_TYPES:
                score += 0.2

        # 若看起来更像云快充（带 CRC 且已知帧类型），压低分数
        if len(raw) >= 8:
            try:
                calc = crc16_modbus(raw[2:-2])
                recv = int.from_bytes(raw[-2:], "little")
                ykc_type = raw[5]
                if calc == recv and ykc_type in {0x01, 0x02, 0x03, 0x04, 0x13, 0x33, 0x34, 0x3B, 0x40, 0x55, 0x56}:
                    return 0.05
            except Exception:
                pass
        return min(score, 0.92)

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
        fields = [FieldItem(name=k, value=v) for k, v in obj.items()]
        type_id = obj.get("typeId") or obj.get("type_id")
        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(None, obj),
            frame_type=str(type_id) if type_id is not None else None,
            frame_type_name=_ASDU_TYPES.get(int(type_id), str(type_id)) if type_id is not None else "IEC104 JSON",
            summary="IEC104 JSON 封装报文",
            fields=fields,
            raw_json=obj,
            valid=True,
        )

    def _parse_bin(self, raw: bytes) -> AnalysisResult:
        fields: list[FieldItem] = []
        warnings: list[WarningItem] = []
        fields.append(FieldItem(name="start", value="0x68", offset=0, length=1, meaning="启动字符"))
        if len(raw) < 2:
            return AnalysisResult(
                protocol=self.protocol_id,
                protocol_name=self.protocol_name,
                confidence=0.2,
                valid=False,
                summary="IEC104 帧过短",
                fields=fields,
                raw_hex=to_hex(raw),
            )

        apdu_len = raw[1]
        fields.append(FieldItem(name="apdu_length", value=apdu_len, offset=1, length=1, meaning="APDU 长度"))
        if apdu_len + 2 != len(raw):
            warnings.append(
                WarningItem(
                    code="LEN_MISMATCH",
                    level="warn",
                    message=f"声明长度 {apdu_len}+2 与实际 {len(raw)} 不一致",
                )
            )

        ctrl = raw[2:6] if len(raw) >= 6 else raw[2:]
        fields.append(FieldItem(name="control", value=to_hex(ctrl), offset=2, length=len(ctrl), meaning="控制域"))

        frame_kind = "unknown"
        type_name = None
        frame_type = None
        if len(raw) >= 3:
            b0 = raw[2]
            if b0 & 0x03 == 0x03:
                frame_kind = "U-format"
                frame_type = "U"
                type_name = "U 格式（启停/测试）"
            elif b0 & 0x03 == 0x01:
                frame_kind = "S-format"
                frame_type = "S"
                type_name = "S 格式（确认）"
            else:
                frame_kind = "I-format"
                frame_type = "I"
                type_name = "I 格式（信息）"
                if len(raw) >= 7:
                    type_id = raw[6]
                    frame_type = str(type_id)
                    type_name = _ASDU_TYPES.get(type_id, f"ASDU type={type_id}")
                    fields.append(
                        FieldItem(name="type_id", value=type_id, offset=6, length=1, meaning=type_name)
                    )
                if len(raw) >= 8:
                    vsq = raw[7]
                    fields.append(FieldItem(name="vsq", value=vsq, offset=7, length=1, meaning="可变结构限定词"))
                if len(raw) >= 10:
                    cot = int.from_bytes(raw[8:10], "little")
                    fields.append(FieldItem(name="cot", value=cot, offset=8, length=2, meaning="传送原因"))
                if len(raw) >= 12:
                    ca = int.from_bytes(raw[10:12], "little")
                    fields.append(FieldItem(name="common_address", value=ca, offset=10, length=2, meaning="公共地址"))

        fields.append(FieldItem(name="raw", value=to_hex(raw), meaning="完整 APDU"))
        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(raw, None),
            frame_type=frame_type,
            frame_type_name=type_name or frame_kind,
            summary=f"IEC104 {frame_kind}" + (f"，{type_name}" if type_name else ""),
            fields=fields,
            warnings=warnings,
            raw_hex=to_hex(raw),
            valid=len(warnings) == 0 or all(w.level != "error" for w in warnings),
        )
