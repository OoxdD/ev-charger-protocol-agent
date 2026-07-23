from __future__ import annotations

from typing import Any

from evcpa.knowledge.ykc import (
    YKC_FRAME_TYPES,
    YKC_START_FAIL_REASON,
    YKC_STOP_REASON,
)
from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.utils import bcd_to_str, crc16_modbus, read_u16_le, to_hex


class YkcParser(ProtocolParser):
    """云快充 TCP 二进制协议（0x68 帧）。"""

    protocol_id = ProtocolId.YKC
    protocol_name = "云快充"

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        if raw is None or len(raw) < 8:
            return 0.0
        if raw[0] != 0x68:
            return 0.0
        # 排除 ASCII 桩号类协议：长度字节后紧跟可打印数字串
        if self._looks_like_ascii_pile(raw):
            return 0.05

        data_len = raw[1]
        # 数据长度 = 序列号~消息体（不含起始、长度、CRC）
        expected_total = 2 + data_len + 2
        length_ok = len(raw) == expected_total
        crc_ok = False
        if len(raw) >= 8:
            recv_crc = read_u16_le(raw, len(raw) - 2)
            calc = crc16_modbus(raw[2:-2])
            crc_ok = recv_crc == calc

        if not length_ok and not crc_ok:
            return 0.08
        if not length_ok:
            return 0.2
        if not crc_ok:
            # 长度对但 CRC 错，可能是截断/粘包，分数不宜过高
            score = 0.35
        else:
            score = 0.78
        frame_type = raw[5] if len(raw) > 5 else None
        if frame_type in YKC_FRAME_TYPES:
            score += 0.12 if crc_ok else 0.05
        return min(score, 1.0)

    @staticmethod
    def _looks_like_ascii_pile(raw: bytes) -> bool:
        """识别 68 | cmd | seq | asciiLen | '3001...' 形态，避免误判为云快充。"""
        if len(raw) < 10:
            return False
        ascii_len = raw[4]
        if ascii_len < 5 or ascii_len > 32:
            return False
        if 5 + ascii_len > len(raw) - 2:
            return False
        pile = raw[5 : 5 + ascii_len]
        return pile.isdigit()

    def parse(self, raw: bytes | None, json_obj: Any | None) -> AnalysisResult:
        if raw is None or len(raw) < 8:
            return AnalysisResult(
                protocol=self.protocol_id,
                protocol_name=self.protocol_name,
                confidence=0.0,
                valid=False,
                summary="报文过短，无法按云快充帧解析",
                warnings=[WarningItem(code="TOO_SHORT", level="error", message="至少需要 8 字节")],
            )

        fields: list[FieldItem] = []
        warnings: list[WarningItem] = []

        start = raw[0]
        fields.append(FieldItem(name="start_flag", value=f"0x{start:02X}", offset=0, length=1, meaning="起始标志"))
        if start != 0x68:
            warnings.append(WarningItem(code="BAD_START", level="error", message=f"起始标志应为 0x68，实际 0x{start:02X}"))

        data_len = raw[1]
        fields.append(FieldItem(name="data_length", value=data_len, offset=1, length=1, meaning="数据长度(序列号~消息体)"))

        expected = 2 + data_len + 2
        if len(raw) != expected:
            warnings.append(
                WarningItem(
                    code="LEN_MISMATCH",
                    level="error",
                    message=f"声明长度 {data_len}，整帧应 {expected} 字节，实际 {len(raw)}；若含 ASCII 桩号请改用 ascii68 协议",
                )
            )

        seq = read_u16_le(raw, 2)
        encrypt = raw[4]
        frame_type = raw[5]
        fields.append(FieldItem(name="seq", value=seq, offset=2, length=2, meaning="序列号"))
        fields.append(
            FieldItem(
                name="encrypt_flag",
                value=encrypt,
                offset=4,
                length=1,
                meaning="未加密" if encrypt == 0 else "加密",
            )
        )

        type_info = YKC_FRAME_TYPES.get(frame_type)
        type_name = type_info[0] if type_info else f"未知帧类型(0x{frame_type:02X})"
        direction = type_info[1] if type_info else "unknown"
        fields.append(
            FieldItem(
                name="frame_type",
                value=f"0x{frame_type:02X}",
                offset=5,
                length=1,
                meaning=type_name,
            )
        )

        body_end = len(raw) - 2
        body = raw[6:body_end] if body_end > 6 else b""
        fields.append(FieldItem(name="body", value=to_hex(body), offset=6, length=len(body), meaning="消息体原始数据"))

        if len(raw) >= 8:
            recv_crc = read_u16_le(raw, len(raw) - 2)
            calc_crc = crc16_modbus(raw[2:-2])
            fields.append(
                FieldItem(
                    name="crc16",
                    value=f"0x{recv_crc:04X}",
                    offset=len(raw) - 2,
                    length=2,
                    meaning="帧校验(CRC16-Modbus)",
                )
            )
            fields.append(FieldItem(name="crc16_calc", value=f"0x{calc_crc:04X}", meaning="本地计算 CRC"))
            if recv_crc != calc_crc:
                warnings.append(
                    WarningItem(
                        code="CRC_FAIL",
                        level="error",
                        message=f"CRC 校验失败: 报文=0x{recv_crc:04X}, 计算=0x{calc_crc:04X}",
                    )
                )

        body_fields = self._parse_body(frame_type, body)
        fields.extend(body_fields)

        summary = f"云快充 {type_name}（0x{frame_type:02X}），序列号={seq}，消息体 {len(body)} 字节"
        if warnings:
            summary += f"；发现 {len(warnings)} 个问题"

        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(raw, None),
            frame_type=f"0x{frame_type:02X}",
            frame_type_name=type_name,
            direction=direction,
            valid=not any(w.level == "error" for w in warnings),
            summary=summary,
            fields=fields,
            warnings=warnings,
            raw_hex=to_hex(raw),
            extras={"body_len": len(body)},
        )

    def _parse_body(self, frame_type: int, body: bytes) -> list[FieldItem]:
        items: list[FieldItem] = []
        if not body:
            return items

        # 登录 0x01: 桩编码 BCD 7 + 桩类型 + ...
        if frame_type == 0x01 and len(body) >= 7:
            pile = bcd_to_str(body[0:7])
            items.append(FieldItem(name="pile_code", value=pile, offset=6, length=7, meaning="桩编码(BCD)"))
            if len(body) >= 8:
                items.append(FieldItem(name="pile_type", value=body[7], meaning="桩类型 0直流/1交流"))
            if len(body) >= 9:
                items.append(FieldItem(name="gun_count", value=body[8], meaning="充电枪数量"))
            if len(body) >= 10:
                items.append(FieldItem(name="protocol_ver", value=body[9], meaning="协议版本"))
            return items

        # 心跳 0x03: 桩编码 + 枪号 + 枪状态
        if frame_type == 0x03 and len(body) >= 8:
            items.append(FieldItem(name="pile_code", value=bcd_to_str(body[0:7]), meaning="桩编码"))
            items.append(FieldItem(name="gun_no", value=body[7], meaning="枪号"))
            if len(body) >= 9:
                st = body[8]
                items.append(
                    FieldItem(
                        name="gun_status",
                        value=st,
                        meaning={0: "正常", 1: "故障"}.get(st, f"状态{st}"),
                    )
                )
            return items

        # 实时监测 0x13
        if frame_type == 0x13 and len(body) >= 16:
            items.append(FieldItem(name="pile_code", value=bcd_to_str(body[0:7]), meaning="桩编码"))
            items.append(FieldItem(name="gun_no", value=body[7], meaning="枪号"))
            status = body[8]
            status_map = {0: "离线", 1: "故障", 2: "空闲", 3: "充电"}
            items.append(FieldItem(name="status", value=status, meaning=status_map.get(status, str(status))))
            # 常见布局：后续含电压电流等（不同版本略有差异，做尽力解析）
            if len(body) >= 18:
                voltage = read_u16_le(body, 16) / 10.0
                items.append(FieldItem(name="voltage", value=voltage, unit="V", meaning="输出电压"))
            if len(body) >= 20:
                current = read_u16_le(body, 18) / 10.0
                items.append(FieldItem(name="current", value=current, unit="A", meaning="输出电流"))
            return items

        # 远程启机回复 0x26
        if frame_type == 0x26 and len(body) >= 9:
            items.append(FieldItem(name="txn_id", value=bcd_to_str(body[0:16]) if len(body) >= 16 else to_hex(body[:16]), meaning="交易流水号"))
            if len(body) >= 24:
                items.append(FieldItem(name="pile_code", value=bcd_to_str(body[16:23]), meaning="桩编码"))
                items.append(FieldItem(name="gun_no", value=body[23], meaning="枪号"))
            if len(body) >= 25:
                result = body[24]
                items.append(FieldItem(name="start_result", value=result, meaning="成功" if result == 1 else "失败"))
            if len(body) >= 26:
                reason = body[25]
                items.append(
                    FieldItem(
                        name="fail_reason",
                        value=reason,
                        meaning=YKC_START_FAIL_REASON.get(reason, f"原因码 {reason}"),
                    )
                )
            return items

        # 交易记录 0x31
        if frame_type == 0x31 and len(body) >= 24:
            items.append(FieldItem(name="txn_id", value=bcd_to_str(body[0:16]), meaning="交易流水号"))
            items.append(FieldItem(name="pile_code", value=bcd_to_str(body[16:23]), meaning="桩编码"))
            items.append(FieldItem(name="gun_no", value=body[23], meaning="枪号"))
            if len(body) >= 44:
                # 结束原因位置因版本可能偏移，尽力读取末尾附近常见字段
                reason = body[-1]
                items.append(
                    FieldItem(
                        name="stop_reason_hint",
                        value=reason,
                        meaning=YKC_STOP_REASON.get(reason, f"结束相关码 0x{reason:02X}"),
                    )
                )
            return items

        items.append(FieldItem(name="body_hex", value=to_hex(body), meaning="未细分解析的消息体，可按帧类型扩展"))
        return items
