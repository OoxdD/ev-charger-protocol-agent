from __future__ import annotations

from typing import Any

from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.utils import to_hex

# 常见命令：低 7 位为功能码，最高位 1 表示平台下发应答/下发
_CMD_NAMES = {
    0x0C: "状态/心跳上报",
    0x8C: "状态/心跳应答",
    0x06: "远程启动充电",
    0x86: "远程启动应答",
    0x09: "实时充电数据",
    0x08: "交易账单上报",
    0x88: "交易账单确认",
    0x24: "参数/VIN 类上报",
    0xA4: "参数类应答",
    0x26: "扩展数据上报",
    0xA6: "扩展数据应答",
}


class Ascii68Parser(ProtocolParser):
    """ASCII 桩号二进制协议（68 开头，桩号为数字字符串，常见于运营平台日志）。"""

    protocol_id = ProtocolId.ASCII68
    protocol_name = "ASCII桩号协议"

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        if raw is None or len(raw) < 10 or raw[0] != 0x68:
            return 0.0
        pile = self._extract_pile(raw)
        if not pile:
            return 0.0
        score = 0.72
        cmd = raw[1]
        if cmd in _CMD_NAMES or (cmd & 0x7F) in {0x0C, 0x06, 0x09, 0x08, 0x24, 0x26}:
            score += 0.15
        if pile.isdigit() and 6 <= len(pile) <= 16:
            score += 0.1
        return min(score, 0.98)

    def parse(self, raw: bytes | None, json_obj: Any | None) -> AnalysisResult:
        if raw is None or len(raw) < 8:
            return AnalysisResult(
                protocol=self.protocol_id,
                protocol_name=self.protocol_name,
                confidence=0.0,
                valid=False,
                summary="报文过短",
                warnings=[WarningItem(code="TOO_SHORT", level="error", message="至少需要 8 字节")],
            )

        fields: list[FieldItem] = []
        warnings: list[WarningItem] = []
        fields.append(FieldItem(name="start_flag", value="0x68", offset=0, length=1, meaning="起始标志"))

        cmd = raw[1]
        cmd_name = _CMD_NAMES.get(cmd) or _CMD_NAMES.get(cmd & 0x7F) or f"命令0x{cmd:02X}"
        direction = "platform->pile" if (cmd & 0x80) else "pile->platform"
        fields.append(FieldItem(name="cmd", value=f"0x{cmd:02X}", offset=1, length=1, meaning=cmd_name))

        seq = int.from_bytes(raw[2:4], "big") if len(raw) >= 4 else 0
        fields.append(FieldItem(name="seq", value=seq, offset=2, length=2, meaning="序列号"))

        pile = self._extract_pile(raw)
        ascii_len = raw[4] if len(raw) > 4 else 0
        fields.append(FieldItem(name="pile_len", value=ascii_len, offset=4, length=1, meaning="桩号长度"))
        if pile:
            fields.append(
                FieldItem(name="pile_code", value=pile, offset=5, length=len(pile), meaning="桩编号(ASCII)")
            )
            body_start = 5 + len(pile)
        else:
            warnings.append(
                WarningItem(code="NO_PILE", level="warn", message="未识别到 ASCII 桩号")
            )
            body_start = 5

        if body_start < len(raw) - 2:
            body = raw[body_start:-2]
            fields.append(FieldItem(name="body", value=to_hex(body), offset=body_start, length=len(body), meaning="消息体"))
            # 启动应答等短体：常见首字节为结果
            if cmd in (0x86, 0x06) and body:
                fields.append(
                    FieldItem(
                        name="result",
                        value=body[0],
                        meaning="成功" if body[0] == 0 else f"结果码={body[0]}",
                    )
                )
        if len(raw) >= 2:
            fields.append(
                FieldItem(
                    name="tail",
                    value=to_hex(raw[-2:]),
                    offset=len(raw) - 2,
                    length=2,
                    meaning="帧尾校验(算法因版本而异)",
                )
            )

        summary = f"ASCII桩号协议 {cmd_name}，桩号={pile or '未知'}，序列号={seq}"
        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(raw, None),
            frame_type=f"0x{cmd:02X}",
            frame_type_name=cmd_name,
            direction=direction,
            valid=pile is not None,
            summary=summary,
            fields=fields,
            warnings=warnings,
            raw_hex=to_hex(raw),
        )

    @staticmethod
    def _extract_pile(raw: bytes) -> str | None:
        if len(raw) < 10 or raw[0] != 0x68:
            return None
        ascii_len = raw[4]
        if ascii_len < 5 or ascii_len > 32:
            return None
        end = 5 + ascii_len
        if end > len(raw) - 2:
            return None
        pile = raw[5:end]
        if not pile.isdigit():
            return None
        return pile.decode("ascii")
