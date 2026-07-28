"""蔚景科技运营服务通信协议 V2.6 解析器。"""

from __future__ import annotations

from typing import Any

from evcpa.knowledge.weijing import (
    PROTOCOL_VERSION,
    WEIJING_CHARGE_STRATEGY,
    WEIJING_CHARGE_WAY,
    WEIJING_CMDS,
    WEIJING_ENCRYPT,
    WEIJING_FIELD_LABELS,
    WEIJING_GUN_STATUS,
    WEIJING_PILE_TYPE,
    WEIJING_REMOTE_START_RESULT,
)
from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.utils import bcd_to_str, crc16_xmodem, read_u16_be, read_u32_be, to_hex


def _ascii_z(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()


def _bcd_time(data: bytes) -> str:
    s = bcd_to_str(data)
    if len(s) < 12:
        return s or to_hex(data, spaced=False)
    return f"20{s[0:2]}-{s[2:4]}-{s[4:6]} {s[6:8]}:{s[8:10]}:{s[10:12]}"


class WeijingParser(ProtocolParser):
    """蔚景科技 TCP 二进制协议（0x68 + ASCII 桩号 + CRC16-XMODEM，大端）。"""

    protocol_id = ProtocolId.WEIJING
    protocol_name = "蔚景科技"

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        if raw is None or len(raw) < 12:
            return 0.0
        if raw[0] != 0x68:
            return 0.0
        parsed = self._try_header(raw)
        if not parsed:
            return 0.0
        _, cmd, _, pile, enc, body, recv_crc, calc_crc = parsed
        score = 0.55
        if calc_crc == recv_crc:
            score = 0.86
        if cmd in WEIJING_CMDS:
            score += 0.08
        if pile and (pile.isalnum() or pile.isdigit()):
            score += 0.04
        if enc in WEIJING_ENCRYPT:
            score += 0.02
        # 与云快充互斥：蔚景头内含 ASCII 桩号
        return min(score, 1.0)

    @staticmethod
    def _try_header(
        raw: bytes,
    ) -> tuple[int, int, int, str, int, bytes, int, int] | None:
        if len(raw) < 12 or raw[0] != 0x68:
            return None
        cmd = raw[1]
        seq = read_u16_be(raw, 2)
        n = raw[4]
        if n < 1 or n > 64:
            return None
        if 5 + n + 1 + 2 + 2 > len(raw):
            return None
        pile_raw = raw[5 : 5 + n]
        # 设备编号应为可打印 ASCII（允许尾部 0x00 填充）
        printable = pile_raw.rstrip(b"\x00")
        if not printable or any(b < 0x20 or b > 0x7E for b in printable):
            return None
        pile = _ascii_z(pile_raw)
        enc_off = 5 + n
        enc = raw[enc_off]
        body_len = read_u16_be(raw, enc_off + 1)
        body_off = enc_off + 3
        if body_off + body_len + 2 != len(raw):
            # 允许粘包截断时宽松一点：至少能放下体+CRC
            if body_off + body_len + 2 > len(raw):
                return None
        body = raw[body_off : body_off + body_len]
        recv_crc = read_u16_be(raw, body_off + body_len)
        calc_crc = crc16_xmodem(raw[: body_off + body_len])
        return n, cmd, seq, pile, enc, body, recv_crc, calc_crc

    def parse(self, raw: bytes | None, json_obj: Any | None) -> AnalysisResult:
        if raw is None or len(raw) < 12:
            return AnalysisResult(
                protocol=self.protocol_id,
                protocol_name=self.protocol_name,
                confidence=0.0,
                valid=False,
                summary="报文过短，无法按蔚景帧解析",
                warnings=[WarningItem(code="TOO_SHORT", level="error", message="至少需要完整消息头+CRC")],
            )

        fields: list[FieldItem] = []
        warnings: list[WarningItem] = []

        start = raw[0]
        fields.append(
            FieldItem(name="start_flag", value=f"0x{start:02X}", offset=0, length=1, meaning="起始标志")
        )
        if start != 0x68:
            warnings.append(
                WarningItem(code="BAD_START", level="error", message=f"起始标志应为 0x68，实际 0x{start:02X}")
            )

        header = self._try_header(raw)
        if header is None:
            fields.append(FieldItem(name="body_hex", value=to_hex(raw), meaning="无法按蔚景消息头拆解"))
            return AnalysisResult(
                protocol=self.protocol_id,
                protocol_name=self.protocol_name,
                confidence=0.2,
                valid=False,
                summary="疑似蔚景帧，但消息头/长度不合法",
                fields=[self._with_label(f) for f in fields],
                warnings=[
                    WarningItem(
                        code="BAD_HEADER",
                        level="error",
                        message="设备编号长度或消息体长度与整帧不匹配",
                    )
                ],
                raw_hex=to_hex(raw),
            )

        n, cmd, seq, pile, enc, body, recv_crc, calc_crc = header
        cmd_info = WEIJING_CMDS.get(cmd)
        cmd_name = cmd_info[0] if cmd_info else f"未知命令(0x{cmd:02X})"
        direction = cmd_info[1] if cmd_info else "unknown"

        fields.append(FieldItem(name="cmd", value=f"0x{cmd:02X}", offset=1, length=1, meaning=cmd_name))
        fields.append(FieldItem(name="seq", value=seq, offset=2, length=2, meaning="消息序号"))
        fields.append(FieldItem(name="pile_code_len", value=n, offset=4, length=1, meaning="设备编号长度"))
        fields.append(FieldItem(name="pile_code", value=pile, offset=5, length=n, meaning="设备编号"))
        enc_off = 5 + n
        fields.append(
            FieldItem(
                name="encrypt_flag",
                value=enc,
                offset=enc_off,
                length=1,
                meaning=WEIJING_ENCRYPT.get(enc, f"自定义加密({enc})"),
            )
        )
        fields.append(
            FieldItem(
                name="body_len",
                value=len(body),
                offset=enc_off + 1,
                length=2,
                meaning="消息体长度",
            )
        )
        fields.append(
            FieldItem(
                name="crc16",
                value=f"0x{recv_crc:04X}",
                offset=len(raw) - 2,
                length=2,
                meaning="帧校验(CRC16-XMODEM)",
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

        body_base = enc_off + 3
        if enc != 0:
            fields.append(
                FieldItem(
                    name="body_hex",
                    value=to_hex(body, spaced=False),
                    offset=body_base,
                    length=len(body),
                    meaning="消息体已加密，明文解析需秘钥",
                )
            )
            warnings.append(
                WarningItem(
                    code="ENCRYPTED_BODY",
                    level="warn",
                    message=f"消息体为{WEIJING_ENCRYPT.get(enc, '加密')}密文，仅解析消息头",
                )
            )
        else:
            fields.extend(self._parse_body(cmd, body, body_base))
            if cmd == 0x0D:
                warnings.append(
                    WarningItem(
                        code="WEIJING_ALARM",
                        level="warn",
                        message=f"设备上报告警帧(0x0D)，体长 {len(body)} 字节",
                    )
                )

        fields = [self._with_label(f) for f in fields]
        summary = f"蔚景 {PROTOCOL_VERSION} {cmd_name}（0x{cmd:02X}），桩号={pile}，序号={seq}，消息体 {len(body)} 字节"
        if warnings:
            summary += f"；发现 {len(warnings)} 个问题"

        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(raw, None),
            frame_type=f"0x{cmd:02X}",
            frame_type_name=cmd_name,
            direction=direction,
            valid=not any(w.level == "error" for w in warnings),
            summary=summary,
            fields=fields,
            warnings=warnings,
            raw_hex=to_hex(raw),
            extras={"body_len": len(body), "weijing_version": PROTOCOL_VERSION, "pile_code": pile},
        )

    @staticmethod
    def _with_label(item: FieldItem) -> FieldItem:
        label = item.label or WEIJING_FIELD_LABELS.get(item.name)
        if not label:
            return item
        return item.model_copy(update={"label": label})

    def _need(self, body: bytes, offset: int, size: int) -> bool:
        return offset + size <= len(body)

    def _parse_body(self, cmd: int, body: bytes, base: int) -> list[FieldItem]:
        if cmd == 0x00:
            return []
        if cmd == 0x80:
            return self._parse_key_reply(body, base)
        if cmd == 0x01:
            return self._parse_login(body, base)
        if cmd == 0x81:
            return self._parse_login_ack(body, base)
        if cmd == 0x0C:
            return self._parse_heartbeat(body, base)
        if cmd == 0x8C:
            return self._parse_heartbeat_ack(body, base)
        if cmd == 0x0D:
            return self._parse_alarm(body, base)
        if cmd == 0x06:
            return self._parse_remote_start(body, base)
        if cmd == 0x86:
            return self._parse_remote_start_ack(body, base)
        if cmd == 0x07:
            return self._parse_remote_stop(body, base)
        if cmd == 0x87:
            return self._parse_remote_start_ack(body, base)  # 同结构：订单+结果
        if cmd in (0x08, 0x09):
            return self._parse_bill_or_progress(body, base)
        if cmd in WEIJING_CMDS:
            return [
                FieldItem(
                    name="body_hex",
                    value=to_hex(body, spaced=False) if body else "",
                    offset=base,
                    length=len(body),
                    meaning=f"消息体（0x{cmd:02X} 细分解析待扩展）",
                )
            ]
        return [
            FieldItem(
                name="body_hex",
                value=to_hex(body, spaced=False) if body else "",
                offset=base,
                length=len(body),
                meaning="未识别命令消息体",
            )
        ]

    def _parse_key_reply(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if not self._need(body, o, 1):
            return items
        key_len = body[o]
        items.append(FieldItem(name="key_len", value=key_len, offset=base + o, length=1, meaning="秘钥长度"))
        o += 1
        if self._need(body, o, key_len):
            items.append(
                FieldItem(
                    name="aes_key",
                    value=_ascii_z(body[o : o + key_len]),
                    offset=base + o,
                    length=key_len,
                    meaning="秘钥",
                )
            )
        return items

    def _parse_login(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 1):
            t = body[o]
            items.append(
                FieldItem(
                    name="pile_type",
                    value=t,
                    offset=base + o,
                    length=1,
                    meaning=WEIJING_PILE_TYPE.get(t, str(t)),
                )
            )
            o += 1
        if self._need(body, o, 4):
            power = read_u32_be(body, o) / 100.0
            items.append(
                FieldItem(name="rated_power", value=power, offset=base + o, length=4, unit="kW", meaning="额定功率")
            )
            o += 4
        if self._need(body, o, 1):
            items.append(FieldItem(name="gun_count", value=body[o], offset=base + o, length=1, meaning="充电枪数量"))
            o += 1
        if self._need(body, o, 4):
            items.append(FieldItem(name="fee_model_id", value=read_u32_be(body, o), offset=base + o, length=4))
            o += 4
        if self._need(body, o, 4):
            items.append(FieldItem(name="fee_model_ver", value=read_u32_be(body, o), offset=base + o, length=4))
            o += 4
        if self._need(body, o, 4):
            items.append(FieldItem(name="operator_code", value=read_u32_be(body, o), offset=base + o, length=4))
            o += 4
        if self._need(body, o, 3):
            items.append(
                FieldItem(name="password", value=bcd_to_str(body[o : o + 3]), offset=base + o, length=3, meaning="密码")
            )
            o += 3
        if self._need(body, o, 16):
            items.append(
                FieldItem(
                    name="software_ver",
                    value=_ascii_z(body[o : o + 16]),
                    offset=base + o,
                    length=16,
                    meaning="软件版本",
                )
            )
            o += 16
        if self._need(body, o, 16):
            items.append(
                FieldItem(
                    name="hardware_ver",
                    value=_ascii_z(body[o : o + 16]),
                    offset=base + o,
                    length=16,
                    meaning="硬件版本",
                )
            )
            o += 16
        if self._need(body, o, 8):
            items.append(
                FieldItem(
                    name="comm_protocol_ver",
                    value=_ascii_z(body[o : o + 8]),
                    offset=base + o,
                    length=8,
                    meaning="通信协议版本",
                )
            )
        return items

    def _parse_login_ack(self, body: bytes, base: int) -> list[FieldItem]:
        if not body:
            return []
        r = body[0]
        return [
            FieldItem(
                name="login_result",
                value=r,
                offset=base,
                length=1,
                meaning="登录成功" if r == 0 else "鉴权失败",
            )
        ]

    def _parse_heartbeat(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        if not body:
            return items
        g = body[0]
        items.append(FieldItem(name="gun_count", value=g, offset=base, length=1, meaning="充电枪数量"))
        for i in range(g):
            if 1 + i >= len(body):
                break
            st = body[1 + i]
            items.append(
                FieldItem(
                    name=f"gun_status_{i + 1}",
                    value=st,
                    offset=base + 1 + i,
                    length=1,
                    label=f"{i + 1}号枪状态",
                    meaning=WEIJING_GUN_STATUS.get(st, str(st)),
                )
            )
        return items

    def _parse_heartbeat_ack(self, body: bytes, base: int) -> list[FieldItem]:
        if len(body) < 6:
            return [FieldItem(name="body_hex", value=to_hex(body), offset=base, length=len(body))]
        return [
            FieldItem(
                name="server_time",
                value=_bcd_time(body[:6]),
                offset=base,
                length=6,
                meaning="服务器时间",
            )
        ]

    def _parse_alarm(self, body: bytes, base: int) -> list[FieldItem]:
        """0x0D 告警：优先解析枪号，其余作为告警载荷十六进制。"""
        items: list[FieldItem] = []
        if not body:
            return items
        o = 0
        if self._need(body, o, 1):
            items.append(
                FieldItem(name="gun_no", value=body[o], offset=base + o, length=1, meaning="枪号")
            )
            o += 1
        if o < len(body):
            rest = body[o:]
            items.append(
                FieldItem(
                    name="alarm_payload",
                    value=to_hex(rest, spaced=False),
                    offset=base + o,
                    length=len(rest),
                    meaning="告警内容",
                )
            )
        return items

    def _parse_remote_start(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 1):
            items.append(FieldItem(name="gun_no", value=body[o], offset=base + o, length=1, meaning="枪号"))
            o += 1
        if self._need(body, o, 1):
            way = body[o]
            items.append(
                FieldItem(
                    name="charge_strategy",
                    value=way,
                    offset=base + o,
                    length=1,
                    meaning=WEIJING_CHARGE_STRATEGY.get(way, str(way)),
                )
            )
            o += 1
        if self._need(body, o, 4):
            items.append(
                FieldItem(name="strategy_data", value=read_u32_be(body, o), offset=base + o, length=4, meaning="策略数据")
            )
            o += 4
        if self._need(body, o, 3):
            items.append(
                FieldItem(
                    name="stop_code",
                    value=bcd_to_str(body[o : o + 3]),
                    offset=base + o,
                    length=3,
                    meaning="充电停止码",
                )
            )
            o += 3
        if self._need(body, o, 16):
            items.append(
                FieldItem(
                    name="trade_no",
                    value=_ascii_z(body[o : o + 16]),
                    offset=base + o,
                    length=16,
                    meaning="订单号",
                )
            )
            o += 16
        if self._need(body, o, 4):
            bal = read_u32_be(body, o) / 100.0
            items.append(
                FieldItem(name="balance", value=bal, offset=base + o, length=4, unit="元", meaning="用户余额")
            )
        return items

    def _parse_remote_start_ack(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 16):
            items.append(
                FieldItem(
                    name="trade_no",
                    value=_ascii_z(body[o : o + 16]),
                    offset=base + o,
                    length=16,
                    meaning="订单号",
                )
            )
            o += 16
        if self._need(body, o, 1):
            r = body[o]
            items.append(
                FieldItem(
                    name="start_result",
                    value=r,
                    offset=base + o,
                    length=1,
                    meaning=WEIJING_REMOTE_START_RESULT.get(r, str(r)),
                )
            )
        return items

    def _parse_remote_stop(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 1):
            items.append(FieldItem(name="gun_no", value=body[o], offset=base + o, length=1, meaning="枪号"))
            o += 1
        if self._need(body, o, 16):
            items.append(
                FieldItem(
                    name="trade_no",
                    value=_ascii_z(body[o : o + 16]),
                    offset=base + o,
                    length=16,
                    meaning="订单号",
                )
            )
        return items

    def _parse_bill_or_progress(self, body: bytes, base: int) -> list[FieldItem]:
        """0x08 上传充电账单 / 0x09 上传充电进度。

        电量、金额及后续 DWORD 数值按协议万分位换算：15650 → 1.565。
        """
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 1):
            items.append(FieldItem(name="gun_no", value=body[o], offset=base + o, length=1, meaning="枪号"))
            o += 1
        if self._need(body, o, 16):
            items.append(
                FieldItem(
                    name="trade_no",
                    value=_ascii_z(body[o : o + 16]),
                    offset=base + o,
                    length=16,
                    meaning="订单号",
                )
            )
            o += 16
        if self._need(body, o, 1):
            way = body[o]
            items.append(
                FieldItem(
                    name="charge_way",
                    value=f"0x{way:02X}",
                    offset=base + o,
                    length=1,
                    meaning=WEIJING_CHARGE_WAY.get(way, str(way)),
                )
            )
            o += 1
        if self._need(body, o, 16):
            items.append(
                FieldItem(name="card_no", value=_ascii_z(body[o : o + 16]), offset=base + o, length=16, meaning="卡号")
            )
            o += 16
        if self._need(body, o, 17):
            items.append(
                FieldItem(name="vin", value=_ascii_z(body[o : o + 17]), offset=base + o, length=17, meaning="VIN码")
            )
            o += 17
        if self._need(body, o, 1):
            items.append(FieldItem(name="soc", value=body[o], offset=base + o, length=1, unit="%", meaning="SOC"))
            o += 1
        if self._need(body, o, 6):
            items.append(
                FieldItem(
                    name="start_time",
                    value=_bcd_time(body[o : o + 6]),
                    offset=base + o,
                    length=6,
                    meaning="开始时间",
                )
            )
            o += 6
        if self._need(body, o, 6):
            items.append(
                FieldItem(
                    name="end_time",
                    value=_bcd_time(body[o : o + 6]),
                    offset=base + o,
                    length=6,
                    meaning="结束时间",
                )
            )
            o += 6
        if not self._need(body, o, 1):
            return items
        precision = body[o]
        items.append(
            FieldItem(
                name="precision",
                value=precision,
                offset=base + o,
                length=1,
                meaning="数据精度位（解析按万分位 ÷10000）",
            )
        )
        o += 1
        # 蔚景 0x08/0x09：数值固定万分位，例 15650 → 1.565
        scale = 10000.0
        decimals = 4

        def scaled(name: str, unit: str, meaning: str) -> None:
            nonlocal o
            if not self._need(body, o, 4):
                return
            raw_v = read_u32_be(body, o)
            items.append(
                FieldItem(
                    name=name,
                    value=round(raw_v / scale, decimals),
                    offset=base + o,
                    length=4,
                    unit=unit,
                    meaning=meaning,
                )
            )
            o += 4

        scaled("charge_energy", "kWh", "充电电量")
        scaled("jian_energy", "kWh", "尖时电量")
        scaled("feng_energy", "kWh", "峰时电量")
        scaled("ping_energy", "kWh", "平时电量")
        scaled("gu_energy", "kWh", "谷时电量")
        scaled("charge_money", "元", "充电费金额")
        scaled("service_money", "元", "服务费金额")
        scaled("reserve_money", "元", "预约费金额")
        scaled("parking_money", "元", "停车费金额")
        scaled("charger_temp", "℃", "充电机温度")
        scaled("gun_temp", "℃", "枪头温度")
        scaled("input_voltage", "V", "输入电压")
        scaled("input_current", "A", "输入电流")
        scaled("output_voltage", "V", "输出电压")
        scaled("output_current", "A", "输出电流")
        scaled("need_voltage", "V", "电压需求")
        scaled("need_current", "A", "电流需求")
        return items

    def _parse_progress(self, body: bytes, base: int) -> list[FieldItem]:
        return self._parse_bill_or_progress(body, base)