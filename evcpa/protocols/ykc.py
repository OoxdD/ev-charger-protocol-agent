from __future__ import annotations

from typing import Any

from evcpa.knowledge.ykc import (
    PROTOCOL_VERSION,
    YKC_APPLY_START_WAY,
    YKC_AUTH_FAIL_REASON,
    YKC_FIELD_LABELS,
    YKC_FRAME_TYPES,
    YKC_GUN_STATUS,
    YKC_HARDWARE_FAULT_BITS,
    YKC_HOMED,
    YKC_START_FAIL_REASON,
    YKC_STOP_CMD_FAIL,
    YKC_STOP_REASON,
    YKC_TXN_FLAG,
)
from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.utils import bcd_to_str, crc16_modbus, read_u16_le, read_u32_le, to_hex


def _cp56time2a(data: bytes) -> str:
    if len(data) < 7:
        return to_hex(data)
    msec = int.from_bytes(data[0:2], "little")
    minute = data[2] & 0x3F
    hour = data[3] & 0x1F
    day = data[4] & 0x1F
    month = data[5] & 0x0F
    year = 2000 + (data[6] & 0x7F)
    sec = msec // 1000
    return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}"


def _ascii_z(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("ascii", errors="ignore")


def _vin_display(data: bytes) -> str:
    raw = data.decode("ascii", errors="ignore").strip("\x00 ")
    if not raw or set(raw) <= {"\x00", "0", "\xff", "\xFF"}:
        return "未上报"
    # 协议要求 VIN 反序上送，同时给出反序还原
    rev = raw[::-1]
    return f"{raw}（反序还原: {rev}）"


class YkcParser(ProtocolParser):
    """云快充 TCP 二进制协议（0x68 帧，按平台协议 V1.7）。"""

    protocol_id = ProtocolId.YKC
    protocol_name = "云快充"

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        if raw is None or len(raw) < 8:
            return 0.0
        if raw[0] != 0x68:
            return 0.0
        if self._looks_like_ascii_pile(raw):
            return 0.05

        data_len = raw[1]
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
            score = 0.35
        else:
            score = 0.78
        frame_type = raw[5] if len(raw) > 5 else None
        if frame_type in YKC_FRAME_TYPES:
            score += 0.12 if crc_ok else 0.05
        return min(score, 1.0)

    @staticmethod
    def _looks_like_ascii_pile(raw: bytes) -> bool:
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
                meaning="不加密" if encrypt == 0 else ("3DES" if encrypt == 1 else f"加密标志 {encrypt}"),
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
        body_base = 6

        if len(raw) >= 8:
            recv_crc = read_u16_le(raw, len(raw) - 2)
            calc_crc = crc16_modbus(raw[2:-2])
            fields.append(
                FieldItem(
                    name="crc16",
                    value=f"0x{recv_crc:04X}",
                    offset=len(raw) - 2,
                    length=2,
                    meaning="帧校验(CRC16)",
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

        body_fields = self._parse_body(frame_type, body, body_base)
        fields.extend(body_fields)
        fields = [self._with_label(f) for f in fields]

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
            extras={"body_len": len(body), "ykc_version": PROTOCOL_VERSION},
        )

    @staticmethod
    def _with_label(item: FieldItem) -> FieldItem:
        label = item.label or YKC_FIELD_LABELS.get(item.name)
        if not label:
            return item
        # meaning 若只是字段中文名，保留；若是枚举释义则原样保留
        return item.model_copy(update={"label": label})

    def _need(self, body: bytes, offset: int, size: int) -> bool:
        return offset + size <= len(body)

    def _parse_body(self, frame_type: int, body: bytes, base: int = 6) -> list[FieldItem]:
        if not body:
            return []
        handlers = {
            0x01: self._p_login,
            0x02: self._p_login_ack,
            0x03: self._p_heartbeat,
            0x04: self._p_heartbeat_ack,
            0x05: self._p_fee_verify_req,
            0x06: self._p_fee_verify_ack,
            0x12: self._p_read_realtime,
            0x13: self._p_realtime,
            0x31: self._p_apply_start,
            0x32: self._p_confirm_start,
            0x33: self._p_remote_start_ack,
            0x34: self._p_remote_start,
            0x35: self._p_remote_stop_ack,
            0x36: self._p_remote_stop,
            0x3B: self._p_trade_record,
            0x3D: self._p_trade_record,
            0x40: self._p_trade_ack,
            0x42: self._p_balance_update,
        }
        fn = handlers.get(frame_type)
        if fn is None:
            return [
                FieldItem(
                    name="body_hex",
                    value=to_hex(body),
                    offset=base,
                    length=len(body),
                    meaning=f"消息体（0x{frame_type:02X} 细分解析待扩展）",
                )
            ]
        return fn(body, base)

    def _p_login(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if not self._need(body, o, 7):
            return items
        items.append(FieldItem(name="pile_code", value=bcd_to_str(body[o : o + 7]), offset=base + o, length=7, meaning="桩编码"))
        o += 7
        if self._need(body, o, 1):
            items.append(
                FieldItem(
                    name="pile_type",
                    value=body[o],
                    offset=base + o,
                    length=1,
                    meaning="直流桩" if body[o] == 0 else ("交流桩" if body[o] == 1 else f"类型{body[o]}"),
                )
            )
            o += 1
        if self._need(body, o, 1):
            items.append(FieldItem(name="gun_count", value=body[o], offset=base + o, length=1, meaning="充电枪数量"))
            o += 1
        if self._need(body, o, 1):
            ver = body[o] / 10.0
            items.append(FieldItem(name="comm_protocol_ver", value=body[o], offset=base + o, length=1, meaning=f"通信协议版本 v{ver:.1f}"))
            o += 1
        if self._need(body, o, 8):
            items.append(FieldItem(name="software_ver", value=_ascii_z(body[o : o + 8]), offset=base + o, length=8, meaning="程序版本"))
            o += 8
        if self._need(body, o, 1):
            net = {0: "SIM卡", 1: "LAN", 2: "WAN", 3: "其他"}.get(body[o], str(body[o]))
            items.append(FieldItem(name="network_type", value=body[o], offset=base + o, length=1, meaning=net))
            o += 1
        if self._need(body, o, 10):
            items.append(FieldItem(name="sim", value=bcd_to_str(body[o : o + 10]), offset=base + o, length=10, meaning="SIM 卡号"))
            o += 10
        if self._need(body, o, 1):
            op = {0: "移动", 2: "电信", 3: "联通", 4: "其他"}.get(body[o], str(body[o]))
            items.append(FieldItem(name="operator", value=body[o], offset=base + o, length=1, meaning=op))
        return items

    def _p_login_ack(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 7):
            items.append(FieldItem(name="pile_code", value=bcd_to_str(body[o : o + 7]), offset=base + o, length=7, meaning="桩编码"))
            o += 7
        if self._need(body, o, 1):
            items.append(
                FieldItem(
                    name="login_result",
                    value=body[o],
                    offset=base + o,
                    length=1,
                    meaning="登陆成功" if body[o] == 0 else "登陆失败",
                )
            )
        return items

    def _p_heartbeat(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 7):
            items.append(FieldItem(name="pile_code", value=bcd_to_str(body[o : o + 7]), offset=base + o, length=7, meaning="桩编码"))
            o += 7
        if self._need(body, o, 1):
            items.append(FieldItem(name="gun_no", value=body[o], offset=base + o, length=1, meaning="枪号"))
            o += 1
        if self._need(body, o, 1):
            items.append(
                FieldItem(
                    name="gun_status",
                    value=body[o],
                    offset=base + o,
                    length=1,
                    meaning="正常" if body[o] == 0 else ("故障" if body[o] == 1 else str(body[o])),
                )
            )
        return items

    def _p_heartbeat_ack(self, body: bytes, base: int) -> list[FieldItem]:
        return self._p_heartbeat(body, base)

    def _p_fee_verify_req(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 7):
            items.append(FieldItem(name="pile_code", value=bcd_to_str(body[o : o + 7]), offset=base + o, length=7, meaning="桩编号"))
            o += 7
        if self._need(body, o, 2):
            items.append(FieldItem(name="fee_model_no", value=bcd_to_str(body[o : o + 2]), offset=base + o, length=2, meaning="计费模型编号"))
        return items

    def _p_fee_verify_ack(self, body: bytes, base: int) -> list[FieldItem]:
        items = self._p_fee_verify_req(body, base)
        o = 9
        if self._need(body, o, 1):
            items.append(
                FieldItem(
                    name="verify_result",
                    value=body[o],
                    offset=base + o,
                    length=1,
                    meaning="一致" if body[o] == 0 else "不一致",
                )
            )
        return items

    def _p_read_realtime(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 7):
            items.append(FieldItem(name="pile_code", value=bcd_to_str(body[o : o + 7]), offset=base + o, length=7, meaning="桩编号"))
            o += 7
        if self._need(body, o, 1):
            items.append(FieldItem(name="gun_no", value=body[o], offset=base + o, length=1, meaning="枪号"))
        return items

    def _p_realtime(self, body: bytes, base: int) -> list[FieldItem]:
        """V1.7 0x13 完整字段；短报文做兼容尽力解析。"""
        items: list[FieldItem] = []
        # V1.7 标准体长 60
        if len(body) >= 60:
            o = 0
            items.append(FieldItem(name="trade_no", value=bcd_to_str(body[o : o + 16]), offset=base + o, length=16, meaning="交易流水号"))
            o += 16
            items.append(FieldItem(name="pile_code", value=bcd_to_str(body[o : o + 7]), offset=base + o, length=7, meaning="桩编号"))
            o += 7
            items.append(FieldItem(name="gun_no", value=body[o], offset=base + o, length=1, meaning="枪号"))
            o += 1
            st = body[o]
            items.append(FieldItem(name="status", value=st, offset=base + o, length=1, meaning=YKC_GUN_STATUS.get(st, str(st))))
            o += 1
            hm = body[o]
            items.append(FieldItem(name="gun_homed", value=hm, offset=base + o, length=1, meaning=YKC_HOMED.get(hm, str(hm))))
            o += 1
            pg = body[o]
            items.append(FieldItem(name="gun_plugged", value=pg, offset=base + o, length=1, meaning="是" if pg == 1 else "否"))
            o += 1
            volt = read_u16_le(body, o) / 10.0
            items.append(FieldItem(name="output_voltage", value=volt, offset=base + o, length=2, unit="V", meaning="输出电压"))
            o += 2
            curr = read_u16_le(body, o) / 10.0
            items.append(FieldItem(name="output_current", value=curr, offset=base + o, length=2, unit="A", meaning="输出电流"))
            o += 2
            items.append(
                FieldItem(
                    name="output_power",
                    value=round(volt * curr / 1000.0, 3),
                    unit="kW",
                    meaning="输出功率(电压×电流)",
                )
            )
            gun_t = body[o] - 50
            items.append(FieldItem(name="gun_cable_temp", value=gun_t, offset=base + o, length=1, unit="℃", meaning="枪线温度"))
            o += 1
            items.append(FieldItem(name="gun_cable_code", value=to_hex(body[o : o + 8], spaced=False), offset=base + o, length=8, meaning="枪线编码"))
            o += 8
            items.append(FieldItem(name="soc", value=body[o], offset=base + o, length=1, unit="%", meaning="SOC"))
            o += 1
            batt_t = body[o] - 50
            items.append(FieldItem(name="battery_max_temp", value=batt_t, offset=base + o, length=1, unit="℃", meaning="电池组最高温度"))
            o += 1
            items.append(FieldItem(name="charge_time_min", value=read_u16_le(body, o), offset=base + o, length=2, unit="min", meaning="累计充电时间"))
            o += 2
            items.append(FieldItem(name="remain_time_min", value=read_u16_le(body, o), offset=base + o, length=2, unit="min", meaning="剩余时间"))
            o += 2
            energy = read_u32_le(body, o) / 10000.0
            items.append(FieldItem(name="charge_energy", value=energy, offset=base + o, length=4, unit="kWh", meaning="充电度数"))
            o += 4
            loss = read_u32_le(body, o) / 10000.0
            items.append(FieldItem(name="loss_energy", value=loss, offset=base + o, length=4, unit="kWh", meaning="计损充电度数"))
            o += 4
            money = read_u32_le(body, o) / 10000.0
            items.append(FieldItem(name="charged_amount", value=money, offset=base + o, length=4, unit="元", meaning="已充金额"))
            o += 4
            fault = read_u16_le(body, o)
            bits = [YKC_HARDWARE_FAULT_BITS[i] for i in range(16) if (fault >> i) & 1 and i in YKC_HARDWARE_FAULT_BITS]
            items.append(
                FieldItem(
                    name="hardware_fault",
                    value=f"0x{fault:04X}",
                    offset=base + o,
                    length=2,
                    meaning=("无" if fault == 0 else "；".join(bits)) or f"故障码 0x{fault:04X}",
                )
            )
            return items

        # 短帧兼容：旧示例/截断
        o = 0
        if self._need(body, o, 7):
            items.append(FieldItem(name="pile_code", value=bcd_to_str(body[o : o + 7]), offset=base + o, length=7, meaning="桩编号(兼容短帧)"))
            o += 7
        if self._need(body, o, 1):
            items.append(FieldItem(name="gun_no", value=body[o], offset=base + o, length=1, meaning="枪号"))
            o += 1
        if self._need(body, o, 1):
            st = body[o]
            items.append(FieldItem(name="status", value=st, offset=base + o, length=1, meaning=YKC_GUN_STATUS.get(st, str(st))))
            o += 1
        items.append(
            FieldItem(
                name="body_hex",
                value=to_hex(body),
                offset=base,
                length=len(body),
                meaning=f"体长 {len(body)} 非 V1.7 标准 60 字节，已尽力解析",
            )
        )
        return items

    def _p_apply_start(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 7):
            items.append(FieldItem(name="pile_code", value=bcd_to_str(body[o : o + 7]), offset=base + o, length=7, meaning="桩编号"))
            o += 7
        if self._need(body, o, 1):
            items.append(FieldItem(name="gun_no", value=body[o], offset=base + o, length=1, meaning="枪号"))
            o += 1
        if self._need(body, o, 1):
            way = body[o]
            items.append(FieldItem(name="start_way", value=way, offset=base + o, length=1, meaning=YKC_APPLY_START_WAY.get(way, str(way))))
            o += 1
        if self._need(body, o, 1):
            items.append(FieldItem(name="need_password", value=body[o], offset=base + o, length=1, meaning="需要" if body[o] == 1 else "不需要"))
            o += 1
        if self._need(body, o, 8):
            items.append(FieldItem(name="account_or_card", value=to_hex(body[o : o + 8], spaced=False), offset=base + o, length=8, meaning="账号/物理卡号"))
            o += 8
        if self._need(body, o, 16):
            items.append(FieldItem(name="password_md5", value=to_hex(body[o : o + 16], spaced=False), offset=base + o, length=16, meaning="密码 MD5"))
            o += 16
        if self._need(body, o, 17):
            items.append(FieldItem(name="vin", value=_vin_display(body[o : o + 17]), offset=base + o, length=17, meaning="VIN 码"))
        return items

    def _p_confirm_start(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 16):
            items.append(FieldItem(name="trade_no", value=bcd_to_str(body[o : o + 16]), offset=base + o, length=16, meaning="交易流水号"))
            o += 16
        if self._need(body, o, 7):
            items.append(FieldItem(name="pile_code", value=bcd_to_str(body[o : o + 7]), offset=base + o, length=7, meaning="桩编号"))
            o += 7
        if self._need(body, o, 1):
            items.append(FieldItem(name="gun_no", value=body[o], offset=base + o, length=1, meaning="枪号"))
            o += 1
        if self._need(body, o, 8):
            items.append(FieldItem(name="logic_card", value=bcd_to_str(body[o : o + 8]), offset=base + o, length=8, meaning="逻辑卡号"))
            o += 8
        if self._need(body, o, 4):
            bal = read_u32_le(body, o) / 100.0
            items.append(FieldItem(name="balance", value=bal, offset=base + o, length=4, unit="元", meaning="账户余额"))
            o += 4
        if self._need(body, o, 1):
            items.append(FieldItem(name="auth_ok", value=body[o], offset=base + o, length=1, meaning="成功" if body[o] == 1 else "失败"))
            o += 1
        if self._need(body, o, 1):
            r = body[o]
            items.append(FieldItem(name="auth_fail_reason", value=r, offset=base + o, length=1, meaning=YKC_AUTH_FAIL_REASON.get(r, f"原因 {r}")))
        return items

    def _p_remote_start(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 16):
            items.append(FieldItem(name="trade_no", value=bcd_to_str(body[o : o + 16]), offset=base + o, length=16, meaning="交易流水号"))
            o += 16
        if self._need(body, o, 7):
            items.append(FieldItem(name="pile_code", value=bcd_to_str(body[o : o + 7]), offset=base + o, length=7, meaning="桩编号"))
            o += 7
        if self._need(body, o, 1):
            items.append(FieldItem(name="gun_no", value=body[o], offset=base + o, length=1, meaning="枪号"))
            o += 1
        if self._need(body, o, 8):
            items.append(FieldItem(name="logic_card", value=bcd_to_str(body[o : o + 8]), offset=base + o, length=8, meaning="逻辑卡号"))
            o += 8
        if self._need(body, o, 8):
            items.append(FieldItem(name="physical_card", value=to_hex(body[o : o + 8], spaced=False), offset=base + o, length=8, meaning="物理卡号"))
            o += 8
        if self._need(body, o, 4):
            bal = read_u32_le(body, o) / 100.0
            items.append(FieldItem(name="balance", value=bal, offset=base + o, length=4, unit="元", meaning="账户余额"))
        return items

    def _p_remote_start_ack(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        # 文档：流水号16 + 桩7 + 枪1 + 结果1 + 原因1
        if self._need(body, o, 16):
            items.append(FieldItem(name="trade_no", value=bcd_to_str(body[o : o + 16]), offset=base + o, length=16, meaning="交易流水号"))
            o += 16
        if self._need(body, o, 7):
            items.append(FieldItem(name="pile_code", value=bcd_to_str(body[o : o + 7]), offset=base + o, length=7, meaning="桩编号"))
            o += 7
        if self._need(body, o, 1):
            items.append(FieldItem(name="gun_no", value=body[o], offset=base + o, length=1, meaning="枪号"))
            o += 1
        if self._need(body, o, 1):
            items.append(FieldItem(name="start_result", value=body[o], offset=base + o, length=1, meaning="成功" if body[o] == 1 else "失败"))
            o += 1
        if self._need(body, o, 1):
            r = body[o]
            items.append(FieldItem(name="fail_reason", value=r, offset=base + o, length=1, meaning=YKC_START_FAIL_REASON.get(r, f"原因 {r}")))
        return items

    def _p_remote_stop(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 7):
            items.append(FieldItem(name="pile_code", value=bcd_to_str(body[o : o + 7]), offset=base + o, length=7, meaning="桩编号"))
            o += 7
        if self._need(body, o, 1):
            items.append(FieldItem(name="gun_no", value=body[o], offset=base + o, length=1, meaning="枪号"))
        return items

    def _p_remote_stop_ack(self, body: bytes, base: int) -> list[FieldItem]:
        items = self._p_remote_stop(body, base)
        o = 8
        if self._need(body, o, 1):
            items.append(FieldItem(name="stop_result", value=body[o], offset=base + o, length=1, meaning="成功" if body[o] == 1 else "失败"))
            o += 1
        if self._need(body, o, 1):
            r = body[o]
            items.append(FieldItem(name="fail_reason", value=r, offset=base + o, length=1, meaning=YKC_STOP_CMD_FAIL.get(r, f"原因 {r}")))
        return items

    def _p_trade_ack(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 16):
            items.append(FieldItem(name="trade_no", value=bcd_to_str(body[o : o + 16]), offset=base + o, length=16, meaning="交易流水号"))
            o += 16
        if self._need(body, o, 1):
            items.append(
                FieldItem(
                    name="confirm_result",
                    value=body[o],
                    offset=base + o,
                    length=1,
                    meaning="上传成功" if body[o] == 0 else "非法账单",
                )
            )
        return items

    def _p_balance_update(self, body: bytes, base: int) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 7):
            items.append(FieldItem(name="pile_code", value=bcd_to_str(body[o : o + 7]), offset=base + o, length=7, meaning="桩编号"))
            o += 7
        if self._need(body, o, 1):
            items.append(FieldItem(name="gun_no", value=body[o], offset=base + o, length=1, meaning="枪号"))
            o += 1
        if self._need(body, o, 8):
            items.append(FieldItem(name="physical_card", value=to_hex(body[o : o + 8], spaced=False), offset=base + o, length=8, meaning="物理卡号"))
            o += 8
        if self._need(body, o, 4):
            bal = read_u32_le(body, o) / 100.0
            items.append(FieldItem(name="balance", value=bal, offset=base + o, length=4, unit="元", meaning="修改后账户金额"))
        return items

    def _p_trade_record(self, body: bytes, base: int) -> list[FieldItem]:
        """V1.7 0x3D 交易记录完整字段（体长约 201）。"""
        items: list[FieldItem] = []
        o = 0

        def take(n: int) -> bytes | None:
            nonlocal o
            if not self._need(body, o, n):
                return None
            chunk = body[o : o + n]
            o += n
            return chunk

        def add(name: str, value: Any, length: int, meaning: str, unit: str | None = None, start: int | None = None) -> None:
            items.append(
                FieldItem(
                    name=name,
                    value=value,
                    offset=(base + (start if start is not None else o - length)),
                    length=length,
                    unit=unit,
                    meaning=meaning,
                )
            )

        b = take(16)
        if b is None:
            return items
        add("trade_no", bcd_to_str(b), 16, "交易流水号")
        b = take(7)
        if b is None:
            return items
        add("pile_code", bcd_to_str(b), 7, "桩编号")
        b = take(1)
        if b is None:
            return items
        add("gun_no", b[0], 1, "枪号")
        b = take(7)
        if b is None:
            return items
        add("start_time", _cp56time2a(b), 7, "开始时间")
        b = take(7)
        if b is None:
            return items
        add("end_time", _cp56time2a(b), 7, "结束时间")
        b = take(6)
        if b is None:
            return items
        add("meter_no", to_hex(b, spaced=False), 6, "电表表号")
        b = take(34)
        if b is None:
            return items
        add("meter_cipher", to_hex(b, spaced=False), 34, "电表密文")
        b = take(2)
        if b is None:
            return items
        add("meter_proto_ver", read_u16_le(b, 0), 2, "电表协议版本号")
        b = take(1)
        if b is None:
            return items
        add("encrypt_type", b[0], 1, "加密标记")

        for prefix, label in (("jian", "尖"), ("feng", "峰"), ("ping", "平"), ("gu", "谷")):
            b = take(4)
            if b is None:
                return items
            add(f"{prefix}_price", read_u32_le(b, 0) / 100000.0, 4, f"{label}单价", "元/kWh")
            b = take(4)
            if b is None:
                return items
            add(f"{prefix}_energy", read_u32_le(b, 0) / 10000.0, 4, f"{label}电量", "kWh")
            b = take(4)
            if b is None:
                return items
            add(f"{prefix}_loss_energy", read_u32_le(b, 0) / 10000.0, 4, f"计损{label}电量", "kWh")
            b = take(4)
            if b is None:
                return items
            add(f"{prefix}_money", read_u32_le(b, 0) / 10000.0, 4, f"{label}金额", "元")

        b = take(5)
        if b is None:
            return items
        # 5 字节电表起止值，按小端整数 /10000
        meter_start = int.from_bytes(b, "little") / 10000.0
        add("meter_start", meter_start, 5, "电表总起值", "kWh")
        b = take(5)
        if b is None:
            return items
        meter_end = int.from_bytes(b, "little") / 10000.0
        add("meter_end", meter_end, 5, "电表总止值", "kWh")

        b = take(4)
        if b is None:
            return items
        add("total_energy", read_u32_le(b, 0) / 10000.0, 4, "总电量", "kWh")
        b = take(4)
        if b is None:
            return items
        add("total_loss_energy", read_u32_le(b, 0) / 10000.0, 4, "计损总电量", "kWh")
        b = take(4)
        if b is None:
            return items
        add("total_money", read_u32_le(b, 0) / 10000.0, 4, "消费金额", "元")
        b = take(17)
        if b is None:
            return items
        add("vin", _vin_display(b), 17, "VIN 码")
        b = take(1)
        if b is None:
            return items
        add("txn_flag", b[0], 1, YKC_TXN_FLAG.get(b[0], f"交易标识 {b[0]}"))
        b = take(7)
        if b is None:
            return items
        add("txn_time", _cp56time2a(b), 7, "交易日期时间")
        b = take(1)
        if b is None:
            return items
        add("stop_reason", b[0], 1, YKC_STOP_REASON.get(b[0], f"停止原因 0x{b[0]:02X}"))
        b = take(8)
        if b is None:
            return items
        add("physical_card", to_hex(b, spaced=False), 8, "物理卡号")

        if o < len(body):
            add("body_tail", to_hex(body[o:]), len(body) - o, "未识别尾部字节")
        return items
