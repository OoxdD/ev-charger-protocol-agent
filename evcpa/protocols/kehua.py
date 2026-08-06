"""科华充电桩与云平台通信协议 V4.09 解析。"""

from __future__ import annotations

from typing import Any

from evcpa.knowledge.kehua import (
    KH_ACTIVE_UNITS,
    KH_CARD_TYPE,
    KH_CAR_LINK,
    KH_CHARGE_MODE,
    KH_CHARGE_WAY,
    KH_CMD_NAMES,
    KH_FIELD_LABELS,
    KH_GUN_STATUS,
    KH_HEADER_LEN,
    KH_LOGIN_ACK,
    KH_MAGIC,
    KH_PROTOCOL_VERSION,
    KH_RT_UNITS,
    KH_START_STOP_OP,
    KH_START_STRATEGY,
    KH_TAIL,
)
from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.utils import bcd_to_str, crc16_modbus, read_u16_be, read_u32_be, to_hex


_KH_JSON_KEYS = {
    "kehua",
    "KH",
    "moduleId",
    "dcVoltage",
    "dcCurrent",
    "moduleStatus",
    "pduId",
    "kehuadata",
}


def _ascii_z(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()


def _bcd_time(data: bytes) -> str:
    if len(data) < 7:
        return to_hex(data)
    s = bcd_to_str(data[:7])
    if len(s) >= 14 and s[:14].isdigit():
        return f"{s[0:4]}-{s[4:6]}-{s[6:8]} {s[8:10]}:{s[10:12]}:{s[12:14]}"
    return to_hex(data)


def _scaled_int(raw: bytes, scale: float) -> float | int:
    if len(raw) == 1:
        v = raw[0]
    elif len(raw) == 2:
        v = read_u16_be(raw, 0)
    elif len(raw) >= 4:
        v = read_u32_be(raw, 0)
    else:
        v = int.from_bytes(raw, "big")
    if scale == 1.0:
        return v
    # 避免浮点噪声
    prec = 1 if scale >= 0.1 else (2 if scale >= 0.01 else 4)
    return round(v * scale, prec)


def _temp_offset(raw: bytes, scale: float = 0.1) -> float:
    """温度：数值×scale 后减 50℃。"""
    v = _scaled_int(raw, scale)
    return round(float(v) - 50.0, 1)


def _field(
    name: str,
    value: Any,
    *,
    offset: int | None = None,
    length: int | None = None,
    unit: str | None = None,
    meaning: str | None = None,
) -> FieldItem:
    return FieldItem(
        name=name,
        value=value,
        offset=offset,
        length=length,
        unit=unit,
        label=KH_FIELD_LABELS.get(name),
        meaning=meaning,
    )


def _parse_tlv_units(
    payload: bytes,
    *,
    base_offset: int,
    table: str = "realtime",
) -> list[FieldItem]:
    """解析 个数 + (标识2 + 长度1 + 值N)*。"""
    fields: list[FieldItem] = []
    if not payload:
        return fields
    count = payload[0]
    fields.append(
        _field("tlv_count", count, offset=base_offset, length=1, meaning="数据单元个数")
    )
    off = 1
    for i in range(count):
        if off + 3 > len(payload):
            break
        uid = read_u16_be(payload, off)
        ulen = payload[off + 2]
        val = payload[off + 3 : off + 3 + ulen]
        if len(val) < ulen:
            break
        name = f"unit_{uid:04X}"
        label = None
        meaning = None
        unit = None
        decoded: Any = to_hex(val)

        if table == "realtime" and uid in KH_RT_UNITS:
            name, label, scale = KH_RT_UNITS[uid]
            if name == "vin":
                decoded = _ascii_z(val) or "-"
            elif name == "card_type" and val:
                decoded = val[0]
                meaning = KH_CARD_TYPE.get(decoded)
            elif name == "charge_discharge" and val:
                decoded = val[0]
                meaning = "充电" if decoded == 0 else ("放电" if decoded == 1 else None)
            elif name in {"gun_dc_pos_temp", "gun_dc_neg_temp", "batt_temp_max", "batt_temp_min"}:
                decoded = _temp_offset(val, scale or 0.1)
                unit = "℃"
            elif scale is None:
                if len(val) == 1:
                    decoded = val[0]
                elif len(val) == 2:
                    decoded = read_u16_be(val, 0)
                elif len(val) >= 4:
                    decoded = read_u32_be(val, 0)
                if name == "soc":
                    unit = "%"
                elif name == "session_id":
                    meaning = f"0x{int(decoded):08X}" if isinstance(decoded, int) else None
            else:
                decoded = _scaled_int(val, scale)
                if "voltage" in name:
                    unit = "V"
                elif "current" in name or name == "leak_current":
                    unit = "A" if name != "leak_current" else "mA"
                elif "energy" in name or name == "meter_kwh":
                    unit = "kWh"
                elif "amount" in name or "fee" in name:
                    unit = "元"
                elif "power" in name:
                    unit = "kW"
                elif name == "charge_duration":
                    unit = "秒"
                elif name == "remain_minutes":
                    unit = "分钟"
        elif table == "active" and uid in KH_ACTIVE_UNITS:
            name, label = KH_ACTIVE_UNITS[uid]
            if name in {"card_no", "vin", "plate_no"}:
                decoded = _ascii_z(val) or "-"
            elif name == "start_time":
                decoded = _bcd_time(val)
            elif name == "gun_status" and val:
                decoded = val[0]
                meaning = KH_GUN_STATUS.get(decoded)
            elif name == "car_link_status" and val:
                decoded = val[0]
                meaning = KH_CAR_LINK.get(decoded)
            elif name == "card_type" and val:
                decoded = val[0]
                meaning = KH_CARD_TYPE.get(decoded)
            elif name == "charge_mode" and val:
                decoded = val[0]
                meaning = KH_CHARGE_MODE.get(decoded)
            elif name == "start_way" and val:
                decoded = val[0]
                meaning = KH_CHARGE_WAY.get(decoded)
            elif name == "card_balance" and len(val) >= 4:
                decoded = round(read_u32_be(val, 0) * 0.01, 2)
                unit = "元"
            elif name == "meter_before" and len(val) >= 4:
                decoded = round(read_u32_be(val, 0) * 0.01, 2)
                unit = "kWh"
            elif len(val) == 1:
                decoded = val[0]
            elif len(val) == 2:
                decoded = read_u16_be(val, 0)
            elif len(val) >= 4:
                decoded = read_u32_be(val, 0)

        fields.append(
            FieldItem(
                name=name,
                value=decoded,
                offset=base_offset + off,
                length=3 + ulen,
                unit=unit,
                label=label,
                meaning=meaning or (f"单元 0x{uid:04X}" if label is None else None),
            )
        )
        off += 3 + ulen
        if i > 200:
            break
    if off < len(payload):
        rest = payload[off:]
        if rest and not all(b == 0 for b in rest):
            fields.append(
                _field(
                    "payload_rest",
                    to_hex(rest),
                    offset=base_offset + off,
                    length=len(rest),
                    meaning="未解析剩余",
                )
            )
    return fields


def _parse_login(payload: bytes, base: int) -> list[FieldItem]:
    fields: list[FieldItem] = []
    if not payload:
        return fields
    fields.append(_field("gun_count", payload[0], offset=base, length=1))
    if len(payload) >= 21:
        parent = payload[1:21]
        fields.append(
            _field(
                "parent_sn",
                "FF×20" if parent == b"\xff" * 20 else (_ascii_z(parent) or to_hex(parent)),
                offset=base + 1,
                length=20,
            )
        )
    return fields


def _parse_login_ack(payload: bytes, base: int) -> list[FieldItem]:
    fields: list[FieldItem] = []
    if not payload:
        return fields
    ack = payload[0]
    fields.append(
        _field("ack", ack, offset=base, length=1, meaning=KH_LOGIN_ACK.get(ack, f"码 {ack}"))
    )
    if len(payload) >= 8:
        fields.append(
            _field("login_time", _bcd_time(payload[1:8]), offset=base + 1, length=7)
        )
    return fields


def _parse_heartbeat(payload: bytes, base: int) -> list[FieldItem]:
    fields: list[FieldItem] = []
    if len(payload) >= 2:
        fields.append(
            _field("heartbeat_seq", read_u16_be(payload, 0), offset=base, length=2)
        )
    if len(payload) >= 3:
        fields.append(_field("reserved", payload[2], offset=base + 2, length=1))
    return fields


def _parse_ack_flag(payload: bytes, base: int) -> list[FieldItem]:
    if not payload:
        return []
    ack = payload[0]
    return [
        _field(
            "ack",
            ack,
            offset=base,
            length=1,
            meaning="成功" if ack == 1 else ("失败" if ack == 0 else f"码 {ack}"),
        )
    ]


def _parse_start_stop(payload: bytes, base: int) -> list[FieldItem]:
    fields: list[FieldItem] = []
    if len(payload) < 1:
        return fields
    op = payload[0]
    fields.append(
        _field("op_type", op, offset=base, length=1, meaning=KH_START_STOP_OP.get(op))
    )
    if len(payload) >= 2:
        fields.append(
            _field(
                "aux_voltage",
                payload[1],
                offset=base + 1,
                length=1,
                meaning="12V" if payload[1] == 0 else ("24V" if payload[1] == 1 else None),
            )
        )
    if len(payload) >= 3:
        st = payload[2]
        fields.append(
            _field("strategy", st, offset=base + 2, length=1, meaning=KH_START_STRATEGY.get(st))
        )
    if len(payload) >= 7:
        fields.append(
            _field("strategy_param", read_u32_be(payload, 3), offset=base + 3, length=4)
        )
    # 后续常见：卡号/流水等，剩余原样展示
    if len(payload) > 7:
        rest = payload[7:]
        # 尝试截取 ASCII 卡号段
        if len(rest) >= 20:
            card = _ascii_z(rest[:20])
            if card:
                fields.append(_field("card_no", card, offset=base + 7, length=20))
            if len(rest) >= 24:
                fields.append(
                    _field(
                        "session_id",
                        read_u32_be(rest, 20),
                        offset=base + 27,
                        length=4,
                        meaning=f"0x{read_u32_be(rest, 20):08X}",
                    )
                )
        else:
            fields.append(
                _field("payload_rest", to_hex(rest), offset=base + 7, length=len(rest))
            )
    return fields


def _parse_charge_record(payload: bytes, base: int) -> list[FieldItem]:
    fields: list[FieldItem] = []
    if len(payload) < 60:
        fields.append(
            _field("payload", to_hex(payload), offset=base, length=len(payload), meaning="充电记录过短")
        )
        return fields

    def take(off: int, n: int) -> bytes:
        return payload[off : off + n]

    way = payload[0]
    mode = payload[1]
    ctype = payload[2]
    fields.append(_field("charge_way", way, offset=base, length=1, meaning=KH_CHARGE_WAY.get(way)))
    fields.append(_field("charge_mode", mode, offset=base + 1, length=1, meaning=KH_CHARGE_MODE.get(mode)))
    fields.append(_field("card_type", ctype, offset=base + 2, length=1, meaning=KH_CARD_TYPE.get(ctype)))
    fields.append(_field("card_no", _ascii_z(take(3, 20)) or "-", offset=base + 3, length=20))
    vin_raw = take(23, 17)
    fields.append(
        _field(
            "vin",
            "-" if vin_raw == b"\xff" * 17 else (_ascii_z(vin_raw) or "-"),
            offset=base + 23,
            length=17,
        )
    )
    fields.append(
        _field(
            "balance_before",
            round(read_u32_be(payload, 40) * 0.01, 2),
            offset=base + 40,
            length=4,
            unit="元",
        )
    )
    fields.append(
        _field(
            "max_voltage",
            round(read_u16_be(payload, 44) * 0.1, 1),
            offset=base + 44,
            length=2,
            unit="V",
        )
    )
    fields.append(
        _field(
            "max_current",
            round(read_u16_be(payload, 46) * 0.01, 2),
            offset=base + 46,
            length=2,
            unit="A",
        )
    )
    fields.append(
        _field("charge_seconds", read_u32_be(payload, 48), offset=base + 48, length=4, unit="秒")
    )
    fields.append(
        _field(
            "energy_fee",
            round(read_u32_be(payload, 52) * 0.0001, 4),
            offset=base + 52,
            length=4,
            unit="元",
        )
    )
    fields.append(
        _field(
            "charge_energy",
            round(read_u32_be(payload, 56) * 0.01, 2),
            offset=base + 56,
            length=4,
            unit="kWh",
        )
    )
    fields.append(
        _field(
            "meter_start",
            round(read_u32_be(payload, 60) * 0.01, 2),
            offset=base + 60,
            length=4,
            unit="kWh",
        )
    )
    fields.append(
        _field(
            "meter_end",
            round(read_u32_be(payload, 64) * 0.01, 2),
            offset=base + 64,
            length=4,
            unit="kWh",
        )
    )
    fields.append(_field("soc_start", payload[68], offset=base + 68, length=1, unit="%"))
    fields.append(_field("soc_end", payload[69], offset=base + 69, length=1, unit="%"))
    paid = payload[70]
    fields.append(
        _field(
            "paid",
            paid,
            offset=base + 70,
            length=1,
            meaning="已付费" if paid == 1 else ("未结算" if paid == 0xFF else f"码 {paid}"),
        )
    )
    stop_lo = payload[71]
    duty = payload[72]
    duty_detail = payload[73]
    stop_hi = payload[74]
    stop_code = (stop_hi << 8) | stop_lo
    fields.append(
        _field(
            "stop_reason",
            stop_code,
            offset=base + 71,
            length=4,
            meaning=f"低={stop_lo} 高={stop_hi} 责任={duty}/{duty_detail}",
        )
    )
    # 预留 12 字节 @ 75
    if len(payload) >= 94:
        fields.append(_field("start_time", _bcd_time(take(87, 7)), offset=base + 87, length=7))
        fields.append(_field("end_time", _bcd_time(take(94, 7)), offset=base + 94, length=7))
    if len(payload) >= 109:
        fields.append(
            _field(
                "cell_vmax",
                round(read_u16_be(payload, 101) * 0.01, 2),
                offset=base + 101,
                length=2,
                unit="V",
            )
        )
        tmax = read_u16_be(payload, 103)
        fields.append(
            _field("cell_tmax", tmax - 50, offset=base + 103, length=2, unit="℃")
        )
        sid = read_u32_be(payload, 105)
        fields.append(
            _field("session_id", sid, offset=base + 105, length=4, meaning=f"0x{sid:08X}")
        )
        lid = read_u32_be(payload, 109)
        fields.append(
            _field(
                "local_session_id",
                lid,
                offset=base + 109,
                length=4,
                meaning=f"0x{lid:08X}",
            )
        )
    if len(payload) >= 121:
        fields.append(
            _field(
                "service_fee",
                round(read_u32_be(payload, 113) * 0.0001, 4),
                offset=base + 113,
                length=4,
                unit="元",
            )
        )
        fields.append(
            _field(
                "total_fee",
                round(read_u32_be(payload, 117) * 0.0001, 4),
                offset=base + 117,
                length=4,
                unit="元",
            )
        )
        fields.append(
            _field("tariff_ver", _ascii_z(take(121, 10)) or "-", offset=base + 121, length=10)
        )
    # 尖峰平谷电量/电费（若长度足够）
    tip_off = 131
    names = [
        ("energy_tip", "尖时段电量", 0.01, "kWh"),
        ("energy_peak", "峰时段电量", 0.01, "kWh"),
        ("energy_flat", "平时段电量", 0.01, "kWh"),
        ("energy_valley", "谷时段电量", 0.01, "kWh"),
        ("fee_tip", "尖时段电费", 0.0001, "元"),
        ("fee_peak", "峰时段电费", 0.0001, "元"),
        ("fee_flat", "平时段电费", 0.0001, "元"),
        ("fee_valley", "谷时段电费", 0.0001, "元"),
        ("svc_tip", "尖时段服务费", 0.0001, "元"),
        ("svc_peak", "峰时段服务费", 0.0001, "元"),
        ("svc_flat", "平时段服务费", 0.0001, "元"),
        ("svc_valley", "谷时段服务费", 0.0001, "元"),
    ]
    for i, (name, label, scale, unit) in enumerate(names):
        o = tip_off + i * 4
        if o + 4 > len(payload):
            break
        fields.append(
            FieldItem(
                name=name,
                value=round(read_u32_be(payload, o) * scale, 4 if scale < 0.01 else 2),
                offset=base + o,
                length=4,
                unit=unit,
                label=label,
            )
        )
    return fields


def _parse_alarm(payload: bytes, base: int) -> list[FieldItem]:
    fields: list[FieldItem] = []
    if len(payload) < 1:
        return fields
    fields.append(_field("alarm_point", payload[0], offset=base, length=1))
    if len(payload) >= 8:
        fields.append(_field("alarm_start", _bcd_time(payload[1:8]), offset=base + 1, length=7))
    if len(payload) >= 15:
        fields.append(_field("alarm_end", _bcd_time(payload[8:15]), offset=base + 8, length=7))
    if len(payload) >= 16:
        affect = payload[15]
        fields.append(
            _field(
                "affect_charge",
                affect,
                offset=base + 15,
                length=1,
                meaning="有影响" if affect == 1 else "无影响",
            )
        )
    return fields


def _parse_vin_req(payload: bytes, base: int) -> list[FieldItem]:
    if len(payload) >= 17:
        return [_field("vin", _ascii_z(payload[:17]) or "-", offset=base, length=17)]
    return [_field("payload", to_hex(payload), offset=base, length=len(payload))]


def _parse_body(func: int, payload: bytes, base: int) -> list[FieldItem]:
    if func == 0x01:
        return _parse_login(payload, base)
    if func == 0x81:
        return _parse_login_ack(payload, base)
    if func == 0x02:
        return _parse_heartbeat(payload, base)
    if func in {0x82, 0x8D, 0x90, 0x92, 0x9A, 0x9B, 0x9C, 0x9F, 0xA2, 0xA4, 0xA5, 0xB0, 0xB8}:
        return _parse_ack_flag(payload, base)
    if func in {0x0D, 0xB2}:
        return _parse_tlv_units(payload, base_offset=base, table="realtime")
    if func == 0x13:
        return _parse_tlv_units(payload, base_offset=base, table="active")
    if func == 0x0E:
        return _parse_charge_record(payload, base)
    if func == 0x0A:
        return _parse_start_stop(payload, base)
    if func == 0x0F:
        return _parse_alarm(payload, base)
    if func == 0x1D:
        return _parse_vin_req(payload, base)
    if func in {0x03, 0x83, 0x04, 0x84}:
        # 终端数据读写：TLV 风格（03 仅标识列表；83/04 含长度值）
        if func == 0x03 and payload:
            fields = [_field("tlv_count", payload[0], offset=base, length=1)]
            off = 1
            for i in range(payload[0]):
                if off + 2 > len(payload):
                    break
                uid = read_u16_be(payload, off)
                fields.append(
                    FieldItem(
                        name=f"unit_id_{i}",
                        value=f"0x{uid:04X}",
                        offset=base + off,
                        length=2,
                        label="数据单元标识",
                    )
                )
                off += 2
            return fields
        return _parse_tlv_units(payload, base_offset=base, table="realtime")
    if payload:
        return [_field("payload", to_hex(payload), offset=base, length=len(payload))]
    return []


class KehuaParser(ProtocolParser):
    protocol_id = ProtocolId.KEHUA
    protocol_name = "科华"

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        score = 0.0
        if raw and len(raw) >= KH_HEADER_LEN + 3:
            if raw[:2] == KH_MAGIC:
                score += 0.45
                total = read_u16_be(raw, 2)
                if total == len(raw) and raw[-1] == KH_TAIL:
                    score += 0.25
                    body = raw[:-3]
                    recv = read_u16_be(raw, len(raw) - 3)
                    if crc16_modbus(body) == recv:
                        score += 0.2
                    func = raw[30] if len(raw) > 30 else -1
                    if func in KH_CMD_NAMES:
                        score += 0.1
                elif raw[:2] == KH_MAGIC:
                    score += 0.05
            # 兼容旧 stub 的错误魔数，仅给极低分以免误伤
            elif raw[:2] == b"\xA5\x5A":
                score += 0.05
        if isinstance(json_obj, dict):
            keys = {str(k) for k in json_obj.keys()}
            hit = len(keys & _KH_JSON_KEYS)
            if hit:
                score = max(score, min(0.55, 0.2 + 0.1 * hit))
            blob = str(json_obj).lower()
            if "kehua" in blob or "科华" in blob:
                score = max(score, 0.4)
        return min(score, 0.99)

    def parse(self, raw: bytes | None, json_obj: Any | None) -> AnalysisResult:
        warnings: list[WarningItem] = []
        fields: list[FieldItem] = []

        if raw is None or len(raw) < KH_HEADER_LEN + 3:
            return AnalysisResult(
                protocol=self.protocol_id,
                protocol_name=self.protocol_name,
                confidence=0.0,
                valid=False,
                summary="科华报文过短或为空",
                warnings=[WarningItem(code="SHORT", level="error", message="报文长度不足")],
                extras={"protocol_version": KH_PROTOCOL_VERSION},
            )

        if raw[:2] != KH_MAGIC:
            warnings.append(
                WarningItem(code="BAD_MAGIC", level="error", message="起始帧头不是 KH(4B 48)")
            )

        total = read_u16_be(raw, 2)
        ver_raw = read_u16_be(raw, 4)
        ver = f"{ver_raw / 100:.2f}"
        seq = read_u16_be(raw, 6)
        device_type = raw[8]
        device_sn = _ascii_z(raw[9:29]) or "-"
        encrypt = raw[29]
        func = raw[30]
        device_id = read_u16_be(raw, 31)
        gun_no = raw[33]
        payload = raw[KH_HEADER_LEN : total - 3] if total >= KH_HEADER_LEN + 3 else raw[KH_HEADER_LEN:-3]
        crc_recv = read_u16_be(raw, len(raw) - 3) if len(raw) >= 3 else 0
        crc_ok = crc16_modbus(raw[:-3]) == crc_recv
        tail = raw[-1]

        if total != len(raw):
            warnings.append(
                WarningItem(
                    code="LEN_MISMATCH",
                    level="warn",
                    message=f"帧长字段 {total} 与实际 {len(raw)} 不一致",
                )
            )
        if not crc_ok:
            warnings.append(
                WarningItem(code="CRC", level="warn", message="CRC16-Modbus 校验失败")
            )
        if tail != KH_TAIL:
            warnings.append(
                WarningItem(code="BAD_TAIL", level="warn", message=f"结束字节应为 0x68，实际 0x{tail:02X}")
            )

        cmd_name = KH_CMD_NAMES.get(func, f"未知功能码 0x{func:02X}")
        fields.extend(
            [
                _field("magic", "KH", offset=0, length=2),
                _field("frame_len", total, offset=2, length=2),
                _field("protocol_ver", ver, offset=4, length=2, meaning=f"原始 0x{ver_raw:04X}"),
                _field("seq", seq, offset=6, length=2),
                _field("device_type", device_type, offset=8, length=1),
                _field("device_sn", device_sn, offset=9, length=20),
                _field("encrypt", encrypt, offset=29, length=1, meaning="不加密" if encrypt == 0 else None),
                _field("func_code", f"0x{func:02X}", offset=30, length=1, meaning=cmd_name),
                _field("device_id", device_id, offset=31, length=2),
                _field(
                    "gun_no",
                    gun_no,
                    offset=33,
                    length=1,
                    meaning="终端" if gun_no == 0 else f"枪{gun_no}",
                ),
            ]
        )
        fields.extend(_parse_body(func, payload, KH_HEADER_LEN))
        fields.append(
            _field(
                "crc",
                f"0x{crc_recv:04X}",
                offset=len(raw) - 3,
                length=2,
                meaning="通过" if crc_ok else "失败",
            )
        )
        fields.append(_field("tail", f"0x{tail:02X}", offset=len(raw) - 1, length=1))

        conf = self.detect_score(raw, json_obj)
        summary = f"科华 {cmd_name}（0x{func:02X}）· 桩 {device_sn} · 枪 {gun_no}"
        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=conf,
            frame_type=f"0x{func:02X}",
            frame_type_name=cmd_name,
            valid=raw[:2] == KH_MAGIC and (crc_ok or conf >= 0.6),
            summary=summary,
            fields=fields,
            warnings=warnings,
            raw_hex=to_hex(raw),
            extras={"protocol_version": KH_PROTOCOL_VERSION},
        )
