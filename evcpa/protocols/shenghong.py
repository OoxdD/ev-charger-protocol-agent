"""盛弘充电桩与后台服务器通信协议 V5.2B 解析。"""

from __future__ import annotations

from typing import Any

from evcpa.knowledge.alarms import VENDOR_STATUS_MAP
from evcpa.knowledge.shenghong import (
    SH_CHARGE_WAY,
    SH_CMD_NAMES,
    SH_CMD102_FIELDS,
    SH_CMD104_FIELDS,
    SH_CMD106_FIELDS,
    SH_CMD202_FIELDS,
    SH_FIELD_LABELS,
    SH_GUN_TYPE,
    SH_PROTOCOL_VERSION,
    SH_STOP_STRATEGY,
    SH_WORK_STATUS,
    SH_CAR_LINK,
)
from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.utils import bcd_to_str, read_u16_le, read_u32_le, to_hex


_SH_JSON_KEYS = {
    "pileSn",
    "gunNo",
    "shCode",
    "shenghong",
    "meterValue",
    "chargeEnergy",
    "soc",
    "workStatus",
}


def _ascii_z(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()


def _bcd_time(data: bytes) -> str:
    """8 字节 BCD 标准时间 → 可读串。"""
    if len(data) < 7:
        return to_hex(data)
    s = bcd_to_str(data[:7])
    # 常见 YYYYMMDDhhmmss
    if len(s) >= 14 and s[:14].isdigit():
        return f"{s[0:4]}-{s[4:6]}-{s[6:8]} {s[8:10]}:{s[10:12]}:{s[12:14]}"
    if len(s) >= 12 and s[:12].isdigit():
        return f"20{s[0:2]}-{s[2:4]}-{s[4:6]} {s[6:8]}:{s[8:10]}:{s[10:12]}"
    return to_hex(data)


def _checksum_ok(cmd: int, body: bytes, recv: int) -> bool:
    total = (cmd & 0xFF) + ((cmd >> 8) & 0xFF) + sum(body)
    return (total & 0xFF) == (recv & 0xFF)


def _decode_field(kind: str, raw: bytes) -> Any:
    if kind == "ascii":
        return _ascii_z(raw) or "-"
    if kind == "hex":
        return to_hex(raw)
    if kind == "skip":
        return None
    if kind == "bcd_time":
        return _bcd_time(raw)
    if kind == "u8":
        return raw[0]
    if kind == "u16":
        return read_u16_le(raw, 0)
    if kind == "u32":
        return read_u32_le(raw, 0)
    if kind == "volt":
        return round(read_u16_le(raw, 0) * 0.1, 1)
    if kind == "curr":
        v = int.from_bytes(raw[:2], "little", signed=True)
        return round(v * 0.1, 1)
    if kind == "energy01":
        return round(read_u32_le(raw, 0) * 0.01, 3)
    if kind == "money":
        return round(read_u32_le(raw, 0) * 0.01, 2)
    if kind == "power01":
        return round(read_u32_le(raw, 0) * 0.1, 2)
    if kind == "temp":
        return int(raw[0]) - 50
    return to_hex(raw)


def _meaning_for(name: str, value: Any) -> str | None:
    if name == "work_status" and isinstance(value, int):
        return SH_WORK_STATUS.get(value)
    if name == "gun_type" and isinstance(value, int):
        return SH_GUN_TYPE.get(value & 0x03) or SH_GUN_TYPE.get(value)
    if name == "start_way" and isinstance(value, int):
        return SH_CHARGE_WAY.get(value)
    if name == "stop_strategy" and isinstance(value, int):
        return SH_STOP_STRATEGY.get(value)
    if name == "car_link_status" and isinstance(value, int):
        return SH_CAR_LINK.get(value)
    if name == "gun_pos_type" and isinstance(value, int):
        return SH_GUN_TYPE.get(value)
    if name == "encrypt_support" and isinstance(value, int):
        return "支持 AES 加密" if value == 1 else "不支持加密"
    return None


def _walk_fields(
    body: bytes,
    layout: list[tuple[str, int, str]],
    *,
    base_offset: int,
) -> list[FieldItem]:
    fields: list[FieldItem] = []
    o = 0
    for name, size, kind in layout:
        if o + size > len(body):
            break
        chunk = body[o : o + size]
        val = _decode_field(kind, chunk)
        o += size
        if val is None:
            continue
        label = SH_FIELD_LABELS.get(name, name)
        meaning = _meaning_for(name, val)
        disp = f"{val} 元" if kind == "money" and isinstance(val, (int, float)) else val
        if kind == "energy01" and isinstance(val, (int, float)):
            disp = f"{val} kWh"
        if kind == "volt" and isinstance(val, (int, float)):
            disp = f"{val} V"
        if kind == "curr" and isinstance(val, (int, float)):
            disp = f"{val} A"
        if kind == "power01" and isinstance(val, (int, float)):
            disp = f"{val} kW"
        fields.append(
            FieldItem(
                name=name,
                value=disp,
                offset=base_offset + o - size,
                length=size,
                meaning=meaning or label,
            )
        )
    if o < len(body):
        fields.append(
            FieldItem(
                name="payload_rest",
                value=to_hex(body[o:]),
                offset=base_offset + o,
                length=len(body) - o,
                meaning="未映射载荷",
            )
        )
    return fields


class ShenghongParser(ProtocolParser):
    """盛弘 V5.2B：起始 AA F5 + 小端长度 + CMD(2) + 累计和校验。"""

    protocol_id = ProtocolId.SHENGHONG
    protocol_name = "盛弘"

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        if isinstance(json_obj, dict):
            keys = {str(k).lower() for k in json_obj.keys()}
            hit = len(keys & {k.lower() for k in _SH_JSON_KEYS})
            score = min(0.2 + hit * 0.15, 0.85)
            blob = str(json_obj).lower()
            if "shenghong" in blob or "盛弘" in blob or "盛宏" in blob:
                score += 0.15
            return min(score, 1.0)
        if not raw or len(raw) < 9:
            return 0.0
        if raw[0] != 0xAA or raw[1] != 0xF5:
            # 兼容历史文档中偶见 AA 55 / AA F6
            if raw[0] == 0xAA and raw[1] in (0x55, 0xF6):
                return 0.35
            return 0.0
        total = read_u16_le(raw, 2)
        if total < 9 or total > 0x8000:
            return 0.25
        score = 0.55
        if total == len(raw):
            score += 0.25
        cmd = read_u16_le(raw, 6)
        if cmd in SH_CMD_NAMES:
            score += 0.15
        if len(raw) == total and len(raw) >= 9:
            body = raw[8:-1]
            if _checksum_ok(cmd, body, raw[-1]):
                score += 0.1
        return min(score, 1.0)

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
        fields = []
        status_map = VENDOR_STATUS_MAP.get("shenghong", {})
        for k, v in obj.items():
            meaning = None
            if k in ("workStatus", "status", "gunStatus") and isinstance(v, int):
                meaning = status_map.get(v) or SH_WORK_STATUS.get(v)
            fields.append(FieldItem(name=k, value=v, meaning=meaning))
        summary = f"盛弘 JSON 报文（{SH_PROTOCOL_VERSION}）"
        sn = obj.get("pileSn") or obj.get("deviceId")
        if sn:
            summary += f"，桩号={sn}"
        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(None, obj),
            summary=summary,
            fields=fields,
            raw_json=obj,
            valid=True,
        )

    def _parse_bin(self, raw: bytes) -> AnalysisResult:
        fields: list[FieldItem] = []
        warnings: list[WarningItem] = []
        if len(raw) < 9:
            return AnalysisResult(
                protocol=self.protocol_id,
                protocol_name=self.protocol_name,
                confidence=0.1,
                valid=False,
                summary="盛弘报文过短",
                warnings=[WarningItem(code="TOO_SHORT", level="error", message="至少需要 9 字节")],
                raw_hex=to_hex(raw),
            )

        fields.append(FieldItem(name="header", value=to_hex(raw[:2]), offset=0, length=2, meaning="起始域 AA F5"))
        total = read_u16_le(raw, 2)
        fields.append(FieldItem(name="frame_length", value=total, offset=2, length=2, meaning="整帧长度"))
        info = raw[4]
        enc = (info >> 7) & 0x01
        ver = info & 0x0F
        fields.append(
            FieldItem(
                name="info",
                value=f"0x{info:02X}",
                offset=4,
                length=1,
                meaning=f"信息域：加密={'是' if enc else '否'}，协议主版本={ver}",
            )
        )
        seq = raw[5]
        fields.append(FieldItem(name="seq", value=seq, offset=5, length=1, meaning="序列号"))
        cmd = read_u16_le(raw, 6)
        cmd_name = SH_CMD_NAMES.get(cmd, f"CMD={cmd}")
        direction = "平台下行" if cmd % 2 == 1 else "桩上行"
        fields.append(
            FieldItem(
                name="cmd",
                value=cmd,
                offset=6,
                length=2,
                meaning=f"{cmd_name}（{direction}）",
            )
        )

        if total != len(raw):
            warnings.append(
                WarningItem(
                    code="LEN_MISMATCH",
                    level="warn",
                    message=f"声明长度 {total} 与实际 {len(raw)} 不一致",
                )
            )

        body = raw[8:-1] if len(raw) >= 9 else b""
        recv_sum = raw[-1]
        calc_ok = _checksum_ok(cmd, body, recv_sum)
        fields.append(
            FieldItem(
                name="checksum",
                value=f"0x{recv_sum:02X}",
                offset=len(raw) - 1,
                length=1,
                meaning="校验和" + ("（通过）" if calc_ok else "（不匹配）"),
            )
        )
        if not calc_ok:
            warnings.append(WarningItem(code="CHECKSUM", level="warn", message="累计和校验不匹配"))

        # 加密时数据域前有 2 字节业务长度
        data = body
        data_off = 8
        if enc and len(body) >= 2:
            biz_len = read_u16_le(body, 0)
            fields.append(
                FieldItem(
                    name="biz_length",
                    value=biz_len,
                    offset=8,
                    length=2,
                    meaning="加密业务数据长度",
                )
            )
            data = body[2:]
            data_off = 10
            warnings.append(
                WarningItem(code="ENCRYPTED", level="info", message="业务数据已加密，字段按明文布局尽力解析可能不准")
            )

        # 多数上行业务体前 4 字节预留
        layout = None
        payload = data
        payload_off = data_off
        if cmd in (102, 104, 106, 202, 222) and len(data) >= 4:
            fields.append(FieldItem(name="reserved1", value=to_hex(data[0:2]), offset=data_off, length=2, meaning="预留"))
            fields.append(FieldItem(name="reserved2", value=to_hex(data[2:4]), offset=data_off + 2, length=2, meaning="预留"))
            payload = data[4:]
            payload_off = data_off + 4
            layout = {
                102: SH_CMD102_FIELDS,
                104: SH_CMD104_FIELDS,
                106: SH_CMD106_FIELDS,
                202: SH_CMD202_FIELDS,
                222: SH_CMD202_FIELDS,
            }.get(cmd)
        elif cmd in (101, 103, 105) and len(data) >= 4:
            fields.append(FieldItem(name="reserved1", value=to_hex(data[0:2]), offset=data_off, length=2, meaning="预留"))
            fields.append(FieldItem(name="reserved2", value=to_hex(data[2:4]), offset=data_off + 2, length=2, meaning="预留"))
            payload = data[4:]
            payload_off = data_off + 4

        if layout:
            # 222 电量分辨率为 0.001，在 walk 后对关键字段再标注
            fields.extend(_walk_fields(payload, layout, base_offset=payload_off))
            if cmd == 222:
                for f in fields:
                    if f.name in {"session_energy", "meter_before", "meter_after"} and isinstance(f.value, str) and f.value.endswith("kWh"):
                        f.meaning = (f.meaning or "") + "（222 分辨率 0.001kWh，当前按 0.01 展示仅供参考）"
        elif payload:
            # 通用：尝试提取 32 字节 ASCII 桩号
            if len(payload) >= 32:
                pile = _ascii_z(payload[:32])
                if pile and all(32 <= ord(c) < 127 for c in pile):
                    fields.append(
                        FieldItem(
                            name="pile_code",
                            value=pile,
                            offset=payload_off,
                            length=32,
                            meaning="充电桩编码",
                        )
                    )
                    rest = payload[32:]
                    if rest:
                        fields.append(
                            FieldItem(
                                name="payload",
                                value=to_hex(rest),
                                offset=payload_off + 32,
                                length=len(rest),
                                meaning="数据域",
                            )
                        )
                else:
                    fields.append(
                        FieldItem(
                            name="payload",
                            value=to_hex(payload),
                            offset=payload_off,
                            length=len(payload),
                            meaning="数据域",
                        )
                    )
            else:
                fields.append(
                    FieldItem(
                        name="payload",
                        value=to_hex(payload),
                        offset=payload_off,
                        length=len(payload),
                        meaning="数据域",
                    )
                )

        pile = next((f.value for f in fields if f.name == "pile_code"), None)
        work = next((f for f in fields if f.name == "work_status"), None)
        summary = f"盛弘 {cmd_name}，CMD={cmd}，{direction}"
        if pile and pile != "-":
            summary += f"，桩号={pile}"
        if work and work.meaning:
            summary += f"，状态={work.meaning}"

        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(raw, None),
            frame_type=str(cmd),
            frame_type_name=cmd_name,
            direction="down" if cmd % 2 == 1 else "up",
            summary=summary,
            fields=fields,
            warnings=warnings,
            raw_hex=to_hex(raw),
            valid=raw[0:2] == b"\xAA\xF5",
            extras={"protocol_version": SH_PROTOCOL_VERSION},
        )
