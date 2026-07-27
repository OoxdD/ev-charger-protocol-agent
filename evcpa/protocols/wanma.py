"""万马新能源充电桩与平台通讯协议 2020 解析器。"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from evcpa.knowledge.wanma import (
    PROTOCOL_VERSION,
    WANMA_FIELD_LABELS,
    WANMA_GUN_WORK,
    WANMA_LOGIN_FAIL,
    WANMA_MSGS,
    WANMA_PILE_WORK,
    WANMA_QOS,
    WANMA_SEND_REASON,
    WANMA_START_BE,
    WANMA_START_LE,
    WANMA_START_WAY,
)
from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.utils import (
    bcd_to_str,
    crc32_iso_hdlc,
    crc32_mpeg2,
    read_u16_le,
    read_u32_le,
    to_hex,
)


def _ascii_z(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip("\x00 ")


def _utc_ts(ts: int) -> str:
    if ts <= 0:
        return str(ts)
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return str(ts)


def _match_crc(payload: bytes, recv: int) -> tuple[bool, str, int]:
    for name, fn in (("ISO-HDLC", crc32_iso_hdlc), ("MPEG-2", crc32_mpeg2)):
        calc = fn(payload)
        if calc == recv:
            return True, name, calc
    return False, "ISO-HDLC", crc32_iso_hdlc(payload)


class WanmaParser(ProtocolParser):
    """万马新能源 TCP 协议（起始 AABB5599H，小端，CRC32）。"""

    protocol_id = ProtocolId.WANMA
    protocol_name = "万马新能源"

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        if raw is None or len(raw) < 24:
            return 0.0
        if raw[:4] not in (WANMA_START_LE, WANMA_START_BE):
            return 0.0
        total = read_u16_le(raw, 8)
        if total != len(raw) or total > 500 or total < 24:
            return 0.25
        body_len = total - 24
        score = 0.55
        if body_len == 0 or body_len % 16 == 0:
            score += 0.12
        msg = read_u16_le(raw, 4)
        if msg in WANMA_MSGS:
            score += 0.12
        reason = raw[10]
        if reason in (1, 2):
            score += 0.05
        ok, _, _ = _match_crc(raw[:-4], read_u32_le(raw, total - 4))
        if ok:
            score += 0.15
        return min(score, 1.0)

    def parse(self, raw: bytes | None, json_obj: Any | None) -> AnalysisResult:
        if raw is None or len(raw) < 24:
            return AnalysisResult(
                protocol=self.protocol_id,
                protocol_name=self.protocol_name,
                confidence=0.0,
                valid=False,
                summary="报文过短，无法按万马帧解析",
                warnings=[WarningItem(code="TOO_SHORT", level="error", message="至少需要 24 字节")],
            )

        fields: list[FieldItem] = []
        warnings: list[WarningItem] = []

        start = raw[:4]
        fields.append(
            FieldItem(
                name="start_flag",
                value=to_hex(start, spaced=False),
                offset=0,
                length=4,
                meaning="起始域 AABB5599H",
            )
        )
        if start not in (WANMA_START_LE, WANMA_START_BE):
            warnings.append(
                WarningItem(
                    code="BAD_START",
                    level="error",
                    message=f"起始域应为 AABB5599，实际 {to_hex(start, spaced=False)}",
                )
            )

        msg = read_u16_le(raw, 4)
        seq = read_u16_le(raw, 6)
        total = read_u16_le(raw, 8)
        reason = raw[10]
        qos = raw[11]
        device = bcd_to_str(raw[12:20])
        info = WANMA_MSGS.get(msg)
        msg_name = info[0] if info else f"未知消息(0x{msg:04X})"
        direction = info[1] if info else "unknown"

        fields.append(
            FieldItem(name="msg_code", value=f"0x{msg:04X}", offset=4, length=2, meaning=msg_name)
        )
        fields.append(FieldItem(name="seq", value=seq, offset=6, length=2, meaning="序列号"))
        fields.append(FieldItem(name="total_len", value=total, offset=8, length=2, meaning="整帧长度"))
        fields.append(
            FieldItem(
                name="send_reason",
                value=reason,
                offset=10,
                length=1,
                meaning=WANMA_SEND_REASON.get(reason, str(reason)),
            )
        )
        fields.append(
            FieldItem(name="qos", value=qos, offset=11, length=1, meaning=WANMA_QOS.get(qos, str(qos)))
        )
        fields.append(FieldItem(name="device_id", value=device, offset=12, length=8, meaning="设备编码"))

        if total != len(raw):
            warnings.append(
                WarningItem(
                    code="LEN_MISMATCH",
                    level="error",
                    message=f"报文长度字段={total}，实际={len(raw)}",
                )
            )

        body_len = max(0, min(len(raw), total) - 24)
        if reason == 2 and body_len != 0:
            warnings.append(
                WarningItem(code="ACK_HAS_BODY", level="warn", message="确认报文通常无数据域")
            )
        if body_len and body_len % 16 != 0:
            rem = body_len % 16
            trailing_ok = body_len >= rem and all(
                b == 0 for b in raw[20 + body_len - rem : 20 + body_len]
            )
            # 未加密可变长报文（如 0x4004 分时列表）常不补齐；CRC 已通过则不告警
            if not trailing_ok:
                # 稍后若 CRC 通过再决定是否保留；先记下，CRC 校验后再过滤
                warnings.append(
                    WarningItem(
                        code="BODY_ALIGN",
                        level="warn",
                        message=f"数据域长度 {body_len} 非 16 的倍数（协议要求填充 00H）",
                    )
                )

        body = raw[20 : 20 + body_len] if body_len else b""
        crc_off = 20 + body_len
        if crc_off + 4 <= len(raw):
            recv_crc = read_u32_le(raw, crc_off)
            ok, algo, calc = _match_crc(raw[:crc_off], recv_crc)
            fields.append(
                FieldItem(
                    name="crc32",
                    value=f"0x{recv_crc:08X}",
                    offset=crc_off,
                    length=4,
                    meaning=f"CRC32({algo})",
                )
            )
            fields.append(FieldItem(name="crc32_calc", value=f"0x{calc:08X}", meaning="本地计算 CRC32"))
            if ok:
                # 可变长数据域未按 16 对齐但 CRC 正确：视为设备未填填充，去掉误报
                warnings[:] = [w for w in warnings if w.code != "BODY_ALIGN"]
            else:
                warnings.append(
                    WarningItem(
                        code="CRC_FAIL",
                        level="warn",
                        message=(
                            f"CRC32 未匹配常见算法(ISO-HDLC/MPEG-2): "
                            f"报文=0x{recv_crc:08X}, 计算=0x{calc:08X}（文档未规定多项式，仅作参考）"
                        ),
                    )
                )
        else:
            warnings.append(WarningItem(code="NO_CRC", level="error", message="缺少 CRC32 校验域"))

        if reason == 2:
            fields.append(FieldItem(name="body_hex", value="", meaning="确认报文无数据域"))
        elif body:
            fields.extend(self._parse_body(msg, body))
        else:
            fields.append(FieldItem(name="body_hex", value="", meaning="无数据域"))

        fields = [self._with_label(f) for f in fields]
        summary = (
            f"万马 {PROTOCOL_VERSION} {msg_name}（0x{msg:04X}），"
            f"设备={device or '-'}，序号={seq}，数据域 {body_len} 字节"
        )
        issues = [w for w in warnings if w.level in ("warn", "error")]
        if issues:
            summary += f"；发现 {len(issues)} 个问题"

        # CRC 未校准时不因 CRC_FAIL 判为无效帧（文档未给多项式）
        hard_errors = [w for w in warnings if w.level == "error"]
        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(raw, None),
            frame_type=f"0x{msg:04X}",
            frame_type_name=msg_name,
            direction=direction,
            valid=len(hard_errors) == 0,
            summary=summary,
            fields=fields,
            warnings=warnings,
            raw_hex=to_hex(raw),
            extras={"body_len": body_len, "wanma_version": PROTOCOL_VERSION, "device_id": device},
        )

    @staticmethod
    def _with_label(item: FieldItem) -> FieldItem:
        label = item.label or WANMA_FIELD_LABELS.get(item.name)
        if not label:
            return item
        return item.model_copy(update={"label": label})

    def _need(self, body: bytes, offset: int, size: int) -> bool:
        return offset + size <= len(body)

    def _parse_body(self, msg: int, body: bytes) -> list[FieldItem]:
        if msg == 0x0001:
            return self._parse_login(body)
        if msg == 0x0002:
            return self._parse_login_ack(body)
        if msg == 0x0003:
            return self._parse_offline(body)
        if msg == 0x0004:
            return self._parse_key(body)
        if msg == 0x0005:
            return []
        if msg == 0x2000:
            return self._parse_status(body)
        if msg == 0x2002:
            return self._parse_pile_data(body)
        if msg == 0x4000:
            return self._parse_start_cmd(body)
        if msg == 0x4002:
            return self._parse_stop_cmd(body)
        if msg == 0x4004:
            return self._parse_energy(body)
        if msg == 0x4006:
            return self._parse_trade(body)
        return [
            FieldItem(
                name="body_hex",
                value=to_hex(body, spaced=False),
                offset=20,
                length=len(body),
                meaning=f"数据域（0x{msg:04X} 细分解析待扩展）",
            )
        ]

    def _parse_login(self, body: bytes) -> list[FieldItem]:
        items: list[FieldItem] = []
        if self._need(body, 0, 40):
            items.append(
                FieldItem(
                    name="hardware_sn",
                    value=_ascii_z(body[0:40]),
                    offset=20,
                    length=40,
                    meaning="硬件序列号",
                )
            )
        if self._need(body, 40, 1):
            items.append(
                FieldItem(name="proto_major", value=body[40], offset=60, length=1, meaning="协议主版本")
            )
        if self._need(body, 41, 1):
            items.append(
                FieldItem(name="proto_minor", value=body[41], offset=61, length=1, meaning="协议子版本")
            )
        return items

    def _parse_login_ack(self, body: bytes) -> list[FieldItem]:
        items: list[FieldItem] = []
        if self._need(body, 0, 2):
            code = read_u16_le(body, 0)
            items.append(
                FieldItem(
                    name="fail_reason",
                    value=code,
                    offset=20,
                    length=2,
                    meaning=WANMA_LOGIN_FAIL.get(code, str(code)),
                )
            )
        if self._need(body, 3, 1):
            items.append(
                FieldItem(
                    name="encrypt_flag",
                    value=body[3],
                    offset=23,
                    length=1,
                    meaning="加密" if body[3] else "不加密",
                )
            )
        if self._need(body, 4, 4):
            ts = read_u32_le(body, 4)
            items.append(
                FieldItem(name="sync_time", value=_utc_ts(ts), offset=24, length=4, meaning="同步时间")
            )
        return items

    def _parse_offline(self, body: bytes) -> list[FieldItem]:
        if not self._need(body, 0, 4):
            return []
        ts = read_u32_le(body, 0)
        return [FieldItem(name="offline_time", value=_utc_ts(ts), offset=20, length=4, meaning="下线时间")]

    def _parse_key(self, body: bytes) -> list[FieldItem]:
        items: list[FieldItem] = []
        if self._need(body, 0, 4):
            items.append(
                FieldItem(
                    name="key_time",
                    value=_utc_ts(read_u32_le(body, 0)),
                    offset=20,
                    length=4,
                    meaning="密钥生成时间",
                )
            )
        if self._need(body, 4, 16):
            items.append(
                FieldItem(
                    name="sm4_key",
                    value=to_hex(body[4:20], spaced=False),
                    offset=24,
                    length=16,
                    meaning="SM4密钥",
                )
            )
        return items

    def _parse_status(self, body: bytes) -> list[FieldItem]:
        items: list[FieldItem] = []
        if not body:
            return items
        work = body[0]
        items.append(
            FieldItem(
                name="pile_work_status",
                value=work,
                offset=20,
                length=1,
                label="充电桩工作状态",
                meaning=WANMA_PILE_WORK.get(work, str(work)),
            )
        )
        if not self._need(body, 11, 1):
            return items
        n = body[11]
        items.append(FieldItem(name="gun_count", value=n, offset=31, length=1, label="有效接口数"))
        off = 12
        for i in range(n):
            if not self._need(body, off, 16):
                break
            gun = body[off]
            gst = body[off + 1]
            items.append(
                FieldItem(
                    name=f"gun_{gun}_status",
                    value=gst,
                    offset=20 + off + 1,
                    length=1,
                    label=f"接口{gun}工作状态",
                    meaning=WANMA_GUN_WORK.get(gst, str(gst)),
                )
            )
            off += 16
        return items

    @staticmethod
    def _scale_voltage_v(raw: int) -> float | None:
        """电压原始值：优先 0.01V，其次 0.1V，落在 50~1000V。"""
        for div, nd in ((100.0, 2), (10.0, 1)):
            v = raw / div
            if 50.0 <= v <= 1000.0:
                return round(v, nd)
        return None

    @staticmethod
    def _scale_current_a(raw: int) -> float | None:
        """电流原始值：优先 0.01A，其次 0.1A / 1A，落在 0~600A。"""
        for div, nd in ((100.0, 2), (10.0, 1), (1.0, 0)):
            c = raw / div
            if 0.0 <= c <= 600.0:
                return round(c, nd)
        return None

    def _parse_pile_data(self, body: bytes) -> list[FieldItem]:
        """0x2002 电桩数据：表码/额定值 + 枪口电压电流等。"""
        items: list[FieldItem] = []
        if len(body) < 8:
            items.append(
                FieldItem(
                    name="body_hex",
                    value=to_hex(body, spaced=False),
                    offset=20,
                    length=len(body),
                    meaning="电桩数据原始域",
                )
            )
            return items

        # 头部常见：累计电表(0.001kWh) + 额定电压/电流(1V/1A，多在偏移 16)
        if self._need(body, 0, 4):
            meter = read_u32_le(body, 0)
            if 0 < meter < 50_000_000:
                items.append(
                    FieldItem(
                        name="meter_value",
                        value=round(meter / 1000.0, 3),
                        offset=20,
                        length=4,
                        unit="kWh",
                        meaning="电表读数",
                    )
                )
        if self._need(body, 4, 4):
            meter2 = read_u32_le(body, 4)
            if 0 < meter2 < 50_000_000:
                items.append(
                    FieldItem(
                        name="meter_value_2",
                        value=round(meter2 / 1000.0, 3),
                        offset=24,
                        length=4,
                        unit="kWh",
                        label="电表读数2",
                        meaning="第二路/接口电表读数",
                    )
                )
        if self._need(body, 16, 4):
            rated_v = read_u16_le(body, 16)
            rated_i = read_u16_le(body, 18)
            if 50 <= rated_v <= 1000 and 1 <= rated_i <= 600:
                items.append(
                    FieldItem(
                        name="rated_voltage",
                        value=rated_v,
                        offset=36,
                        length=2,
                        unit="V",
                        label="额定电压",
                        meaning="额定输出电压",
                    )
                )
                items.append(
                    FieldItem(
                        name="rated_current",
                        value=rated_i,
                        offset=38,
                        length=2,
                        unit="A",
                        label="额定电流",
                        meaning="额定输出电流",
                    )
                )

        # 枪口实时段：port(1~8) + 状态 + 电压 + 电流（可能有多处误对齐，打分择优）
        candidates: list[tuple[int, int, int, float, float, int]] = []
        for off in range(0, len(body) - 5):
            gun = body[off]
            st = body[off + 1]
            if gun < 1 or gun > 8 or st not in WANMA_GUN_WORK:
                continue
            volt_raw = read_u16_le(body, off + 2)
            curr_raw = read_u16_le(body, off + 4)
            volt = self._scale_voltage_v(volt_raw)
            curr = self._scale_current_a(curr_raw)
            if volt is None or curr is None:
                continue
            # 避免把额定 500V/500A 误当成实时输出
            if off <= 18 and self._need(body, 16, 4):
                if volt_raw == read_u16_le(body, 16) and curr_raw == read_u16_le(body, 18):
                    continue
            score = 0
            if 200.0 <= volt <= 800.0:
                score += 3
            elif 50.0 <= volt <= 1000.0:
                score += 1
            if 1.0 <= curr <= 500.0:
                score += 2
            power_kw = volt * curr / 1000.0
            if 3.0 <= power_kw <= 400.0:
                score += 3
            if st == 2:
                score += 2
            elif st == 1:
                score += 1
            if off >= 1 and body[off - 1] == 0:
                score += 1
            # 电压偏低但电流很大，多半是错位
            if volt < 150.0 and curr > 150.0:
                score -= 2
            candidates.append((score, off, gun, st, volt, curr))

        gun_off: int | None = None
        if candidates:
            candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
            _score, off, gun, st, volt, curr = candidates[0]
            gun_off = off
            items.append(
                FieldItem(
                    name="gun_no",
                    value=gun,
                    offset=20 + off,
                    length=1,
                    meaning="接口标识",
                )
            )
            items.append(
                FieldItem(
                    name=f"gun_{gun}_status",
                    value=st,
                    offset=20 + off + 1,
                    length=1,
                    label=f"接口{gun}工作状态",
                    meaning=WANMA_GUN_WORK.get(st, str(st)),
                )
            )
            items.append(
                FieldItem(
                    name="output_voltage",
                    value=volt,
                    offset=20 + off + 2,
                    length=2,
                    unit="V",
                    meaning="输出电压",
                )
            )
            items.append(
                FieldItem(
                    name="output_current",
                    value=curr,
                    offset=20 + off + 4,
                    length=2,
                    unit="A",
                    meaning="输出电流",
                )
            )
            items.append(
                FieldItem(
                    name="output_power",
                    value=round(volt * curr / 1000.0, 2),
                    unit="kW",
                    label="输出功率(估算)",
                    meaning="电压×电流",
                )
            )

        items.append(
            FieldItem(
                name="body_hex",
                value=to_hex(body, spaced=False),
                offset=20,
                length=len(body),
                meaning="电桩数据原始域"
                + (f"；枪口段偏移 body+{gun_off}" if gun_off is not None else "（未识别到枪口电气段）"),
            )
        )
        return items

    def _parse_start_cmd(self, body: bytes) -> list[FieldItem]:
        items: list[FieldItem] = []
        o = 0
        if self._need(body, o, 1):
            items.append(FieldItem(name="gun_no", value=body[o], offset=20 + o, length=1, meaning="接口标识"))
            o += 1
        if self._need(body, o, 1):
            way = body[o]
            items.append(
                FieldItem(
                    name="start_way",
                    value=way,
                    offset=20 + o,
                    length=1,
                    meaning=WANMA_START_WAY.get(way, str(way)),
                )
            )
            o += 1
        if self._need(body, o, 1):
            items.append(
                FieldItem(
                    name="parallel",
                    value=body[o],
                    offset=20 + o,
                    length=1,
                    meaning="并充" if body[o] == 1 else "单充",
                )
            )
            o += 1
        # 跳过个性化费率标志 + 账号(常见32) + 策略8 + MD5 32，尽力找流水号
        # 保守：从偏移 4+32+8+32 = 76 取 BCD16；若不够则输出 hex
        if self._need(body, 76, 16):
            items.append(
                FieldItem(
                    name="trade_no",
                    value=bcd_to_str(body[76:92]),
                    offset=96,
                    length=16,
                    meaning="充电流水号",
                )
            )
        else:
            items.append(
                FieldItem(
                    name="body_hex",
                    value=to_hex(body, spaced=False),
                    offset=20,
                    length=len(body),
                    meaning="启动命令体（字段布局待样本核对）",
                )
            )
        return items

    def _parse_stop_cmd(self, body: bytes) -> list[FieldItem]:
        items: list[FieldItem] = []
        if self._need(body, 0, 1):
            items.append(FieldItem(name="gun_no", value=body[0], offset=20, length=1, meaning="接口标识"))
        if self._need(body, 4, 16):
            items.append(
                FieldItem(
                    name="trade_no",
                    value=bcd_to_str(body[4:20]),
                    offset=24,
                    length=16,
                    meaning="充电流水号",
                )
            )
        return items

    def _parse_energy(self, body: bytes) -> list[FieldItem]:
        """0x4004 充电电量数据（对齐爱充 wmp_charge_data + slot 列表）。"""
        items: list[FieldItem] = []
        tou_names = {0: "尖", 1: "峰", 2: "平", 3: "谷"}

        if self._need(body, 0, 1):
            items.append(FieldItem(name="gun_no", value=body[0], offset=20, length=1, meaning="接口标识"))
        if self._need(body, 1, 1):
            items.append(FieldItem(name="soc", value=body[1], offset=21, length=1, unit="%", meaning="SOC"))
        if self._need(body, 4, 4):
            items.append(
                FieldItem(
                    name="charge_time_sec",
                    value=read_u32_le(body, 4),
                    offset=24,
                    length=4,
                    unit="s",
                    label="持续充电时间",
                )
            )
        if self._need(body, 8, 4):
            items.append(
                FieldItem(
                    name="charge_energy",
                    value=round(read_u32_le(body, 8) / 1000.0, 3),
                    offset=28,
                    length=4,
                    unit="kWh",
                    meaning="充电总电量",
                )
            )
        if self._need(body, 12, 4):
            items.append(
                FieldItem(
                    name="charge_money",
                    value=round(read_u32_le(body, 12) / 10000.0, 4),
                    offset=32,
                    length=4,
                    unit="元",
                    meaning="充电总费用",
                )
            )
        if self._need(body, 16, 2):
            need = read_u16_le(body, 16)
            # 部分桩把剩余分钟写成高字节（如 00 0F → 本应 15）
            if need > 24 * 60 and body[16] == 0 and 0 < body[17] <= 24 * 60:
                need = body[17]
            items.append(
                FieldItem(
                    name="need_time_min",
                    value=need,
                    offset=36,
                    length=2,
                    unit="min",
                    label="剩余充电时间",
                    meaning="剩余充电时间",
                )
            )

        # ProtocolObjList：1 字节条数 + N×8 字节时段
        # 时段布局：序号(1) + 保留(1) + 单价0.0001元(2) + 电量0.001kWh(4)
        if self._need(body, 19, 1):
            n = body[19]
            items.append(
                FieldItem(
                    name="slot_count",
                    value=n,
                    offset=39,
                    length=1,
                    label="分时段数",
                    meaning="分时电量段数",
                )
            )
            off = 20
            slot_energy_sum = 0.0
            # 先扫一遍：若存在 >3 的序号，按半小时费率时段解释；否则按尖峰平谷
            indices: list[int] = []
            for i in range(n):
                if self._need(body, off + i * 8, 1):
                    indices.append(body[off + i * 8])
            use_tou_name = bool(indices) and max(indices) <= 3

            for i in range(n):
                if not self._need(body, off, 8):
                    items.append(
                        FieldItem(
                            name="slot_truncated",
                            value=True,
                            meaning=f"分时列表声明 {n} 段，实际仅解析到 {i} 段",
                        )
                    )
                    break
                idx = body[off]
                price_raw = read_u16_le(body, off + 2)
                energy_raw = read_u32_le(body, off + 4)
                energy = round(energy_raw / 1000.0, 3)
                price = round(price_raw / 10000.0, 4)
                slot_energy_sum += energy
                if use_tou_name and idx in tou_names:
                    label = f"分时{tou_names[idx]}"
                    name = f"tou_{tou_names[idx]}_energy"
                else:
                    # 0~47 常见为半小时费率时段号
                    label = f"分时时段{idx}"
                    name = f"slot_{idx}_energy"
                items.append(
                    FieldItem(
                        name=name,
                        value=energy,
                        offset=20 + off,
                        length=8,
                        unit="kWh",
                        label=label,
                        meaning=f"{label}电量；单价 {price} 元/kWh",
                    )
                )
                items.append(
                    FieldItem(
                        name=f"{name}_price",
                        value=price,
                        offset=20 + off + 2,
                        length=2,
                        unit="元/kWh",
                        label=f"{label}单价",
                        meaning="时段电价（含服务费口径以设备为准）",
                    )
                )
                off += 8
            if n and slot_energy_sum > 0:
                items.append(
                    FieldItem(
                        name="slot_energy_sum",
                        value=round(slot_energy_sum, 3),
                        unit="kWh",
                        label="分时电量合计",
                        meaning="各分时段电量之和",
                    )
                )
        return items

    def _parse_trade(self, body: bytes) -> list[FieldItem]:
        items: list[FieldItem] = []
        if self._need(body, 0, 1):
            items.append(FieldItem(name="gun_no", value=body[0], offset=20, length=1, meaning="接口标识"))
        if self._need(body, 4, 16):
            items.append(
                FieldItem(
                    name="trade_no",
                    value=bcd_to_str(body[4:20]),
                    offset=24,
                    length=16,
                    meaning="充电流水号",
                )
            )
        if self._need(body, 20, 4):
            items.append(
                FieldItem(
                    name="start_time",
                    value=_utc_ts(read_u32_le(body, 20)),
                    offset=40,
                    length=4,
                    label="开始时间",
                )
            )
        if self._need(body, 24, 4):
            items.append(
                FieldItem(
                    name="end_time",
                    value=_utc_ts(read_u32_le(body, 24)),
                    offset=44,
                    length=4,
                    label="结束时间",
                )
            )
        # 电量/费用在账号结构之后，位置不固定；保留 hex 便于人工核对
        items.append(
            FieldItem(
                name="body_hex",
                value=to_hex(body, spaced=False),
                offset=20,
                length=len(body),
                meaning="充电记录完整数据域",
            )
        )
        return items
