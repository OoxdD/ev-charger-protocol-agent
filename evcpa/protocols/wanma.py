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
            if not ok:
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
        if warnings:
            summary += f"；发现 {len(warnings)} 个问题"

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
        items: list[FieldItem] = []
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
