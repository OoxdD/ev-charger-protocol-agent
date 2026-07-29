"""南方电网充换电服务网络运营监控系统通信规约（系统与充电设施）解析。

基于 IEC 60870-5-104 APCI/ASDU，南网扩展：
- APDU 长度域 2 字节（与经典 104 单字节长度区分）
- 类型 130/132/133/134 业务与实时监测
- 协议标识帧（启动 68H，标识 FF）
"""

from __future__ import annotations

from typing import Any

from evcpa.knowledge.csg import (
    CSG_ASDU_TYPES,
    CSG_CHARGE_MODE_BITS,
    CSG_COT,
    CSG_DEVICE_TYPES,
    CSG_PROTOCOL_VERSION,
    CSG_RECORD_TYPES,
)
from evcpa.models import AnalysisResult, FieldItem, ProtocolId, WarningItem
from evcpa.protocols.base import ProtocolParser
from evcpa.protocols.csg_business import parse_business_payload
from evcpa.utils import bcd_to_str, crc16_modbus, read_u16_le, to_hex


_CSG_JSON_KEYS = {
    "csg",
    "CSG",
    "southGrid",
    "pileNo",
    "connectorNo",
    "chargeOrderNo",
    "runStatus",
    "elecQuantity",
    "chargeFee",
}


def _looks_like_ykc(raw: bytes) -> bool:
    if len(raw) < 8 or raw[0] != 0x68:
        return False
    try:
        calc = crc16_modbus(raw[2:-2])
        recv = int.from_bytes(raw[-2:], "little")
        return calc == recv
    except Exception:
        return False


class CsgParser(ProtocolParser):
    """南网标准接入（系统与充电设施）二进制 / JSON。"""

    protocol_id = ProtocolId.CSG
    protocol_name = "南方电网"

    def detect_score(self, raw: bytes | None, json_obj: Any | None) -> float:
        if isinstance(json_obj, dict):
            keys = {str(k) for k in json_obj.keys()}
            hit = len(keys & _CSG_JSON_KEYS)
            score = min(0.15 + hit * 0.12, 0.8)
            blob = str(json_obj).lower()
            if any(x in blob for x in ("csg", "southgrid", "南方电网", "南网", "nanwang")):
                score += 0.2
            return min(score, 1.0)

        if not raw or len(raw) < 6 or raw[0] != 0x68:
            return 0.0
        if _looks_like_ykc(raw):
            return 0.05

        # 协议标识帧：68 | len(2) | FF | ...
        if len(raw) >= 4 and raw[3] == 0xFF:
            body_len = read_u16_le(raw, 1)
            if body_len + 3 == len(raw) or body_len == len(raw):
                return 0.92
            return 0.7

        # 南网 2 字节长度 APDU
        if len(raw) >= 7:
            apdu_len = read_u16_le(raw, 1) & 0x07FF
            if apdu_len + 3 == len(raw) and apdu_len >= 4:
                score = 0.55
                ctrl0 = raw[3]
                if ctrl0 & 0x01 == 0 and len(raw) >= 8:
                    type_id = raw[7]
                    if type_id in CSG_ASDU_TYPES:
                        score += 0.35
                        if type_id in {130, 132, 133, 134}:
                            score += 0.08
                elif ctrl0 & 0x03 in (0x01, 0x03):
                    score += 0.2
                return min(score, 1.0)

        # 兼容部分实现仍用经典 1 字节长度但携带南网扩展类型
        if len(raw) >= 7:
            apdu_len1 = raw[1]
            if apdu_len1 + 2 == len(raw) and raw[2] & 0x01 == 0:
                type_id = raw[6]
                if type_id in {130, 132, 133, 134}:
                    return 0.88
                if type_id in CSG_ASDU_TYPES:
                    return 0.45
        return 0.0

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
        from evcpa.knowledge.alarms import VENDOR_STATUS_MAP

        fields: list[FieldItem] = []
        status_map = VENDOR_STATUS_MAP.get("csg", {})
        for k, v in obj.items():
            meaning = None
            if k in ("runStatus", "status", "gunStatus", "chargeStatus") and v is not None:
                meaning = status_map.get(v, status_map.get(str(v)))
            fields.append(FieldItem(name=k, value=v, meaning=meaning))
        pile = obj.get("pileNo") or obj.get("equipId") or obj.get("deviceId")
        summary = f"南方电网 JSON 报文（规约 {CSG_PROTOCOL_VERSION}）"
        if pile:
            summary += f"，桩号={pile}"
        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(None, obj),
            summary=summary,
            fields=fields,
            raw_json=obj,
            valid=True,
            extras={"protocol_version": CSG_PROTOCOL_VERSION},
        )

    def _parse_bin(self, raw: bytes) -> AnalysisResult:
        fields: list[FieldItem] = [
            FieldItem(name="start", value="0x68", offset=0, length=1, meaning="启动字符"),
        ]
        warnings: list[WarningItem] = []

        # —— 协议标识帧 ——
        if len(raw) >= 4 and raw[3] == 0xFF:
            return self._parse_proto_id(raw, fields, warnings)

        # —— 优先南网 2 字节长度 ——
        if len(raw) >= 7:
            apdu_len2 = read_u16_le(raw, 1) & 0x07FF
            if apdu_len2 + 3 == len(raw) and apdu_len2 >= 4:
                return self._parse_apdu(
                    raw,
                    fields,
                    warnings,
                    len_size=2,
                    ctrl_off=3,
                    asdu_off=7,
                    apdu_len=apdu_len2,
                )

        # —— 兼容 1 字节长度 ——
        if len(raw) >= 6:
            apdu_len1 = raw[1]
            if apdu_len1 + 2 == len(raw):
                return self._parse_apdu(
                    raw,
                    fields,
                    warnings,
                    len_size=1,
                    ctrl_off=2,
                    asdu_off=6,
                    apdu_len=apdu_len1,
                )
            warnings.append(
                WarningItem(
                    code="LEN_MISMATCH",
                    level="warn",
                    message=f"长度域与实际帧长不一致（实际 {len(raw)} 字节）",
                )
            )

        fields.append(FieldItem(name="raw", value=to_hex(raw), meaning="原始报文"))
        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(raw, None),
            summary="南方电网报文（结构未完整识别）",
            fields=fields,
            warnings=warnings,
            raw_hex=to_hex(raw),
            valid=False,
            extras={"protocol_version": CSG_PROTOCOL_VERSION},
        )

    def _parse_proto_id(
        self,
        raw: bytes,
        fields: list[FieldItem],
        warnings: list[WarningItem],
    ) -> AnalysisResult:
        flen = read_u16_le(raw, 1)
        fields.append(FieldItem(name="frame_length", value=flen, offset=1, length=2, meaning="帧长度"))
        fields.append(FieldItem(name="proto_flag", value="0xFF", offset=3, length=1, meaning="协议启动标识"))
        o = 4
        if len(raw) > o:
            ver = raw[o]
            fields.append(
                FieldItem(
                    name="protocol_version",
                    value=bcd_to_str(bytes([ver])),
                    offset=o,
                    length=1,
                    meaning="协议版本(BCD)",
                )
            )
            o += 1
        if len(raw) >= o + 8:
            fields.append(
                FieldItem(
                    name="fee_model_id",
                    value=to_hex(raw[o : o + 8]),
                    offset=o,
                    length=8,
                    meaning="计费模型 ID",
                )
            )
            o += 8
        if len(raw) >= o + 8:
            pile = bcd_to_str(raw[o : o + 8])
            fields.append(
                FieldItem(name="pile_code", value=pile, offset=o, length=8, meaning="设备编号(BCD)")
            )
            o += 8
        if len(raw) > o:
            guns = bcd_to_str(bytes([raw[o]]))
            fields.append(
                FieldItem(name="gun_count", value=guns, offset=o, length=1, meaning="充电接口数量(BCD)")
            )
            o += 1
        if len(raw) > o:
            mode = raw[o]
            bits = [name for bit, name in CSG_CHARGE_MODE_BITS.items() if mode & (1 << bit)]
            fields.append(
                FieldItem(
                    name="charge_mode",
                    value=f"0x{mode:02X}",
                    offset=o,
                    length=1,
                    meaning="支持充电模式：" + ("、".join(bits) if bits else "无"),
                )
            )
            o += 1
        if len(raw) >= o + 2:
            station = bcd_to_str(raw[o : o + 2])
            fields.append(
                FieldItem(name="station_addr", value=station, offset=o, length=2, meaning="站地址(BCD)")
            )

        pile = next((f.value for f in fields if f.name == "pile_code"), None)
        summary = "南方电网协议标识帧"
        if pile:
            summary += f"，设备编号={pile}"
        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(raw, None),
            frame_type="PROTO_ID",
            frame_type_name="协议标识帧",
            summary=summary,
            fields=fields,
            warnings=warnings,
            raw_hex=to_hex(raw),
            valid=True,
            extras={"protocol_version": CSG_PROTOCOL_VERSION},
        )

    def _parse_apdu(
        self,
        raw: bytes,
        fields: list[FieldItem],
        warnings: list[WarningItem],
        *,
        len_size: int,
        ctrl_off: int,
        asdu_off: int,
        apdu_len: int,
    ) -> AnalysisResult:
        fields.append(
            FieldItem(
                name="apdu_length",
                value=apdu_len,
                offset=1,
                length=len_size,
                meaning=f"APDU 长度（{len_size} 字节域）",
            )
        )
        ctrl = raw[ctrl_off : ctrl_off + 4]
        fields.append(
            FieldItem(name="control", value=to_hex(ctrl), offset=ctrl_off, length=len(ctrl), meaning="控制域")
        )

        frame_kind = "unknown"
        frame_type: str | None = None
        type_name: str | None = None
        b0 = ctrl[0] if ctrl else 0
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
            if len(raw) > asdu_off:
                type_id = raw[asdu_off]
                frame_type = str(type_id)
                type_name = CSG_ASDU_TYPES.get(type_id, f"ASDU type={type_id}")
                fields.append(
                    FieldItem(name="type_id", value=type_id, offset=asdu_off, length=1, meaning=type_name)
                )
            if len(raw) > asdu_off + 1:
                vsq = raw[asdu_off + 1]
                n = vsq & 0x7F
                sq = (vsq >> 7) & 0x01
                fields.append(
                    FieldItem(
                        name="vsq",
                        value=vsq,
                        offset=asdu_off + 1,
                        length=1,
                        meaning=f"可变结构限定词：数目={n}，SQ={sq}",
                    )
                )
            if len(raw) >= asdu_off + 4:
                cot = read_u16_le(raw, asdu_off + 2)
                cot_code = cot & 0xFF
                fields.append(
                    FieldItem(
                        name="cot",
                        value=cot,
                        offset=asdu_off + 2,
                        length=2,
                        meaning=f"传送原因：{CSG_COT.get(cot_code, cot_code)}",
                    )
                )
            if len(raw) >= asdu_off + 6:
                ca = read_u16_le(raw, asdu_off + 4)
                fields.append(
                    FieldItem(
                        name="common_address",
                        value=ca,
                        offset=asdu_off + 4,
                        length=2,
                        meaning="公共地址/站地址",
                    )
                )
            info_off = asdu_off + 6
            if len(raw) >= info_off + 3:
                ioa = int.from_bytes(raw[info_off : info_off + 3], "little")
                # 南网：0x000000/0x100000/…/0xF00000 → 枪 0..15
                gun = (ioa >> 20) & 0x0F
                fields.append(
                    FieldItem(
                        name="ioa",
                        value=f"0x{ioa:06X}",
                        offset=info_off,
                        length=3,
                        meaning=f"信息对象地址（枪 {gun}）",
                    )
                )
                fields.append(FieldItem(name="gun_no", value=gun, offset=info_off + 2, length=1, meaning="枪编号"))
                payload = raw[info_off + 3 :]
                type_id = raw[asdu_off] if len(raw) > asdu_off else -1
                vsq = raw[asdu_off + 1] if len(raw) > asdu_off + 1 else 0
                n = vsq & 0x7F
                sq = (vsq >> 7) & 0x01
                if type_id == 130 and payload:
                    rec = payload[0]
                    fields.append(
                        FieldItem(
                            name="record_type",
                            value=rec,
                            offset=info_off + 3,
                            length=1,
                            meaning=CSG_RECORD_TYPES.get(rec, f"记录类型 {rec}"),
                        )
                    )
                    if len(payload) > 1:
                        biz = payload[1:]
                        parsed = parse_business_payload(rec, biz)
                        enc = bool(parsed.get("encrypted"))
                        fields.append(
                            FieldItem(
                                name="business_data",
                                value=to_hex(biz),
                                offset=info_off + 4,
                                length=len(biz),
                                meaning=(
                                    "业务数据（SM4 软加密，仅识别类型/桩号）"
                                    if enc
                                    else "业务数据（附录 A 明文）"
                                ),
                            )
                        )
                        # 展开已识别业务字段，供会话汇总订单
                        label_map = {
                            "pile_code": ("充电设备编号", None),
                            "gun_no": ("业务体枪号", None),
                            "trade_no": ("交易流水号", None),
                            "order_no": ("订单编号", None),
                            "start_time": ("开始时间", None),
                            "end_time": ("结束时间", None),
                            "total_kwh": ("总电量", "kWh"),
                            "total_fee": ("充电总费用", "元"),
                            "elec_fee": ("充电总电费", "元"),
                            "service_amount": ("服务费金额", "元"),
                            "service_fee": ("服务费", "元"),
                            "consume_amount": ("消费金额", "元"),
                            "charge_fee": ("充电总费用", "元"),
                            "stop_reason": ("结束原因", None),
                            "vin": ("VIN", None),
                            "start_meter": ("总起示值", "kWh"),
                            "end_meter": ("总止示值", "kWh"),
                            "charged_minutes": ("累计充电时间", "min"),
                            "biz_type": ("业务类型", None),
                        }
                        for key, (label, unit) in label_map.items():
                            if key not in parsed or parsed[key] is None:
                                continue
                            if key == "gun_no" and any(f.name == "gun_no" for f in fields):
                                # IOA 枪号优先；业务体枪号另存
                                fields.append(
                                    FieldItem(
                                        name="body_gun_no",
                                        value=parsed[key],
                                        label=label,
                                        meaning=label,
                                    )
                                )
                                continue
                            fields.append(
                                FieldItem(
                                    name=key,
                                    value=parsed[key],
                                    label=label,
                                    unit=unit,
                                    meaning=label,
                                )
                            )
                        if enc:
                            warnings.append(
                                WarningItem(
                                    code="CSG_BUSINESS_ENCRYPTED",
                                    level="warn",
                                    message=parsed.get("note")
                                    or "业务载荷疑似 SM4 加密，订单明细需密钥解密",
                                )
                            )
                        extras_biz = {
                            k: v
                            for k, v in parsed.items()
                            if k
                            not in {
                                "raw_hex_head",
                                "note",
                            }
                        }
                        # 挂到返回 extras（下方构造时合并）
                        fields.append(
                            FieldItem(
                                name="_business_parsed",
                                value=extras_biz,
                                meaning="内部：业务解析字典",
                            )
                        )
                elif type_id == 134 and payload:
                    dev = payload[0]
                    fields.append(
                        FieldItem(
                            name="device_type",
                            value=dev,
                            offset=info_off + 3,
                            length=1,
                            meaning=CSG_DEVICE_TYPES.get(dev, f"设备类型 {dev}"),
                        )
                    )
                    if len(payload) > 1:
                        fields.append(
                            FieldItem(
                                name="monitor_data",
                                value=to_hex(payload[1:]),
                                offset=info_off + 4,
                                length=len(payload) - 1,
                                meaning="实时监测数据（附录 A.1）",
                            )
                        )
                elif type_id == 133 and payload:
                    # 下发数据项：首字节常为记录/命令子类型
                    sub = payload[0]
                    fields.append(
                        FieldItem(
                            name="downlink_type",
                            value=sub,
                            offset=info_off + 3,
                            length=1,
                            meaning=CSG_RECORD_TYPES.get(sub, f"下发子类型 {sub}"),
                        )
                    )
                    if len(payload) > 1:
                        fields.append(
                            FieldItem(
                                name="downlink_data",
                                value=to_hex(payload[1:]),
                                offset=info_off + 4,
                                length=len(payload) - 1,
                                meaning="下发数据项载荷",
                            )
                        )
                elif type_id == 132 and payload:
                    self._parse_md_objects(fields, payload, info_off + 3, n=n, sq=sq)
                elif type_id == 11 and payload:
                    self._parse_me_nb_objects(fields, payload, info_off + 3, n=n, sq=sq)
                elif type_id == 1 and payload:
                    self._parse_sp_objects(fields, payload, info_off + 3, n=n, sq=sq)
                elif payload:
                    fields.append(
                        FieldItem(
                            name="info_payload",
                            value=to_hex(payload),
                            offset=info_off + 3,
                            length=len(payload),
                            meaning="信息元素",
                        )
                    )

        summary = f"南方电网 {frame_kind}"
        if type_name:
            summary += f"：{type_name}"
        gun_f = next((f for f in fields if f.name == "gun_no"), None)
        if gun_f is not None:
            summary += f"，枪{gun_f.value}"
        rec_f = next((f for f in fields if f.name == "record_type"), None)
        if rec_f is not None:
            summary += f"，{rec_f.meaning or rec_f.value}"
        trade_f = next((f for f in fields if f.name == "trade_no"), None)
        if trade_f is not None:
            summary += f"，流水={trade_f.value}"
        kwh_f = next((f for f in fields if f.name == "total_kwh"), None)
        if kwh_f is not None:
            summary += f"，电量={kwh_f.value}kWh"

        biz_parsed = None
        cleaned: list[FieldItem] = []
        for f in fields:
            if f.name == "_business_parsed":
                biz_parsed = f.value if isinstance(f.value, dict) else None
                continue
            cleaned.append(f)

        extras: dict[str, Any] = {"protocol_version": CSG_PROTOCOL_VERSION, "apdu_len_size": len_size}
        if biz_parsed:
            extras["business"] = biz_parsed

        return AnalysisResult(
            protocol=self.protocol_id,
            protocol_name=self.protocol_name,
            confidence=self.detect_score(raw, None),
            frame_type=frame_type,
            frame_type_name=type_name or frame_kind,
            summary=summary,
            fields=cleaned,
            warnings=warnings,
            raw_hex=to_hex(raw),
            valid=True,
            extras=extras,
        )

    @staticmethod
    def _parse_md_objects(
        fields: list[FieldItem],
        payload: bytes,
        base: int,
        *,
        n: int,
        sq: int,
    ) -> None:
        """类型 132：变长标度化值（长度 + Value + QDS）。"""
        o = 0
        count = n if n > 0 else 16
        for i in range(count):
            if o >= len(payload):
                break
            ln = payload[o]
            o += 1
            if o + ln > len(payload):
                fields.append(
                    FieldItem(
                        name=f"md_{i}_raw",
                        value=to_hex(payload[o - 1 :]),
                        offset=base + o - 1,
                        meaning="变长测点截断",
                    )
                )
                break
            val_b = payload[o : o + ln]
            o += ln
            qds = payload[o] if o < len(payload) else None
            if qds is not None:
                o += 1
            if ln == 4:
                val: Any = int.from_bytes(val_b, "little", signed=False)
            elif ln == 2:
                val = int.from_bytes(val_b, "little", signed=True)
            else:
                val = to_hex(val_b)
            fields.append(
                FieldItem(
                    name=f"md_{i}",
                    value=val,
                    offset=base + o - ln - 1 - (1 if qds is not None else 0),
                    length=1 + ln + (1 if qds is not None else 0),
                    meaning=f"变长测点#{i + 1}（len={ln}"
                    + (f"，QDS=0x{qds:02X}" if qds is not None else "")
                    + "）",
                )
            )
        if o < len(payload):
            fields.append(
                FieldItem(
                    name="md_rest",
                    value=to_hex(payload[o:]),
                    offset=base + o,
                    length=len(payload) - o,
                    meaning="未解析测点尾部",
                )
            )

    @staticmethod
    def _parse_me_nb_objects(
        fields: list[FieldItem],
        payload: bytes,
        base: int,
        *,
        n: int,
        sq: int,
    ) -> None:
        """类型 11：2 字节标度化值 + QDS；SQ=1 时连续排列。"""
        o = 0
        count = n if n > 0 else max(1, len(payload) // 3)
        for i in range(count):
            if o + 3 > len(payload):
                break
            val = int.from_bytes(payload[o : o + 2], "little", signed=True)
            qds = payload[o + 2]
            fields.append(
                FieldItem(
                    name=f"me_{i}",
                    value=val,
                    offset=base + o,
                    length=3,
                    meaning=f"标度化测点#{i + 1}（QDS=0x{qds:02X}）",
                )
            )
            o += 3
        if o < len(payload):
            fields.append(
                FieldItem(
                    name="me_rest",
                    value=to_hex(payload[o:]),
                    offset=base + o,
                    length=len(payload) - o,
                    meaning="未解析测点尾部",
                )
            )

    @staticmethod
    def _parse_sp_objects(
        fields: list[FieldItem],
        payload: bytes,
        base: int,
        *,
        n: int,
        sq: int,
    ) -> None:
        """类型 1：单点信息 + QDS；SQ=1 时每点 1 字节。"""
        o = 0
        count = n if n > 0 else len(payload)
        for i in range(count):
            if o >= len(payload):
                break
            b = payload[o]
            # 低位为状态，高位常含品质
            st = b & 0x01
            fields.append(
                FieldItem(
                    name=f"sp_{i}",
                    value=st,
                    offset=base + o,
                    length=1,
                    meaning=f"单点#{i + 1}={'合/ON' if st else '分/OFF'}（raw=0x{b:02X}）",
                )
            )
            o += 1
        if o < len(payload):
            fields.append(
                FieldItem(
                    name="sp_rest",
                    value=to_hex(payload[o:]),
                    offset=base + o,
                    length=len(payload) - o,
                    meaning="未解析单点尾部",
                )
            )
