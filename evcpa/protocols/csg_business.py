"""南网类型 130 业务体解析（附录 A.3 充电记录 / A.33 过程上传）。

传输层常对信息体做 SM4-ECB 软加密：记录类型明文，设备编号 8 字节常明文，
其后为密文（长度对齐 16）。提供明文解析 + 可选密钥解密。
"""

from __future__ import annotations

import os
import re
from typing import Any

from evcpa.crypto.sm4 import sm4_ecb_decrypt
from evcpa.utils import bcd_to_str, to_hex

# 附录 A.3 充电结束原因（低字节）
CSG_STOP_REASON: dict[int, str] = {
    1: "本地刷卡终止",
    2: "远程终止充电",
    3: "充满自动停止",
    4: "余额不足",
    5: "充电桩故障",
    6: "BMS 故障",
    7: "急停按钮停止",
    8: "验证码停止",
    9: "停电结束",
    10: "按电量满足结束",
    11: "按金额满足结束",
    12: "按时间满足结束",
    13: "拔枪结束",
    14: "过压",
    15: "欠压",
    16: "过流",
    17: "失流",
    18: "接地不良",
    19: "桩屏幕停止",
    20: "充电桩过温",
    21: "充电枪过温",
    22: "车辆电池过温",
    23: "枪加锁失败",
    255: "其他",
}


def _cp56(data: bytes) -> str | None:
    if len(data) < 7:
        return None
    if data == b"\xff" * 7:
        return None
    msec = int.from_bytes(data[0:2], "little")
    minute = data[2] & 0x3F
    hour = data[3] & 0x1F
    day = data[4] & 0x1F
    month = data[5] & 0x0F
    year = 2000 + (data[6] & 0x7F)
    if not (1 <= month <= 12 and 1 <= day <= 31 and hour <= 23 and minute <= 59):
        return None
    if not (2018 <= year <= 2038):
        return None
    sec = msec // 1000
    ms = msec % 1000
    if sec > 59:
        return None
    return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}.{ms:03d}"


def _u32(data: bytes, off: int) -> int | None:
    if off + 4 > len(data):
        return None
    return int.from_bytes(data[off : off + 4], "little")


def _f2(v: int | None) -> float | None:
    if v is None:
        return None
    return round(v / 100.0, 2)


def _f5(v: int | None) -> float | None:
    if v is None:
        return None
    return round(v / 100000.0, 5)


def _bcd_ok(data: bytes, *, allow_ff: bool = True) -> bool:
    for b in data:
        if allow_ff and b == 0xFF:
            continue
        hi, lo = (b >> 4) & 0x0F, b & 0x0F
        if hi > 9 or lo > 9:
            return False
    return True


def looks_encrypted_business(biz: bytes, *, record_type: int | None = None) -> bool:
    """启发式：明文 A.3/A.33 头字段合法则视为未加密。"""
    if len(biz) < 42:
        return True
    pile, rest = biz[:8], biz[8:]
    if not _bcd_ok(pile, allow_ff=False):
        # 整段可能加密
        return len(biz) % 16 == 0
    gun = rest[0] if rest else 0xFF
    if gun > 15:
        return True
    if len(rest) < 17:
        return True
    trade = rest[1:17]
    if not _bcd_ok(trade, allow_ff=False):
        return True
    # A.3 / A.33 开始时间偏移不同
    if record_type == 17:
        # 8+1+16+2+8+8 = 43 → start@43
        if len(biz) >= 50 and _cp56(biz[43:50]) is None and biz[43:50] != b"\xff" * 7:
            return True
    else:
        # A.3: 8+1+16+8+8+1 = 42 → start@42
        if len(biz) >= 49 and _cp56(biz[42:49]) is None and biz[42:49] != b"\xff" * 7:
            return True
    # 密文常见：去掉桩号后长度为 16 倍数且头字段已失败
    if len(rest) % 16 == 0 and gun > 15:
        return True
    return False


def resolve_sm4_key(key: bytes | str | None = None) -> bytes | None:
    """从参数或环境变量 EVCPA_CSG_SM4_KEY（32 hex）取密钥。"""
    raw = key
    if raw is None:
        env = os.environ.get("EVCPA_CSG_SM4_KEY") or os.environ.get("CSG_SM4_KEY")
        raw = env
    if raw is None:
        return None
    if isinstance(raw, bytes):
        if len(raw) == 16:
            return raw
        if len(raw) == 32:
            try:
                return bytes.fromhex(raw.decode("ascii", errors="ignore"))
            except Exception:
                return None
        return None
    s = re.sub(r"[^0-9a-fA-F]", "", str(raw))
    if len(s) != 32:
        return None
    try:
        return bytes.fromhex(s)
    except Exception:
        return None


def try_decrypt_business(biz: bytes, key: bytes | None) -> tuple[bytes, str]:
    """尝试解密业务体。返回 (数据, 模式说明)。"""
    if key is None:
        return biz, "plain_or_unknown"
    candidates: list[tuple[str, bytes]] = []
    # 模式1：桩号明文 + 其后 SM4
    if len(biz) > 8 and (len(biz) - 8) % 16 == 0:
        try:
            candidates.append(("pile_clear+sm4", biz[:8] + sm4_ecb_decrypt(key, biz[8:])))
        except Exception:
            pass
    # 模式2：整段业务体 SM4
    if len(biz) % 16 == 0:
        try:
            candidates.append(("full_sm4", sm4_ecb_decrypt(key, biz)))
        except Exception:
            pass
    best = biz
    best_mode = "decrypt_failed"
    for mode, plain in candidates:
        # 去尾部 0x00 填充后再评估；保留足够长度
        trimmed = plain.rstrip(b"\x00")
        probe = trimmed if len(trimmed) >= 56 else plain
        if not looks_encrypted_business(probe, record_type=2) or not looks_encrypted_business(
            probe, record_type=17
        ):
            return probe if len(trimmed) >= 56 else plain, mode
        # 宽松：枪号合法即采纳
        if len(probe) >= 9 and probe[8] <= 15 and _bcd_ok(probe[:8], allow_ff=False):
            best, best_mode = probe, mode
    return best, best_mode


def parse_a3_charge_record(biz: bytes) -> dict[str, Any] | None:
    """附录 A.3 充电记录上传。字段不全时尽量解析头部与费用。"""
    if len(biz) < 56:
        return None
    if looks_encrypted_business(biz, record_type=2):
        return None
    o = 0
    pile = bcd_to_str(biz[o : o + 8])
    o += 8
    gun = biz[o]
    o += 1
    trade = bcd_to_str(biz[o : o + 16])
    o += 16
    pay_card = bcd_to_str(biz[o : o + 8])
    o += 8
    phys_card = bcd_to_str(biz[o : o + 8])
    o += 8
    tou = biz[o]
    o += 1
    start = _cp56(biz[o : o + 7])
    o += 7
    end = _cp56(biz[o : o + 7])
    o += 7
    # 跳过尖峰平谷起止示值 8*4
    o += 32
    meter_type = bcd_to_str(biz[o : o + 2]) if o + 2 <= len(biz) else None
    o += 2
    start_meter = _f2(_u32(biz, o))
    o += 4
    end_meter = _f2(_u32(biz, o))
    o += 4
    # 尖峰平谷：单价/电量/金额 ×4 = 12*4
    o += 48
    total_kwh = _f2(_u32(biz, o))
    o += 4
    biz_type = bcd_to_str(biz[o : o + 2]) if o + 2 <= len(biz) else None
    o += 2
    o += 4  # 扣款后余额
    o += 4  # 消费单价
    consume_amt = _f2(_u32(biz, o))
    o += 4
    vin = ""
    if o + 17 <= len(biz):
        vin = biz[o : o + 17].split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()
    o += 17
    # 跳过交易相关至服务费：1+6+4+2+4+7+4+1+4+1+4 = 38
    o += 38
    svc_price = _f5(_u32(biz, o)) if o + 4 <= len(biz) else None
    o += 4
    svc_amt = _f2(_u32(biz, o)) if o + 4 <= len(biz) else None
    o += 4
    o += 8  # 预约费
    o += 8  # 占位费
    elec_fee = _f2(_u32(biz, o)) if o + 4 <= len(biz) else None
    o += 4
    fee_model = to_hex(biz[o : o + 8]) if o + 8 <= len(biz) else None
    o += 8
    total_fee = _f2(_u32(biz, o)) if o + 4 <= len(biz) else None
    o += 4
    stop_raw = int.from_bytes(biz[o : o + 2], "little") if o + 2 <= len(biz) else None
    stop_lo = (stop_raw & 0xFF) if stop_raw is not None else None
    stop_hi = ((stop_raw >> 8) & 0xFF) if stop_raw is not None else None
    o += 2
    user_id = bcd_to_str(biz[o : o + 8]) if o + 8 <= len(biz) else None

    return {
        "record_type": 2,
        "pile_code": pile,
        "gun_no": gun,
        "trade_no": trade,
        "pay_card": pay_card,
        "phys_card": phys_card,
        "tou_flag": tou,
        "start_time": start,
        "end_time": end,
        "meter_type": meter_type,
        "start_meter": start_meter,
        "end_meter": end_meter,
        "total_kwh": total_kwh,
        "biz_type": biz_type,
        "consume_amount": consume_amt,
        "vin": vin or None,
        "service_price": svc_price,
        "service_amount": svc_amt,
        "elec_fee": elec_fee,
        "fee_model_id": fee_model,
        "total_fee": total_fee,
        "stop_reason_code": stop_lo,
        "stop_reason": CSG_STOP_REASON.get(stop_lo or -1, f"原因码{stop_lo}") if stop_lo is not None else None,
        "upload_flag": stop_hi,
        "user_id": user_id,
        "encrypted": False,
    }


def parse_a33_process(biz: bytes) -> dict[str, Any] | None:
    """附录 A.33 充电过程中上传数据。"""
    if len(biz) < 57:
        return None
    if looks_encrypted_business(biz, record_type=17):
        return None
    o = 0
    pile = bcd_to_str(biz[o : o + 8])
    o += 8
    gun = biz[o]
    o += 1
    trade = bcd_to_str(biz[o : o + 16])
    o += 16
    biz_type = bcd_to_str(biz[o : o + 2])
    o += 2
    user_id = bcd_to_str(biz[o : o + 8])
    o += 8
    phys = bcd_to_str(biz[o : o + 8])
    o += 8
    start = _cp56(biz[o : o + 7])
    o += 7
    end = _cp56(biz[o : o + 7])
    o += 7
    o += 32  # 尖峰平谷起止
    tip = _f2(_u32(biz, o))
    o += 4
    peak = _f2(_u32(biz, o))
    o += 4
    flat = _f2(_u32(biz, o))
    o += 4
    valley = _f2(_u32(biz, o))
    o += 4
    total_kwh = _f2(_u32(biz, o))
    o += 4
    o += 16  # 尖峰平谷电费
    total_fee = _f2(_u32(biz, o))
    o += 4
    svc_fee = _f2(_u32(biz, o))
    o += 4
    occupy_fee = _f2(_u32(biz, o))
    o += 4
    meter_type = bcd_to_str(biz[o : o + 2]) if o + 2 <= len(biz) else None
    o += 2
    start_meter = _f2(_u32(biz, o))
    o += 4
    end_meter = _f2(_u32(biz, o))
    o += 4
    tou = biz[o] if o < len(biz) else None
    o += 1
    vin = ""
    if o + 17 <= len(biz):
        vin = biz[o : o + 17].split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()
    o += 17
    charged_min = int.from_bytes(biz[o : o + 2], "little") if o + 2 <= len(biz) else None
    o += 2
    remain_min = int.from_bytes(biz[o : o + 2], "little") if o + 2 <= len(biz) else None
    o += 2
    charge_fee = _f2(_u32(biz, o)) if o + 4 <= len(biz) else None
    o += 4
    order_no = bcd_to_str(biz[o : o + 8]) if o + 8 <= len(biz) else None

    return {
        "record_type": 17,
        "pile_code": pile,
        "gun_no": gun,
        "trade_no": trade,
        "biz_type": biz_type,
        "user_id": user_id,
        "phys_card": phys,
        "start_time": start,
        "end_time": end,
        "tip_kwh": tip,
        "peak_kwh": peak,
        "flat_kwh": flat,
        "valley_kwh": valley,
        "total_kwh": total_kwh,
        "total_fee": total_fee,
        "service_fee": svc_fee,
        "occupy_fee": occupy_fee,
        "meter_type": meter_type,
        "start_meter": start_meter,
        "end_meter": end_meter,
        "tou_flag": tou,
        "vin": vin or None,
        "charged_minutes": charged_min,
        "remain_minutes": remain_min,
        "charge_fee": charge_fee,
        "order_no": order_no,
        "encrypted": False,
    }


def parse_business_payload(
    record_type: int,
    biz: bytes,
    *,
    sm4_key: bytes | str | None = None,
) -> dict[str, Any]:
    """解析类型 130 业务数据；必要时尝试 SM4 解密。"""
    key = resolve_sm4_key(sm4_key)
    encrypted = looks_encrypted_business(biz, record_type=record_type)
    data = biz
    mode = "plain"
    if encrypted and key is not None:
        data, mode = try_decrypt_business(biz, key)
        encrypted = looks_encrypted_business(data, record_type=record_type)

    pile_hint = bcd_to_str(biz[:8]) if len(biz) >= 8 and _bcd_ok(biz[:8], allow_ff=False) else None
    base: dict[str, Any] = {
        "record_type": record_type,
        "encrypted": encrypted,
        "decrypt_mode": mode,
        "payload_len": len(biz),
        "pile_code": pile_hint,
    }

    parsed: dict[str, Any] | None = None
    if record_type == 2:
        parsed = parse_a3_charge_record(data)
    elif record_type == 17:
        parsed = parse_a33_process(data)

    if parsed:
        parsed["decrypt_mode"] = mode
        parsed["payload_len"] = len(biz)
        return parsed

    base["raw_hex_head"] = to_hex(biz[:24])
    if encrypted:
        base["note"] = "业务体疑似 SM4 软加密，需配置 EVCPA_CSG_SM4_KEY 后才能展开订单明细"
    return base
