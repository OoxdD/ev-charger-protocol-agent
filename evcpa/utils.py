from __future__ import annotations

import re
from typing import Any


_HEX_CLEAN = re.compile(r"[^0-9a-fA-F]")


def parse_hex(text: str) -> bytes:
    """Accept hex with spaces, 0x prefixes, commas, or continuous string."""
    cleaned = text.strip()
    cleaned = cleaned.replace("0x", "").replace("0X", "")
    cleaned = _HEX_CLEAN.sub("", cleaned)
    if not cleaned:
        raise ValueError("空十六进制输入")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"十六进制长度必须为偶数，当前 {len(cleaned)}")
    return bytes.fromhex(cleaned)


def to_hex(data: bytes, spaced: bool = True) -> str:
    if spaced:
        return " ".join(f"{b:02X}" for b in data)
    return data.hex().upper()


def bcd_to_str(data: bytes) -> str:
    out = []
    for b in data:
        hi, lo = (b >> 4) & 0x0F, b & 0x0F
        if hi > 9 or lo > 9:
            out.append(f"{b:02X}")
        else:
            out.append(f"{hi}{lo}")
    return "".join(out).rstrip("F").rstrip("f")


def read_u8(data: bytes, offset: int) -> int:
    return data[offset]


def read_u16_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def read_u16_be(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")


def read_u32_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def read_u32_be(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big")


def looks_like_json(text: str) -> bool:
    s = text.strip()
    return (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]"))


def safe_json_loads(text: str) -> dict[str, Any] | list[Any] | None:
    import json

    try:
        return json.loads(text)
    except Exception:
        return None


def crc16_modbus(data: bytes) -> int:
    """CRC16-Modbus (poly 0xA001), used by 云快充."""
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def crc16_xmodem(data: bytes) -> int:
    """CRC-16/XMODEM (poly 0x1021, init 0), used by 蔚景科技协议."""
    crc = 0x0000
    poly = 0x1021
    for b in data:
        for i in range(8):
            bit = ((b >> (7 - i)) & 1) == 1
            c15 = ((crc >> 15) & 1) == 1
            crc = (crc << 1) & 0xFFFF
            if c15 ^ bit:
                crc ^= poly
    return crc & 0xFFFF


def crc32_iso_hdlc(data: bytes) -> int:
    """CRC-32/ISO-HDLC (zlib)，万马协议优先候选。"""
    import zlib

    return zlib.crc32(data) & 0xFFFFFFFF


def crc32_mpeg2(data: bytes) -> int:
    """CRC-32/MPEG-2（不反射、xorout=0），万马备选。"""
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc & 0xFFFFFFFF
