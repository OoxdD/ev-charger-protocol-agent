"""多帧粘包拆分：云快充 / 蔚景 / 万马 / 盛弘 / 南网。"""

from __future__ import annotations

from dataclasses import dataclass

from evcpa.utils import crc16_modbus, crc16_xmodem, crc32_iso_hdlc, crc32_mpeg2, read_u16_be, read_u16_le, read_u32_le


@dataclass
class FrameSlice:
    offset: int
    data: bytes
    protocol_hint: str | None = None  # ykc | weijing | wanma | shenghong | csg


def _ykc_len_at(raw: bytes, i: int) -> int | None:
    if i + 2 > len(raw) or raw[i] != 0x68:
        return None
    data_len = raw[i + 1]
    total = 2 + data_len + 2
    if data_len < 4 or total < 8 or i + total > len(raw):
        return None
    return total


def _ykc_crc_ok(frame: bytes) -> bool:
    if len(frame) < 8:
        return False
    recv = int.from_bytes(frame[-2:], "little")
    return crc16_modbus(frame[2:-2]) == recv


def _weijing_len_at(raw: bytes, i: int) -> int | None:
    if i + 12 > len(raw) or raw[i] != 0x68:
        return None
    n = raw[i + 4]
    if n < 1 or n > 64:
        return None
    enc_off = i + 5 + n
    if enc_off + 3 + 2 > len(raw):
        return None
    pile = raw[i + 5 : i + 5 + n].rstrip(b"\x00")
    if not pile or any(b < 0x20 or b > 0x7E for b in pile):
        return None
    body_len = read_u16_be(raw, enc_off + 1)
    total = 5 + n + 3 + body_len + 2
    if i + total > len(raw):
        return None
    return total


def _weijing_crc_ok(frame: bytes) -> bool:
    if len(frame) < 12:
        return False
    recv = read_u16_be(frame, len(frame) - 2)
    return crc16_xmodem(frame[:-2]) == recv


def _wanma_len_at(raw: bytes, i: int) -> int | None:
    if i + 24 > len(raw):
        return None
    magic = raw[i : i + 4]
    if magic not in (bytes.fromhex("AABB5599"), bytes.fromhex("9955BBAA")):
        return None
    total = read_u16_le(raw, i + 8)
    if total < 24 or total > 500 or i + total > len(raw):
        return None
    return total


def _wanma_crc_ok(frame: bytes) -> bool:
    if len(frame) < 24:
        return False
    recv = read_u32_le(frame, len(frame) - 4)
    payload = frame[:-4]
    return crc32_iso_hdlc(payload) == recv or crc32_mpeg2(payload) == recv


def _shenghong_len_at(raw: bytes, i: int) -> int | None:
    if i + 9 > len(raw) or raw[i] != 0xAA or raw[i + 1] != 0xF5:
        return None
    total = read_u16_le(raw, i + 2)
    if total < 9 or total > 0x8000 or i + total > len(raw):
        return None
    return total


def _shenghong_sum_ok(frame: bytes) -> bool:
    if len(frame) < 9:
        return False
    cmd = read_u16_le(frame, 6)
    body = frame[8:-1]
    total = (cmd & 0xFF) + ((cmd >> 8) & 0xFF) + sum(body)
    return (total & 0xFF) == frame[-1]


def _csg_len_at(raw: bytes, i: int) -> int | None:
    """南网：68 + 2字节长度 + 控制/标识。"""
    if i + 6 > len(raw) or raw[i] != 0x68:
        return None
    if i + 4 <= len(raw) and raw[i + 3] == 0xFF:
        flen = read_u16_le(raw, i + 1)
        for total in (flen + 3, flen):
            if 10 <= total <= 64 and i + total <= len(raw):
                return total
        return None
    apdu_len = read_u16_le(raw, i + 1) & 0x07FF
    total = apdu_len + 3
    if apdu_len < 4 or total > 2048 or i + total > len(raw):
        return None
    return total


def _score_ykc(frame: bytes) -> float:
    if not _ykc_len_at(frame, 0) or len(frame) != (_ykc_len_at(frame, 0) or -1):
        return 0.0
    if _weijing_len_at(frame, 0) and _weijing_crc_ok(frame):
        return 0.1
    if _csg_len_at(frame, 0) and len(frame) >= 8 and frame[3] == 0xFF:
        return 0.05
    return 0.9 if _ykc_crc_ok(frame) else 0.45


def _score_weijing(frame: bytes) -> float:
    if not _weijing_len_at(frame, 0):
        return 0.0
    return 0.95 if _weijing_crc_ok(frame) else 0.5


def _score_wanma(frame: bytes) -> float:
    if not _wanma_len_at(frame, 0):
        return 0.0
    return 0.95 if _wanma_crc_ok(frame) else 0.55


def _score_shenghong(frame: bytes) -> float:
    if not _shenghong_len_at(frame, 0):
        return 0.0
    return 0.95 if _shenghong_sum_ok(frame) else 0.6


def _score_csg(frame: bytes) -> float:
    L = _csg_len_at(frame, 0)
    if not L or len(frame) != L:
        return 0.0
    if frame[3] == 0xFF:
        return 0.92
    if len(frame) >= 8 and (frame[3] & 0x01) == 0:
        type_id = frame[7]
        if type_id in {130, 132, 133, 134}:
            return 0.9
        if type_id in {1, 11, 15, 100, 101, 103}:
            return 0.7
    return 0.55


def classify_frame(frame: bytes) -> str | None:
    scores = {
        "ykc": _score_ykc(frame),
        "weijing": _score_weijing(frame),
        "wanma": _score_wanma(frame),
        "shenghong": _score_shenghong(frame),
        "csg": _score_csg(frame),
    }
    best = max(scores, key=scores.get)
    if scores[best] <= 0:
        return None
    return best


def split_frames(raw: bytes) -> list[FrameSlice]:
    """从粘包/多帧十六进制缓冲中拆出完整帧。"""
    if not raw:
        return []
    out: list[FrameSlice] = []
    i = 0
    n = len(raw)
    while i < n:
        if i + 4 <= n and raw[i : i + 4] in (
            bytes.fromhex("AABB5599"),
            bytes.fromhex("9955BBAA"),
        ):
            L = _wanma_len_at(raw, i)
            if L:
                out.append(FrameSlice(offset=i, data=raw[i : i + L], protocol_hint="wanma"))
                i += L
                continue

        if i + 2 <= n and raw[i] == 0xAA and raw[i + 1] == 0xF5:
            L = _shenghong_len_at(raw, i)
            if L:
                out.append(FrameSlice(offset=i, data=raw[i : i + L], protocol_hint="shenghong"))
                i += L
                continue

        if raw[i] == 0x68:
            yL = _ykc_len_at(raw, i)
            wL = _weijing_len_at(raw, i)
            cL = _csg_len_at(raw, i)
            candidates: list[tuple[str, int, float]] = []
            if yL:
                fr = raw[i : i + yL]
                candidates.append(("ykc", yL, _score_ykc(fr)))
            if wL:
                fr = raw[i : i + wL]
                candidates.append(("weijing", wL, _score_weijing(fr)))
            if cL:
                fr = raw[i : i + cL]
                candidates.append(("csg", cL, _score_csg(fr)))
            if candidates:
                hint, L, _ = max(candidates, key=lambda x: x[2])
                out.append(FrameSlice(offset=i, data=raw[i : i + L], protocol_hint=hint))
                i += L
                continue
            i += 1
            continue

        i += 1

    if not out and raw:
        hint = classify_frame(raw)
        out.append(FrameSlice(offset=0, data=raw, protocol_hint=hint))
    return out


def looks_like_multi_hex(raw: bytes) -> bool:
    frames = split_frames(raw)
    return len(frames) >= 2
