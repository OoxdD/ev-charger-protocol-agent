"""多帧粘包拆分：云快充 / 蔚景 / 万马。"""

from __future__ import annotations

from dataclasses import dataclass

from evcpa.utils import crc16_modbus, crc16_xmodem, crc32_iso_hdlc, crc32_mpeg2, read_u16_be, read_u16_le, read_u32_le


@dataclass
class FrameSlice:
    offset: int
    data: bytes
    protocol_hint: str | None = None  # ykc | weijing | wanma


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
    body_len = total - 24
    if body_len and body_len % 16 != 0:
        # 仍允许拆出，后续 warn
        pass
    return total


def _wanma_crc_ok(frame: bytes) -> bool:
    if len(frame) < 24:
        return False
    recv = read_u32_le(frame, len(frame) - 4)
    payload = frame[:-4]
    return crc32_iso_hdlc(payload) == recv or crc32_mpeg2(payload) == recv


def _score_ykc(frame: bytes) -> float:
    if not _ykc_len_at(frame, 0) or len(frame) != (_ykc_len_at(frame, 0) or -1):
        return 0.0
    # 蔚景头也会是 0x68，用 CRC + 非 ASCII 桩号头区分
    if _weijing_len_at(frame, 0) and _weijing_crc_ok(frame):
        return 0.1
    return 0.9 if _ykc_crc_ok(frame) else 0.45


def _score_weijing(frame: bytes) -> float:
    if not _weijing_len_at(frame, 0):
        return 0.0
    return 0.95 if _weijing_crc_ok(frame) else 0.5


def _score_wanma(frame: bytes) -> float:
    if not _wanma_len_at(frame, 0):
        return 0.0
    return 0.95 if _wanma_crc_ok(frame) else 0.55


def classify_frame(frame: bytes) -> str | None:
    scores = {
        "ykc": _score_ykc(frame),
        "weijing": _score_weijing(frame),
        "wanma": _score_wanma(frame),
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
        # 万马优先扫 magic（与 0x68 无关）
        if i + 4 <= n and raw[i : i + 4] in (
            bytes.fromhex("AABB5599"),
            bytes.fromhex("9955BBAA"),
        ):
            L = _wanma_len_at(raw, i)
            if L:
                frame = raw[i : i + L]
                out.append(FrameSlice(offset=i, data=frame, protocol_hint="wanma"))
                i += L
                continue

        if raw[i] == 0x68:
            yL = _ykc_len_at(raw, i)
            wL = _weijing_len_at(raw, i)
            candidates: list[tuple[str, int, float]] = []
            if yL:
                fr = raw[i : i + yL]
                candidates.append(("ykc", yL, _score_ykc(fr)))
            if wL:
                fr = raw[i : i + wL]
                candidates.append(("weijing", wL, _score_weijing(fr)))
            if candidates:
                hint, L, _ = max(candidates, key=lambda x: x[2])
                out.append(FrameSlice(offset=i, data=raw[i : i + L], protocol_hint=hint))
                i += L
                continue
            # 无法确定长度：跳过该 0x68，继续扫描
            i += 1
            continue

        i += 1

    # 若完全拆不出，整包当作单帧兜底（保持旧行为）
    if not out and raw:
        hint = classify_frame(raw)
        out.append(FrameSlice(offset=0, data=raw, protocol_hint=hint))
    return out


def looks_like_multi_hex(raw: bytes) -> bool:
    frames = split_frames(raw)
    return len(frames) >= 2
