"""从平台协议抓包日志中按行提取二进制帧。

典型行：
2026-07-22 06:03:07.700 > 【24001031030207】【上报 0x13】 6840...
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from evcpa.utils import parse_hex

_LINE_FRAME = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    r".*?"
    r"【(?P<pile>[^】]+)】"
    r"(?:【(?P<dir>上报|下发)\s*0x(?P<cmd>[0-9A-Fa-f]{2,4})】)?"
    r"\s*(?P<hex>(?:68|9955BBAA|AABB5599)[0-9A-Fa-f]{10,})",
    re.IGNORECASE,
)

# 兼容无桩号括号、仅有上报/下发标记的行（含万马 0x2002 等 4 位命令字）
_LINE_FRAME_LOOSE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)?"
    r".*?"
    r"【(?P<dir>上报|下发)\s*0x(?P<cmd>[0-9A-Fa-f]{2,4})】"
    r"\s*(?P<hex>(?:68|9955BBAA|AABB5599)[0-9A-Fa-f]{10,})",
    re.IGNORECASE,
)


@dataclass
class LogFrame:
    ts: str | None
    pile: str | None
    direction: str | None  # 上报/下发
    cmd_hint: str | None
    hex_text: str
    data: bytes
    line_no: int


def looks_like_protocol_trace_log(text: str) -> bool:
    if not text or len(text) < 40:
        return False
    # 强特征：日志时间 + 【上报/下发 0xNN】 + 已知帧头
    hit_dir = len(re.findall(r"【(?:上报|下发)\s*0x[0-9A-Fa-f]{2,4}】", text))
    hit_frame = len(
        re.findall(r"(?i)(?:^|[^0-9A-Fa-f])(68|9955BBAA|AABB5599)[0-9A-Fa-f]{10,}", text)
    )
    hit_ts = len(re.findall(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}", text[:5000]))
    if hit_dir >= 2 and hit_frame >= 2 and hit_ts >= 1:
        return True
    # 单行粘贴：【上报 0x2002】 + 万马/云快充帧
    return hit_dir >= 1 and hit_frame >= 1


def extract_frames_from_protocol_log(text: str) -> list[LogFrame]:
    frames: list[LogFrame] = []
    seen: set[tuple[int, str]] = set()
    for i, line in enumerate(text.splitlines(), 1):
        m = _LINE_FRAME.search(line) or _LINE_FRAME_LOOSE.search(line)
        if not m:
            continue
        hx = m.group("hex")
        try:
            data = parse_hex(hx)
        except ValueError:
            continue
        key = (i, hx[:32])
        if key in seen:
            continue
        seen.add(key)
        gd = m.groupdict()
        frames.append(
            LogFrame(
                ts=gd.get("ts"),
                pile=(gd.get("pile") or "").strip() or None,
                direction=gd.get("dir"),
                cmd_hint=(gd.get("cmd") or "").upper() or None,
                hex_text=hx,
                data=data,
                line_no=i,
            )
        )
    return frames
