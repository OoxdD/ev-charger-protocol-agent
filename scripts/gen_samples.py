"""Generate sample YKC frames with valid CRC16-Modbus."""

from __future__ import annotations

from evcpa.utils import crc16_modbus, to_hex


def build_ykc(frame_type: int, body: bytes, seq: int = 1, encrypt: int = 0) -> bytes:
    mid = seq.to_bytes(2, "little") + bytes([encrypt, frame_type]) + body
    length = len(mid)  # 不含起始、长度、CRC
    crc = crc16_modbus(mid).to_bytes(2, "little")
    return bytes([0x68, length]) + mid + crc


def main() -> None:
    # 登录: 桩编码 BCD 3201020000001 -> 32 01 02 00 00 00 01, 直流, 2枪, 协议版本 0x10
    login_body = bytes.fromhex("32010200000001") + bytes([0x00, 0x02, 0x10])
    login = build_ykc(0x01, login_body)
    print("login:", to_hex(login))

    # 心跳: 桩编码 + 枪号1 + 状态0
    hb_body = bytes.fromhex("32010200000001") + bytes([0x01, 0x00])
    hb = build_ykc(0x03, hb_body, seq=2)
    print("heartbeat:", to_hex(hb))

    # 实时监测简版
    rt_body = bytes.fromhex("32010200000001") + bytes([0x01, 0x03]) + bytes(7) + (2200).to_bytes(2, "little") + (320).to_bytes(2, "little")
    # status at [8], pad to offset 16 for voltage
    # body[0:7] pile, [7] gun, [8] status, [9:16] pad, [16:18] V, [18:20] I
    rt_body = bytes.fromhex("32010200000001") + bytes([0x01, 0x03]) + bytes(7) + (2200).to_bytes(2, "little") + (320).to_bytes(2, "little")
    rt = build_ykc(0x13, rt_body, seq=3)
    print("realtime:", to_hex(rt))


if __name__ == "__main__":
    main()
