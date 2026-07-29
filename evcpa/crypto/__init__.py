"""轻量国密算法（南网 SM4 软加密等）。"""

from evcpa.crypto.sm4 import sm4_ecb_decrypt, sm4_ecb_encrypt

__all__ = ["sm4_ecb_decrypt", "sm4_ecb_encrypt"]
