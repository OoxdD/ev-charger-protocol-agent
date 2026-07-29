from __future__ import annotations

from evcpa.protocols.ascii68 import Ascii68Parser
from evcpa.protocols.base import ProtocolParser
from evcpa.protocols.cec import CecParser
from evcpa.protocols.csg import CsgParser
from evcpa.protocols.huawei import HuaweiParser
from evcpa.protocols.iec104 import Iec104Parser
from evcpa.protocols.infypower import InfypowerParser
from evcpa.protocols.ocpp import OcppParser
from evcpa.protocols.shenghong import ShenghongParser
from evcpa.protocols.vendors_extra import (
    AbbParser,
    AnyueParser,
    AonengParser,
    DakuyunParser,
    EverchargeParser,
    KamaisiParser,
    KehuaParser,
    KstarParser,
    LvtongParser,
    NariParser,
    PhoenixParser,
    PutianParser,
    SgccParser,
    TeldParser,
    WallboxParser,
    XiaojuParser,
    YouyichongParser,
    ZhichongParser,
)
from evcpa.protocols.wanma import WanmaParser
from evcpa.protocols.weijing import WeijingParser
from evcpa.protocols.xingxing import XingxingParser
from evcpa.protocols.ykc import YkcParser


def all_parsers() -> list[ProtocolParser]:
    return [
        # 主流 / 二进制敏感协议优先（蔚景与云快充均 0x68，靠头结构区分）
        WeijingParser(),
        YkcParser(),
        WanmaParser(),
        Ascii68Parser(),
        ShenghongParser(),
        CsgParser(),
        OcppParser(),
        Iec104Parser(),
        CecParser(),
        XingxingParser(),
        HuaweiParser(),
        InfypowerParser(),
        # 运营商 / 厂商
        TeldParser(),
        SgccParser(),
        XiaojuParser(),
        AonengParser(),
        PutianParser(),
        KehuaParser(),
        KstarParser(),
        AbbParser(),
        EverchargeParser(),
        KamaisiParser(),
        DakuyunParser(),
        YouyichongParser(),
        NariParser(),
        ZhichongParser(),
        AnyueParser(),
        WallboxParser(),
        PhoenixParser(),
        LvtongParser(),
    ]


__all__ = [
    "ProtocolParser",
    "WeijingParser",
    "WanmaParser",
    "YkcParser",
    "XingxingParser",
    "ShenghongParser",
    "HuaweiParser",
    "InfypowerParser",
    "OcppParser",
    "CecParser",
    "CsgParser",
    "Iec104Parser",
    "Ascii68Parser",
    "all_parsers",
]
