"""国内运营商 / 冷门厂商 JSON 启发式解析器集合。"""

from __future__ import annotations

from evcpa.models import ProtocolId
from evcpa.protocols.json_heuristic import JsonHeuristicParser


class TeldParser(JsonHeuristicParser):
    protocol_id = ProtocolId.TELD
    protocol_name = "特来电"
    KEYS = {
        "pileCode", "gunNo", "teld", "TELD", "stationId", "orderId",
        "chargeStatus", "soc", "outVoltage", "outCurrent", "totalPower",
        "billCode", "terminalCode",
    }
    KEYWORDS = ("teld", "特来电", "teladian")
    STATUS_VENDOR = "teld"
    BINARY_MAGIC = b"\xAA\x75"


class SgccParser(JsonHeuristicParser):
    protocol_id = ProtocolId.SGCC
    protocol_name = "国家电网"
    KEYS = {
        "sgcc", "SGCC", "stateGrid", "equipId", "assetNo", "consNo",
        "chargePileNo", "gunId", "workStatus", "meterValue", "aPhaseVoltage",
    }
    KEYWORDS = ("sgcc", "stategrid", "国家电网", "国网", "eichong")
    STATUS_VENDOR = "sgcc"
    BINARY_MAGIC = b"\xEB\x90"


class XiaojuParser(JsonHeuristicParser):
    protocol_id = ProtocolId.XIAOJU
    protocol_name = "小桔充电"
    KEYS = {
        "xiaoju", "xjl", "didi", "connector_id", "charge_seq", "station_id",
        "power", "electricity", "gun_status", "full_charge",
    }
    KEYWORDS = ("xiaoju", "小桔", "didi", "xiaojucharge")
    STATUS_VENDOR = "xiaoju"


class AonengParser(JsonHeuristicParser):
    protocol_id = ProtocolId.AONENG
    protocol_name = "奥能"
    KEYS = {"aoneng", "AONeng", "pileSn", "gunIndex", "workState", "alarmCode", "bmsSoc"}
    KEYWORDS = ("aoneng", "奥能", "allinonecharge")
    STATUS_VENDOR = "aoneng"
    BINARY_MAGIC = b"\x7E\x7E"


class PutianParser(JsonHeuristicParser):
    protocol_id = ProtocolId.PUTIAN
    protocol_name = "普天"
    KEYS = {"putian", "ptn", "pileCode", "gunId", "chargeMode", "meterKwh", "faultCode"}
    KEYWORDS = ("putian", "普天", "potevio")
    STATUS_VENDOR = "putian"


class KehuaParser(JsonHeuristicParser):
    protocol_id = ProtocolId.KEHUA
    protocol_name = "科华"
    KEYS = {"kehua", "KH", "moduleId", "dcVoltage", "dcCurrent", "moduleStatus", "pduId"}
    KEYWORDS = ("kehua", "科华", "kehuadata")
    STATUS_VENDOR = "kehua"
    BINARY_MAGIC = b"\xA5\x5A"


class KstarParser(JsonHeuristicParser):
    protocol_id = ProtocolId.KSTAR
    protocol_name = "科士达"
    KEYS = {"kstar", "KSTAR", "cabinetId", "gunNo", "outputPower", "alarmBits", "envTemp"}
    KEYWORDS = ("kstar", "科士达")
    STATUS_VENDOR = "kstar"


class AbbParser(JsonHeuristicParser):
    protocol_id = ProtocolId.ABB
    protocol_name = "ABB"
    KEYS = {
        "abb", "ABB", "terra", "serialNumber", "chargeBoxIdentity",
        "evseId", "sessionId", "deliveredEnergy",
    }
    KEYWORDS = ("abb", "terra", "chargeboxidentity")
    STATUS_VENDOR = "abb"


class EverchargeParser(JsonHeuristicParser):
    protocol_id = ProtocolId.EVERCHARGE
    protocol_name = "依威能源"
    KEYS = {"evercharge", "evpower", "ew", "deviceSn", "socketId", "orderSn", "usedKwh"}
    KEYWORDS = ("evercharge", "依威", "evpower", "everex")
    STATUS_VENDOR = "evercharge"


class KamaisiParser(JsonHeuristicParser):
    protocol_id = ProtocolId.KAMAISI
    protocol_name = "开迈斯"
    KEYS = {"kamaisi", "cams", "wallboxSn", "plugStatus", "currentA", "voltageV", "energyKwh"}
    KEYWORDS = ("kamaisi", "开迈斯", "cams")
    STATUS_VENDOR = "kamaisi"


class DakuyunParser(JsonHeuristicParser):
    protocol_id = ProtocolId.DAKUYUN
    protocol_name = "达克云"
    KEYS = {"dakuyun", "dake", "cloudPileId", "portNo", "online", "powerW", "energyWh"}
    KEYWORDS = ("dakuyun", "达克云", "dakecloud")
    STATUS_VENDOR = "dakuyun"


class YouyichongParser(JsonHeuristicParser):
    protocol_id = ProtocolId.YOUYICHONG
    protocol_name = "优易充"
    KEYS = {"youyichong", "yyc", "pileId", "portId", "chargeState", "remainTime", "fee"}
    KEYWORDS = ("youyichong", "优易充", "ueasy")
    STATUS_VENDOR = "youyichong"


class NariParser(JsonHeuristicParser):
    protocol_id = ProtocolId.NARI
    protocol_name = "南瑞"
    KEYS = {"nari", "NARI", "rtuId", "ycValue", "yxStatus", "ykCmd", "bayId"}
    KEYWORDS = ("nari", "南瑞", "nrelectric")
    STATUS_VENDOR = "nari"


class ZhichongParser(JsonHeuristicParser):
    protocol_id = ProtocolId.ZHICHONG
    protocol_name = "智充"
    KEYS = {"zhichong", "izchong", "evseCode", "connectorCode", "sessionCode", "meterReading"}
    KEYWORDS = ("zhichong", "智充", "izchong")
    STATUS_VENDOR = "zhichong"


class AnyueParser(JsonHeuristicParser):
    protocol_id = ProtocolId.ANYUE
    protocol_name = "安悦"
    KEYS = {"anyue", "ancharge", "pileNumber", "gunNumber", "tradeNo", "stopReason"}
    KEYWORDS = ("anyue", "安悦", "ancharge")
    STATUS_VENDOR = "anyue"


class WallboxParser(JsonHeuristicParser):
    protocol_id = ProtocolId.WALLBOX
    protocol_name = "Wallbox"
    KEYS = {"wallbox", "chargerId", "uid", "added_energy", "max_current", "locked_current"}
    KEYWORDS = ("wallbox", "pulsar", "commander")
    STATUS_VENDOR = "wallbox"


class PhoenixParser(JsonHeuristicParser):
    protocol_id = ProtocolId.PHOENIX
    protocol_name = "Phoenix CHARX"
    KEYS = {"phoenix", "charx", "evse", "cp_state", "pp_state", "pwm_duty", "proximity"}
    KEYWORDS = ("phoenix", "charx", "phoenixcontact")
    STATUS_VENDOR = "phoenix"


class LvtongParser(JsonHeuristicParser):
    protocol_id = ProtocolId.LVTONG
    protocol_name = "绿通/绿能"
    KEYS = {"lvtong", "greenpower", "lvneng", "pileSn", "gunSn", "chargeKwh", "alarmList"}
    KEYWORDS = ("lvtong", "绿通", "绿能", "lvneng", "greenpower")
    STATUS_VENDOR = "lvtong"
