"""万马新能源充电桩与平台通讯协议 2020（V1.00）知识库。"""

from __future__ import annotations

PROTOCOL_VERSION = "V1.00"
PROTOCOL_VERSION_NUM = "1.000"

# 起始域两种线序均兼容
WANMA_START_LE = bytes.fromhex("AABB5599")  # 字面序 AA BB 55 99
WANMA_START_BE = bytes.fromhex("9955BBAA")  # 按 u32 LE 写出 0xAABB5599

WANMA_MSGS: dict[int, tuple[str, str]] = {
    0x0001: ("上线请求", "pile->platform"),
    0x0002: ("上线应答", "platform->pile"),
    0x0003: ("下线通知", "both"),
    0x0004: ("密钥下发", "platform->pile"),
    0x0005: ("平台保活", "platform->pile"),
    0x1000: ("费率获取", "pile->platform"),
    0x1001: ("费率下发", "platform->pile"),
    0x1002: ("费率查询", "platform->pile"),
    0x1003: ("费率响应", "pile->platform"),
    0x2000: ("电桩状态", "pile->platform"),
    0x2001: ("电桩故障", "pile->platform"),
    0x2002: ("电桩数据", "pile->platform"),
    0x3000: ("充电鉴权请求", "pile->platform"),
    0x3001: ("充电鉴权响应", "platform->pile"),
    0x3002: ("充电策略设置", "pile->platform"),
    0x3003: ("充电策略响应", "platform->pile"),
    0x3004: ("充电识别码请求", "pile->platform"),
    0x3005: ("充电识别码响应", "platform->pile"),
    0x4000: ("启动充电命令", "platform->pile"),
    0x4001: ("启动充电事件", "pile->platform"),
    0x4002: ("停止充电命令", "platform->pile"),
    0x4003: ("停止充电事件", "pile->platform"),
    0x4004: ("充电电量数据", "pile->platform"),
    0x4005: ("充电功率控制", "platform->pile"),
    0x4006: ("充电记录上报", "pile->platform"),
    0x4007: ("充电记录确认", "platform->pile"),
    0x6000: ("设备信息获取", "platform->pile"),
    0x6001: ("设备信息响应", "pile->platform"),
    0x6002: ("控制板信息获取", "platform->pile"),
    0x6003: ("控制板信息响应", "pile->platform"),
    0x6004: ("远程操作命令", "platform->pile"),
    0x6005: ("远程命令响应", "pile->platform"),
    0x8000: ("固件概要获取", "pile->platform"),
    0x8001: ("固件概要信息", "platform->pile"),
    0x8002: ("固件数据块请求", "pile->platform"),
    0x8003: ("固件数据块响应", "platform->pile"),
    0x8004: ("固件下载完成", "pile->platform"),
}

WANMA_SEND_REASON: dict[int, str] = {
    1: "消息发送",
    2: "消息确认",
}

WANMA_QOS: dict[int, str] = {
    0: "不需确认",
    1: "需确认可重发",
    2: "需确认且同序号只收一次",
}

WANMA_PILE_WORK: dict[int, str] = {
    0: "待机",
    1: "工作",
    2: "维护",
    3: "故障",
}

WANMA_GUN_WORK: dict[int, str] = {
    0: "空闲",
    1: "操作中",
    2: "充电中",
    3: "预约",
    255: "故障",
}

WANMA_START_WAY: dict[int, str] = {
    1: "App",
    2: "第三方",
    3: "刷卡",
    4: "VIN",
}

WANMA_LOGIN_FAIL: dict[int, str] = {
    0: "成功",
    1: "电桩编码不存在",
    255: "其他错误",
}

WANMA_FIELD_LABELS: dict[str, str] = {
    "start_flag": "起始域",
    "msg_code": "消息码",
    "seq": "序列号",
    "total_len": "报文长度",
    "send_reason": "发送原因",
    "qos": "Qos",
    "device_id": "设备编码",
    "body_hex": "数据域十六进制",
    "crc32": "校验码",
    "crc32_calc": "计算校验",
    "hardware_sn": "硬件序列号",
    "proto_major": "协议主版本",
    "proto_minor": "协议子版本",
    "fail_reason": "失败原因",
    "encrypt_flag": "报文加密",
    "sync_time": "同步时间",
    "key_time": "密钥生成时间",
    "sm4_key": "SM4密钥",
    "offline_time": "下线时间",
    "gun_no": "接口标识",
    "start_way": "启动方式",
    "parallel": "并充模式",
    "trade_no": "充电流水号",
    "soc": "SOC",
    "output_voltage": "输出电压",
    "output_current": "输出电流",
    "output_power": "输出功率(估算)",
    "rated_voltage": "额定电压",
    "rated_current": "额定电流",
    "gun_temp": "枪线温度",
    "charge_energy": "充电总电量",
    "charge_money": "充电总费用",
    "need_time_min": "剩余充电时间",
    "slot_count": "分时段数",
    "slot_energy_sum": "分时电量合计",
    "meter_value": "电表读数",
    "meter_value_2": "电表读数2",
}
