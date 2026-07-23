"""云快充帧类型知识库（常用子集，可扩展）。"""

from __future__ import annotations

# frame_type -> (name, direction, brief)
YKC_FRAME_TYPES: dict[int, tuple[str, str, str]] = {
    0x01: ("登录认证", "pile->platform", "充电桩上线登录"),
    0x02: ("登录认证应答", "platform->pile", "平台对登录结果应答"),
    0x03: ("心跳包", "pile->platform", "桩心跳保活"),
    0x04: ("心跳包应答", "platform->pile", "平台心跳应答"),
    0x05: ("计费模型验证请求", "pile->platform", "计费模型校验"),
    0x06: ("计费模型验证请求应答", "platform->pile", "计费模型校验结果"),
    0x09: ("充电桩计费模型请求", "pile->platform", "请求下发计费模型"),
    0x0A: ("计费模型请求应答", "platform->pile", "下发计费模型"),
    0x12: ("读取实时监测数据", "platform->pile", "平台召测实时数据"),
    0x13: ("上传实时监测数据", "pile->platform", "桩上报实时监测"),
    0x15: ("充电握手", "pile->platform", "BMS 握手信息"),
    0x17: ("参数配置", "pile->platform", "BMS 参数配置"),
    0x19: ("充电结束", "pile->platform", "BMS 充电结束"),
    0x1B: ("错误报文", "pile->platform", "BMS 错误"),
    0x1D: ("BMS 中止", "pile->platform", "BMS 中止充电"),
    0x21: ("充电过程 BMS 需求与充电机输出", "pile->platform", "充电过程数据"),
    0x23: ("充电过程 BMS 信息", "pile->platform", "BMS 信息"),
    0x25: ("主动申请启动充电", "platform->pile", "远程启机"),
    0x26: ("远程启动充电命令回复", "pile->platform", "启机应答"),
    0x27: ("远程停机", "platform->pile", "远程停机"),
    0x28: ("远程停机命令回复", "pile->platform", "停机应答"),
    0x31: ("交易记录", "pile->platform", "订单/交易上送"),
    0x32: ("交易记录确认", "platform->pile", "交易确认"),
    0x33: ("交易记录确认（兼容）", "platform->pile", "交易确认"),
    0x34: ("对时设置", "platform->pile", "平台对时"),
    0x35: ("对时设置应答", "pile->platform", "对时应答"),
    0x36: ("计费模型设置", "platform->pile", "下发费率"),
    0x40: ("充电桩工作参数设置", "platform->pile", "工作参数"),
    0x41: ("充电桩工作参数设置应答", "pile->platform", "参数设置应答"),
    0x42: ("时间同步设置（兼容）", "platform->pile", "对时"),
    0x55: ("远程重启", "platform->pile", "重启指令"),
    0x56: ("远程重启应答", "pile->platform", "重启应答"),
    0x57: ("远程更新", "platform->pile", "OTA 更新"),
    0x58: ("远程更新应答", "pile->platform", "OTA 应答"),
}


# 常用启停失败原因（简化）
YKC_START_FAIL_REASON: dict[int, str] = {
    0x00: "无",
    0x01: "设备编号不匹配",
    0x02: "枪已在充电",
    0x03: "设备故障",
    0x04: "设备离线",
    0x05: "未插枪",
}


YKC_STOP_REASON: dict[int, str] = {
    0x40: "结束充电，APP 远程停止",
    0x41: "结束充电，SOC 达到 100%",
    0x42: "结束充电，充电电量满足设定条件",
    0x43: "结束充电，充电金额满足设定条件",
    0x44: "结束充电，充电时间满足设定条件",
    0x45: "结束充电，手动停止充电",
}
