# EV Charger Protocol Agent

新能源 / 单车充电桩报文分析智能体，自动识别并解析市面常见与冷门充电协议。

## 支持协议

| 协议 | 标识 | 典型形态 |
|------|------|----------|
| 云快充 | `ykc` | TCP 二进制帧 `0x68` + CRC16（**平台协议 V1.7**） |
| 星星充电 | `xingxing` | JSON / MQTT 业务报文 |
| 盛宏 | `shenghong` | 二进制帧 / ASCII 扩展 |
| 华为 | `huawei` | JSON IoT / FusionCharge 风格 |
| 英飞源 | `infypower` | 模块/桩侧二进制与 JSON |
| OCPP | `ocpp` | OCPP 1.6/2.0.1 Call JSON 数组 |
| 中电联互联互通 | `cec` | T/CEC 102.* 平台对接 JSON |
| 特来电 | `teld` | 运营商 JSON / 私有帧 |
| 国家电网 | `sgcc` | 国网风格 JSON / IEC104 衍生 |
| 南方电网 | `csg` | 南网风格 JSON |
| 小桔充电 | `xiaoju` | 滴滴小桔业务 JSON |
| 奥能 | `aoneng` | 厂商 JSON / 私有帧 |
| 普天 | `putian` | 厂商 JSON |
| 科华 | `kehua` | 模块/系统 JSON |
| 科士达 | `kstar` | 厂商 JSON |
| ABB | `abb` | Terra / ChargeBox JSON |
| 依威能源 | `evercharge` | 厂商 JSON |
| 开迈斯 | `kamaisi` | 家用桩 JSON |
| 达克云 | `dakuyun` | 云平台 JSON |
| 优易充 | `youyichong` | 两轮/小功率 JSON |
| IEC104 | `iec104` | IEC 60870-5-104 APDU |
| 南瑞 | `nari` | 电力自动化风格 JSON |
| 智充 | `zhichong` | 厂商 JSON |
| 安悦 | `anyue` | 厂商 JSON |
| Wallbox | `wallbox` | 国际家用桩 JSON |
| Phoenix CHARX | `phoenix` | CHARX 控制盒 JSON |
| 绿通/绿能 | `lvtong` | 厂商 JSON |

完整操作说明见：[docs/操作使用指引.md](docs/操作使用指引.md)

## 快速开始

```bash
cd E:\ev-charger-protocol-agent
python -m venv .venv
.\.venv\Scripts\activate
pip install -e ".[dev]"
```

### CLI

```bash
# 自动识别并分析十六进制报文
evcpa analyze --hex "68 1A 00 00 00 00 00 01 ..."

# 指定协议
evcpa analyze --protocol ykc --hex "681A..."

# 分析 JSON 报文
evcpa analyze --json "{\"cmd\":\"login\",\"pileNo\":\"3201020001\"}"

# 列出已注册协议
evcpa protocols

# 启动可视化分析页面（浏览器打开提示的地址）
evcpa serve --host 0.0.0.0 --port 8080
# 页面: http://127.0.0.1:8080/
# 接口: http://127.0.0.1:8080/docs
```

### Python API

```python
from evcpa.agent import ProtocolAgent

agent = ProtocolAgent()
result = agent.analyze_hex("68 0D 00 00 00 00 00 01 01 00 ...")
print(result.protocol, result.summary)
print(result.fields)
```

## 目录结构

```
evcpa/
  agent.py           # 分析智能体入口
  models.py          # 统一结果模型
  detect.py          # 协议自动识别
  protocols/         # 各厂商解析器
  knowledge/         # 帧类型/告警码知识库
  cli.py             # 命令行
  api.py             # FastAPI
samples/             # 示例报文
tests/
```

## 说明

- 云快充按公开《云快充充电桩与运营平台通信协议》帧格式实现（起始 `0x68`、序列号、加密标志、帧类型、CRC16-Modbus）。
- OCPP 支持 Call / CallResult / CallError JSON 数组识别。
- IEC104 与云快充均可能以 `0x68` 开头；解析器会用控制域/CRC/帧类型做互斥打分。
- 特来电 / 国网 / 南网 / 小桔及多数冷门厂商以公开字段与品牌关键字做启发式识别；私有字段可在 `protocols/` 下增量扩展。
- 智能体输出：协议判定、置信度、帧类型释义、字段表、异常/告警提示、人工可读摘要。
