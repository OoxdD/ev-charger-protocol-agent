# -*- coding: utf-8 -*-
from __future__ import annotations

from evcpa.order_report import _infer_start_way, analyze_order_log


def test_infer_card_start_by_marker():
    text = "刷卡鉴权结果，{\"failCode\":\"0000\",\"physicalCardNo\":\"0000000031928D57\"}\n刷卡启动充电执行结果，{}"
    way = _infer_start_way(text, remote=None, start_ok=True, src={}, data={}, card_auth=True)
    assert way.startswith("刷卡启动")


def test_infer_vin_start_by_marker():
    text = "VIN验证启动已正常启动充电，vin号：LFXAH77W6S3016091"
    way = _infer_start_way(text, remote=None, start_ok=True, src={}, data={}, vin_auth=True)
    assert way.startswith("VIN鉴权启动")


def test_infer_vin_by_card_no_prefix():
    way = _infer_start_way(
        "record",
        remote=None,
        start_ok=False,
        src={"cardNo": "VINLVCMBC1E9SS144238", "carvin": "LVCMBC1E9SS144238"},
        data={},
    )
    assert way.startswith("VIN鉴权启动")


def test_infer_remote_start():
    text = "远程启动充电, {\"orderId\":\"1\"}\nRemoteCmd>>>>>>>>:{\"remoteCmd\":17}"
    way = _infer_start_way(
        text,
        remote={"remoteCmd": 17, "data": {}},
        start_ok=True,
        src={},
        data={},
    )
    assert way.startswith("远程启动")


def test_analyze_order_log_card_start_way():
    text = "\n".join(
        [
            "2026-05-08 23:16:17.000 [x] INFO - [pile]刷卡鉴权结果，"
            '{"balance":1000,"failCode":"0000","physicalCardNo":"0000000031928D57","carvin":""}',
            "2026-05-08 23:16:17.100 [x] INFO - [pile]刷卡启动充电执行结果，{\"failCode\":255}",
            "2026-05-08 23:16:20.000 [x] INFO - [pile]1枪:CHARGING",
            "2026-05-08 23:20:00.000 [x] INFO - [pile]--recordInfo:"
            '{"deviceNo":"pile","interfaceCode":1,"tradeNo":"1","totalBattery":1000,'
            '"chargeMoney":100,"serviceMoney":0,"deviceChargeFinishReasonMsg":"充满停止"}',
        ]
    )
    r = analyze_order_log(text)
    assert r["fields"]
    start = next(f for f in r["fields"] if f["name"] == "启动方式")
    assert start["value"].startswith("刷卡启动")
    assert "刷卡" in r["report_text"]
