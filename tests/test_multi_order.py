# -*- coding: utf-8 -*-
from __future__ import annotations

from evcpa.multi_order import build_multi_order_choice, combine_filter
from evcpa.order_report import _discover_orders, analyze_order_log


def test_combine_filter_prefers_trade_no():
    assert combine_filter("sid1", "tn1") == "tn1"
    assert combine_filter("sid1", None) == "sid1"
    assert combine_filter(None, "  ") is None


def test_discover_and_multi_order_choice():
    text = "\n".join(
        [
            '--socInfo:{"deviceNo":"P1","interfaceCode":1,"serviceId":"1001","tradeNo":"0000000000001001","battery":1}',
            '--socInfo:{"deviceNo":"P1","interfaceCode":2,"serviceId":"1002","tradeNo":"0000000000001002","battery":2}',
            '--recordInfo:{"deviceNo":"P1","interfaceCode":1,"serviceId":"1001","tradeNo":"0000000000001001","totalBattery":5000,"chargeMoney":1200}',
            '--recordInfo:{"deviceNo":"P1","interfaceCode":2,"serviceId":"1002","tradeNo":"0000000000001002","totalBattery":8000,"chargeMoney":2000}',
        ]
    )
    orders = _discover_orders(text)
    assert len(orders) == 2
    sids = {o["service_id"] for o in orders}
    assert sids == {"1001", "1002"}

    choice = analyze_order_log(text)
    assert choice["mode"] == "multi_order_choice"
    assert "多个订单" in (choice.get("verdict") or "")
    assert choice["extras"]["order_count"] == 2

    one = analyze_order_log(text, service_id="1002")
    assert one["mode"] == "charging_report"
    fields = {f["name"]: f["value"] for f in one["fields"]}
    assert "1002" in str(fields.get("服务ID", ""))


def test_build_multi_order_choice_shape():
    r = build_multi_order_choice(
        [
            {"service_id": "A", "trade_no": "1", "gun": 1, "energy": 1.2, "money": 3.4},
            {"service_id": "B", "trade_no": "2", "gun": 2},
        ],
        protocol="order_log",
        protocol_name="充电订单日志",
        pile="P1",
    )
    assert r["mode"] == "multi_order_choice"
    assert r["extras"]["need_order_filter"] is True
    assert len(r["extras"]["orders"]) == 2


def test_remote_starts_without_trade_no_not_merged():
    """RemoteCmd 常无 tradeNo；不得因 _norm_id(None)=='None' 把多单并成一单。"""
    text = "\n".join(
        [
            '>>>>>>>>RemoteCmd>>>>>>>>:{"remoteCmd":"17","deviceNo":"P1","interfaceCode":"1","data":{"serviceId":111}}',
            '>>>>>>>>RemoteCmd>>>>>>>>:{"remoteCmd":"17","deviceNo":"P1","interfaceCode":"2","data":{"serviceId":222}}',
            '--chargingInfo:{"deviceNo":"P1","interfaceCode":"1","serviceId":111,"tradeNo":"T111","totalBattery":1000,"chargeMoney":100}',
            '--chargingInfo:{"deviceNo":"P1","interfaceCode":"2","serviceId":222,"tradeNo":"T222","totalBattery":2000,"chargeMoney":200}',
            '--recordInfo:{"deviceNo":"P1","interfaceCode":"1","serviceId":111,"tradeNo":"T111","totalBattery":1000,"chargeMoney":100}',
            '--recordInfo:{"deviceNo":"P1","interfaceCode":"2","serviceId":222,"tradeNo":"T222","totalBattery":2000,"chargeMoney":200}',
        ]
    )
    orders = _discover_orders(text)
    assert len(orders) == 2
    assert {o["service_id"] for o in orders} == {"111", "222"}
    choice = analyze_order_log(text)
    assert choice["mode"] == "multi_order_choice"
    assert choice["extras"]["order_count"] == 2
