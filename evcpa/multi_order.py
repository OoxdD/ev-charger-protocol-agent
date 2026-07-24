"""多订单筛选与提示。"""

from __future__ import annotations

from typing import Any


def norm_id(v: Any) -> str:
    s = str(v or "").strip()
    if not s or s == "-":
        return ""
    if set(s) <= {"0"}:
        return ""
    if s.isdigit():
        return str(int(s))
    return s


def combine_filter(service_id: str | None = None, trade_no: str | None = None) -> str | None:
    """优先流水号，其次服务 ID；忽略空值与全 0。"""
    import re

    for v in (trade_no, service_id):
        s = (v or "").strip()
        if not s:
            continue
        if re.fullmatch(r"0+", s):
            continue
        return s
    return None


def id_matches(candidate: Any, filter_id: str | None) -> bool:
    if not filter_id:
        return True
    raw = str(candidate or "").strip()
    if not raw or raw == "-":
        return False
    c = norm_id(candidate)
    f = norm_id(filter_id)
    if not f:
        return True
    if c and f and c == f:
        return True
    return filter_id.strip() == raw or (c and filter_id.strip() == c) or (f and raw == f)


def order_matches_filter(order: dict[str, Any], filter_id: str | None) -> bool:
    if not filter_id:
        return True
    for key in ("trade_no", "service_id", "serviceId", "txn_id", "order_id"):
        val = order.get(key)
        if val in (None, "", "-"):
            continue
        if id_matches(val, filter_id):
            return True
    return False


def build_multi_order_choice(
    orders: list[dict[str, Any]],
    *,
    protocol: str = "unknown",
    protocol_name: str = "未知",
    pile: str | None = None,
) -> dict[str, Any]:
    """多订单且未指定筛选条件时，提示用户输入 serviceId / tradeNo。"""
    points = [
        f"1. 该报文解析出 {len(orders)} 笔订单（多枪同时充电时常见）。",
    ]
    n = 2
    if pile:
        points.append(f"{n}. 充电桩：{pile}。")
        n += 1
    points.append(f"{n}. 请在左侧填写「服务ID」或「流水号」后重新分析，以锁定单笔订单。")
    n += 1
    points.append(f"{n}. 也可点击下方订单条目，自动填入对应流水号/服务ID。")
    n += 1

    fields: list[dict[str, Any]] = [
        {"name": "订单笔数", "value": str(len(orders))},
        {"name": "充电桩编号", "value": pile or "-"},
    ]
    choice_orders: list[dict[str, Any]] = []
    for i, o in enumerate(orders, 1):
        sid = o.get("service_id") or o.get("serviceId") or "-"
        tn = o.get("trade_no") or o.get("txn_id") or "-"
        gun = o.get("gun")
        energy = o.get("energy") if o.get("energy") is not None else o.get("bill_energy")
        money = o.get("money") if o.get("money") is not None else o.get("bill_money")
        fields.extend(
            [
                {"name": f"订单{i} 服务ID", "value": sid},
                {"name": f"订单{i} 流水号", "value": tn},
                {"name": f"订单{i} 枪口", "value": f"{gun} 枪" if gun is not None else "-"},
                {
                    "name": f"订单{i} 电量",
                    "value": f"{energy} kWh" if energy is not None else "-",
                },
                {
                    "name": f"订单{i} 费用",
                    "value": f"{money} 元" if money is not None else "-",
                },
            ]
        )
        choice_orders.append(
            {
                "index": i,
                "service_id": None if sid == "-" else sid,
                "trade_no": None if tn == "-" else tn,
                "gun": gun,
                "energy": energy,
                "money": money,
                "start_way": o.get("start_way"),
                "stop_reason": o.get("stop_reason"),
            }
        )
        points.append(
            f"{n}. 订单{i}：服务ID={sid}，流水号={tn}，枪口={gun if gun is not None else '-'}"
        )
        n += 1

    verdict = "该报文有多个订单，请选择并输入服务ID或流水号再进行解析。"
    return {
        "mode": "multi_order_choice",
        "protocol": protocol,
        "protocol_name": protocol_name,
        "confidence": 0.85,
        "frame_type": None,
        "frame_type_name": f"多订单待选择（{len(orders)} 笔）",
        "valid": False,
        "summary": "\n".join(points + ["", verdict]),
        "conclusion": f"报文含 {len(orders)} 笔订单，需指定服务ID/流水号后重新分析。",
        "verdict": verdict,
        "result_points": points,
        "report_text": "\n".join(["多订单选择提示", "", *points, "", verdict]),
        "fields": fields,
        "warnings": [
            {
                "code": "MULTI_ORDER",
                "level": "warn",
                "message": "检测到多个订单，请输入服务ID(service_Id)或流水号(tradeNo)后重新解析",
            }
        ],
        "extras": {
            "need_order_filter": True,
            "order_count": len(orders),
            "orders": choice_orders,
            "pile": pile,
        },
    }
