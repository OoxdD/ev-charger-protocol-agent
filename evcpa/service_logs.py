"""按订单 / serviceId 拉取报文（代理外部 Device/serviceLogs）。"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


DEFAULT_SERVICE_LOGS_URL = "http://172.16.1.94:9138/Device/serviceLogs"
DEFAULT_SERVICE_LOGS_SKEY = "B7674FBA87FBB806ED98D1CD3EADDAA2"


def service_logs_config() -> tuple[str, str]:
    url = (os.environ.get("EVCPA_SERVICE_LOGS_URL") or DEFAULT_SERVICE_LOGS_URL).rstrip("?")
    skey = os.environ.get("EVCPA_SERVICE_LOGS_SKEY") or DEFAULT_SERVICE_LOGS_SKEY
    return url, skey


def fetch_service_logs(
    *,
    service: str,
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """调用外部接口按订单号 / serviceId 拉取报文。

    请求体示例：{"service": "S2608050899023698405"}
    """
    service = (service or "").strip()
    if not service:
        raise ValueError("service（订单号 / serviceId）不能为空")

    body: dict[str, Any] = {"service": service}

    base_url, skey = service_logs_config()
    sep = "&" if "?" in base_url else "?"
    url = f"{base_url}{sep}skey={skey}" if "skey=" not in base_url else base_url

    raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=raw,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "Authorization": f"Bearer {skey}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            payload = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
        raise RuntimeError(f"订单报文接口 HTTP {e.code}: {detail[:300]}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"无法连接订单报文接口: {e.reason}") from e

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"订单报文接口返回非 JSON: {payload[:200]}") from e
    if not isinstance(data, dict):
        raise RuntimeError("订单报文接口返回格式异常")
    return data
