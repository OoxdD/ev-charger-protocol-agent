"""设备历史报文拉取（代理外部 Device/historyLogs）。"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


DEFAULT_HISTORY_URL = "http://172.16.1.94:9138/Device/historyLogs"
DEFAULT_HISTORY_SKEY = "B7674FBA87FBB806ED98D1CD3EADDAA2"


def history_logs_config() -> tuple[str, str]:
    url = (os.environ.get("EVCPA_HISTORY_LOGS_URL") or DEFAULT_HISTORY_URL).rstrip("?")
    skey = os.environ.get("EVCPA_HISTORY_LOGS_SKEY") or DEFAULT_HISTORY_SKEY
    return url, skey


def fetch_device_history_logs(
    *,
    device_no: str,
    start_time: int,
    cmd: str | None = None,
    is_send_log: int | None = None,
    sort_type: int | None = 1,
    limit_count: int | None = 1000,
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """调用外部接口拉取设备历史报文。

    startTime 使用毫秒级时间戳（如 1785296760000）。
    """
    device_no = (device_no or "").strip()
    if not device_no:
        raise ValueError("deviceNo 不能为空")
    if start_time is None:
        raise ValueError("startTime 不能为空")

    body: dict[str, Any] = {
        "deviceNo": device_no,
        "startTime": int(start_time),
        "isHexLog": 0,
    }
    if cmd not in (None, ""):
        body["cmd"] = str(cmd).strip()
    if is_send_log is not None:
        body["isSendLog"] = int(is_send_log)
    if sort_type is not None:
        body["sortType"] = int(sort_type)
    if limit_count is not None:
        body["limitCount"] = int(limit_count)

    base_url, skey = history_logs_config()
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
        raise RuntimeError(f"历史报文接口 HTTP {e.code}: {detail[:300]}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"无法连接历史报文接口: {e.reason}") from e

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"历史报文接口返回非 JSON: {payload[:200]}") from e
    if not isinstance(data, dict):
        raise RuntimeError("历史报文接口返回格式异常")
    return data


def logs_to_text(items: list[dict[str, Any]] | None) -> str:
    """将 LogInfo 列表拼成可导入分析的文本。"""
    if not items:
        return ""
    lines: list[str] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        content = str(it.get("content") or "").rstrip()
        if not content:
            continue
        # content 已含完整日志时直接使用；否则补时间与方向前缀
        create_time = str(it.get("createTime") or "").strip()
        is_send = it.get("isSendLog")
        direction = "下行" if str(is_send) in {"1", "True", "true"} else "上行"
        cmd = it.get("cmd")
        if create_time and not content.startswith(create_time[:10]):
            prefix = create_time
            if cmd not in (None, ""):
                prefix = f"{prefix} [cmd={cmd}]"
            prefix = f"{prefix} [{direction}]"
            lines.append(f"{prefix} {content}")
        else:
            lines.append(content)
    return "\n".join(lines)
