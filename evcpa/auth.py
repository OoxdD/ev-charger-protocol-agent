"""Web 登录：环境变量配置账号 + HMAC Cookie 会话。"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, Response, status

COOKIE_NAME = "evcpa_session"
_AUTH_USERS_ENV = "EVCPA_AUTH_USERS"
_AUTH_SECRET_ENV = "EVCPA_AUTH_SECRET"
_AUTH_TTL_ENV = "EVCPA_AUTH_TTL_HOURS"
_DEFAULT_TTL_HOURS = 72


def auth_enabled() -> bool:
    """设置了 EVCPA_AUTH_SECRET 时启用登录门禁。"""
    return bool((os.environ.get(_AUTH_SECRET_ENV) or "").strip())


def _secret() -> str:
    return (os.environ.get(_AUTH_SECRET_ENV) or "").strip()


def auth_ttl_seconds() -> int:
    raw = (os.environ.get(_AUTH_TTL_ENV) or "").strip()
    try:
        hours = float(raw) if raw else _DEFAULT_TTL_HOURS
    except ValueError:
        hours = _DEFAULT_TTL_HOURS
    if hours <= 0:
        hours = _DEFAULT_TTL_HOURS
    return int(hours * 3600)


def parse_auth_users(raw: str | None = None) -> dict[str, str]:
    """解析 EVCPA_AUTH_USERS：user:pass，多组用逗号或分号分隔。"""
    text = raw if raw is not None else (os.environ.get(_AUTH_USERS_ENV) or "")
    users: dict[str, str] = {}
    for part in text.replace(";", ",").split(","):
        item = part.strip()
        if not item or ":" not in item:
            continue
        user, pwd = item.split(":", 1)
        user = user.strip()
        pwd = pwd.strip()
        if user and pwd:
            users[user] = pwd
    return users


def verify_password(username: str, password: str) -> bool:
    users = parse_auth_users()
    expected = users.get(username)
    if expected is None:
        return False
    return hmac.compare_digest(expected, password)


def _sign(payload: str) -> str:
    dig = hmac.new(_secret().encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return dig


def issue_session_token(username: str, *, now: int | None = None) -> str:
    """格式：username|exp|sig"""
    if not auth_enabled():
        raise RuntimeError("auth not enabled")
    ts = int(now if now is not None else time.time())
    exp = ts + auth_ttl_seconds()
    # 用户名不含 |，避免解析歧义
    safe_user = username.replace("|", "")
    payload = f"{safe_user}|{exp}"
    return f"{payload}|{_sign(payload)}"


def parse_session_token(token: str | None, *, now: int | None = None) -> str | None:
    """校验 Cookie，成功返回用户名。"""
    if not token or not auth_enabled():
        return None
    parts = token.split("|")
    if len(parts) != 3:
        return None
    user, exp_s, sig = parts
    if not user or not exp_s or not sig:
        return None
    try:
        exp = int(exp_s)
    except ValueError:
        return None
    ts = int(now if now is not None else time.time())
    if exp < ts:
        return None
    payload = f"{user}|{exp_s}"
    expect = _sign(payload)
    if not hmac.compare_digest(expect, sig):
        return None
    return user


def set_session_cookie(response: Response, username: str) -> None:
    token = issue_session_token(username)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=auth_ttl_seconds(),
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(key=COOKIE_NAME, path="/")


def optional_user(
    evcpa_session: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
) -> str | None:
    """未启用鉴权时返回 None；启用时返回当前用户或 None。"""
    if not auth_enabled():
        return None
    return parse_session_token(evcpa_session)


def require_user(
    evcpa_session: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
) -> str | None:
    """未启用鉴权时放行（返回 None）；启用时必须已登录。"""
    if not auth_enabled():
        return None
    user = parse_session_token(evcpa_session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="未登录或会话已过期",
        )
    return user


RequireUser = Annotated[str | None, Depends(require_user)]
OptionalUser = Annotated[str | None, Depends(optional_user)]
