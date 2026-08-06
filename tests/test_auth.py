"""Web 登录鉴权测试。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from evcpa import auth
from evcpa.api import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_env(monkeypatch):
    monkeypatch.setenv("EVCPA_AUTH_SECRET", "test-secret-key-for-hmac")
    monkeypatch.setenv("EVCPA_AUTH_USERS", "admin:pass123,ops:ops456")
    monkeypatch.setenv("EVCPA_AUTH_TTL_HOURS", "72")
    yield


@pytest.fixture
def no_auth_env(monkeypatch):
    monkeypatch.delenv("EVCPA_AUTH_SECRET", raising=False)
    monkeypatch.delenv("EVCPA_AUTH_USERS", raising=False)
    yield


def test_parse_auth_users():
    users = auth.parse_auth_users("admin:pass123;ops:ops456")
    assert users == {"admin": "pass123", "ops": "ops456"}


def test_session_token_roundtrip(auth_env):
    token = auth.issue_session_token("admin", now=1_000_000)
    assert auth.parse_session_token(token, now=1_000_001) == "admin"
    assert auth.parse_session_token(token, now=1_000_000 + 72 * 3600 + 1) is None
    bad = token[:-4] + "dead"
    assert auth.parse_session_token(bad, now=1_000_001) is None


def test_auth_disabled_allows_protocols(client, no_auth_env):
    me = client.get("/api/me")
    assert me.status_code == 200
    body = me.json()
    assert body["auth_enabled"] is False
    assert body["authenticated"] is True

    res = client.get("/protocols")
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_protected_requires_login(client, auth_env):
    me = client.get("/api/me")
    assert me.status_code == 200
    body = me.json()
    assert body["auth_enabled"] is True
    assert body["authenticated"] is False

    assert client.get("/protocols").status_code == 401
    assert client.post("/analyze", json={"text": "x"}).status_code == 401
    assert client.post(
        "/history-logs",
        json={"device_no": "1", "start_time": 1, "end_time": 2},
    ).status_code == 401
    assert client.post(
        "/card-auth-query",
        json={"text": "卡未注册，卡号: 00000000DDE4BF6B"},
    ).status_code == 401


def test_login_success_and_fail(client, auth_env):
    bad = client.post("/api/login", json={"username": "admin", "password": "wrong"})
    assert bad.status_code == 401

    ok = client.post("/api/login", json={"username": "admin", "password": "pass123"})
    assert ok.status_code == 200
    assert ok.json()["username"] == "admin"
    assert "evcpa_session" in ok.cookies

    me = client.get("/api/me")
    assert me.json()["authenticated"] is True
    assert me.json()["username"] == "admin"

    protocols = client.get("/protocols")
    assert protocols.status_code == 200


def test_logout(client, auth_env):
    client.post("/api/login", json={"username": "ops", "password": "ops456"})
    assert client.get("/protocols").status_code == 200

    out = client.post("/api/logout")
    assert out.status_code == 200
    assert client.get("/protocols").status_code == 401
    me = client.get("/api/me")
    assert me.json()["authenticated"] is False


def test_health_open_when_auth_enabled(client, auth_env):
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200
