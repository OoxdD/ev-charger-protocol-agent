"""订单报文拉取 API 测试。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from evcpa.api import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def no_auth_env(monkeypatch):
    monkeypatch.delenv("EVCPA_AUTH_SECRET", raising=False)
    monkeypatch.delenv("EVCPA_AUTH_USERS", raising=False)
    yield


def test_service_logs_endpoint(client, no_auth_env, monkeypatch):
    def fake_fetch(*, service: str, timeout_sec: float = 30.0):
        assert service == "S2608050899023698405"
        return {
            "code": 1,
            "msg": "ok",
            "serviceId": 515597830,
            "data": [
                {
                    "content": "2026-08-05 10:00:00.000 > order line",
                    "createTime": "2026-08-05 10:00:00.000",
                    "isSendLog": 0,
                }
            ],
        }

    monkeypatch.setattr("evcpa.api.fetch_service_logs", fake_fetch)
    res = client.post("/service-logs", json={"service": "S2608050899023698405"})
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is True
    assert body["count"] == 1
    assert body["service"] == "S2608050899023698405"
    assert body["service_id"] == "515597830"
    assert "order line" in body["text"]


def test_service_logs_requires_service(client, no_auth_env):
    res = client.post("/service-logs", json={"service": ""})
    assert res.status_code == 422


def test_pages_routes(client, no_auth_env):
    assert client.get("/").status_code == 200
    assert client.get("/device").status_code == 200
    assert client.get("/cards").status_code == 200
