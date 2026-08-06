"""API /card-auth-query 单测。"""

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


def test_card_auth_query_from_text(client, no_auth_env):
    text = (
        '2026-07-20 10:01:00 {"cardNo":"00000000DDE4BF6B"}\n'
        "2026-07-20 10:01:02 卡未注册，卡号: 00000000DDE4BF6B\n"
        '2026-07-20 10:02:00 {"cardNo":"3527460N0BC4ECXGL"}\n'
        "2026-07-20 10:02:03 VIN卡账户余额不足，卡号: 3527460N0BC4ECXGL\n"
        '2026-07-20 10:03:00 {"cardNo":"LZYTDGBW7H1021627"}\n'
        "2026-07-20 10:03:04 作废卡，卡号: LZYTDGBW7H1021627\n"
    )
    res = client.post("/card-auth-query", json={"text": text})
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is True
    assert body["summary"]["failed"] == 3
    by_card = {e["cardNo"]: e for e in body["events"]}
    assert by_card["00000000DDE4BF6B"]["reason"] == "卡未注册，卡号: 00000000DDE4BF6B"
    assert by_card["00000000DDE4BF6B"]["card_type"] == "刷卡"
    assert by_card["3527460N0BC4ECXGL"]["reason"] == "VIN卡账户余额不足，卡号: 3527460N0BC4ECXGL"
    assert by_card["3527460N0BC4ECXGL"]["card_type"] == "VIN"


def test_card_auth_query_requires_time_when_device(client, no_auth_env):
    res = client.post("/card-auth-query", json={"device_no": "D1"})
    assert res.status_code == 400
