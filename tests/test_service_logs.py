from __future__ import annotations

import pytest

from evcpa.service_logs import fetch_service_logs


def test_fetch_service_logs_posts_service(monkeypatch):
    captured: dict = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"code":1,"data":[{"content":"hello","createTime":"2026-08-05 10:00:00"}]}'

    def fake_urlopen(req, timeout=30.0):
        import json

        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _Resp()

    monkeypatch.setattr("evcpa.service_logs.urllib.request.urlopen", fake_urlopen)
    data = fetch_service_logs(service="S2608050899023698405")
    assert captured["body"] == {"service": "S2608050899023698405"}
    assert "skey=" in captured["url"]
    assert "serviceLogs" in captured["url"]
    assert data["code"] == 1
    assert len(data["data"]) == 1


def test_fetch_service_logs_rejects_empty():
    with pytest.raises(ValueError, match="service"):
        fetch_service_logs(service="  ")
