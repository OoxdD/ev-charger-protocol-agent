from __future__ import annotations

import pytest

from evcpa.history_logs import fetch_device_history_logs, logs_to_text


def test_logs_to_text_joins_content():
    text = logs_to_text(
        [
            {
                "cmd": "0x13",
                "content": "2026-07-27 22:00:05.697 > hello",
                "createTime": "2026-07-27 22:00:05.697",
                "isSendLog": 0,
            },
            {
                "cmd": "17",
                "content": "RemoteCmd blah",
                "createTime": "2026-07-27 22:00:21.000",
                "isSendLog": 1,
            },
        ]
    )
    assert "2026-07-27 22:00:05.697 > hello" in text
    assert "下行" in text
    assert "RemoteCmd blah" in text


def test_logs_to_text_empty():
    assert logs_to_text(None) == ""
    assert logs_to_text([]) == ""


def test_fetch_pads_start_end_and_omits_limit(monkeypatch):
    captured: dict = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"code":1,"data":[]}'

    def fake_urlopen(req, timeout=30.0):
        import json

        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _Resp()

    monkeypatch.setattr("evcpa.history_logs.urllib.request.urlopen", fake_urlopen)
    # 10:01 → 10:00；10:30 → 10:33（毫秒）
    start = 1_700_000_000_000 + (10 * 3600 + 1 * 60) * 1000
    end = 1_700_000_000_000 + (10 * 3600 + 30 * 60) * 1000
    fetch_device_history_logs(device_no="D1", start_time=start, end_time=end)
    body = captured["body"]
    assert body["startTime"] == start - 60_000
    assert body["endTime"] == end + 3 * 60_000
    assert "limitCount" not in body
    assert body["isHexLog"] == 0


def test_fetch_rejects_inverted_range():
    with pytest.raises(ValueError, match="endTime"):
        fetch_device_history_logs(device_no="D1", start_time=2000, end_time=1000)
