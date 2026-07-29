from __future__ import annotations

from evcpa.history_logs import logs_to_text


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
