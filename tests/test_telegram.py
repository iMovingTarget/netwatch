from __future__ import annotations

import json
import os
import sys
import urllib.error
from pathlib import Path

import pytest

from netwatch.config import load_settings
from netwatch.errors import ConfigError
from netwatch.telegram import MAX_TEXT, Bot, TelegramError, read_token

TOKEN = "123456789:AAE-fake_token_for_tests_0123456789"
API = "https://api.telegram.org"


class FakeApi:
    """Records each request and answers with the next (status, JSON) reply."""

    def __init__(self, *replies: tuple[int, object]) -> None:
        self.replies = list(replies)
        self.requests: list[tuple[str, dict[str, object]]] = []

    def __call__(self, url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
        self.requests.append((url, json.loads(body)))
        status, reply = self.replies.pop(0) if self.replies else (200, {"ok": True})
        return status, json.dumps(reply).encode()


def test_send_posts_plain_text_to_the_chat() -> None:
    api = FakeApi((200, {"ok": True, "result": {"message_id": 1}}))
    Bot(TOKEN, API, api).send(42, "hello", silent=True)
    url, payload = api.requests[0]
    assert url == f"{API}/bot{TOKEN}/sendMessage"
    assert payload["chat_id"] == 42
    assert payload["text"] == "hello"
    assert payload["disable_notification"] is True
    # Plain text: no parse_mode, so a "<" or "_" in an alert can't break the message.
    assert "parse_mode" not in payload


def test_long_text_is_cut_to_telegrams_limit() -> None:
    api = FakeApi()
    Bot(TOKEN, API, api).send(42, "x" * (MAX_TEXT + 100))
    text = api.requests[0][1]["text"]
    assert isinstance(text, str)
    assert len(text) == MAX_TEXT
    assert text.endswith("...")


@pytest.mark.parametrize(
    ("status", "temporary"),
    [(400, False), (401, False), (403, False), (404, False), (429, True), (502, True)],
)
def test_errors_say_whether_retrying_can_help(status: int, temporary: bool) -> None:
    api = FakeApi((status, {"ok": False, "description": "Bad Request: chat not found"}))
    with pytest.raises(TelegramError, match="chat not found") as caught:
        Bot(TOKEN, API, api).send(42, "hello")
    assert caught.value.temporary is temporary


def test_too_many_requests_carries_the_wait_telegram_asked_for() -> None:
    reply = {"ok": False, "description": "Too Many Requests", "parameters": {"retry_after": 7}}
    with pytest.raises(TelegramError) as caught:
        Bot(TOKEN, API, FakeApi((429, reply))).send(42, "hello")
    assert caught.value.temporary
    assert caught.value.retry_after == 7


def test_an_unreachable_api_is_a_temporary_error_without_the_token() -> None:
    def unreachable(url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
        # The worst case: an exception whose text contains the whole URL, token and all.
        raise urllib.error.URLError(f"connection refused for {url}")

    with pytest.raises(TelegramError) as caught:
        Bot(TOKEN, API, unreachable).send(42, "hello")
    assert caught.value.temporary
    assert TOKEN not in str(caught.value)
    assert "<token>" in str(caught.value)


def test_a_reply_that_is_not_json_is_an_error() -> None:
    def garbage(url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
        return 502, b"<html>Bad gateway</html>"

    with pytest.raises(TelegramError, match="HTTP 502") as caught:
        Bot(TOKEN, API, garbage).send(42, "hello")
    assert caught.value.temporary


def test_chats_lists_each_chat_once() -> None:
    updates = [
        {"update_id": 1, "message": {"chat": {"id": 42, "type": "private", "first_name": "Ann"}}},
        {
            "update_id": 2,
            "message": {
                "chat": {"id": 42, "type": "private", "first_name": "Ann", "username": "a"}
            },
        },
        {"update_id": 3, "message": {"chat": {"id": -100, "type": "group", "title": "Home"}}},
        {"update_id": 4, "edited_message": {}},
    ]
    chats = Bot(TOKEN, API, FakeApi((200, {"ok": True, "result": updates}))).chats()
    assert [(c.id, c.kind, c.name) for c in chats] == [
        (42, "private", "Ann @a"),
        (-100, "group", "Home"),
    ]


def test_token_comes_from_systemds_credentials_first(tmp_path: Path) -> None:
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "telegram-bot-token").write_text(TOKEN + "\n")
    settings = load_settings({"NETWATCH_TELEGRAM_TOKEN_FILE": str(tmp_path / "missing")})
    assert read_token(settings, {"CREDENTIALS_DIRECTORY": str(creds)}) == TOKEN


def test_token_falls_back_to_the_file(tmp_path: Path) -> None:
    path = tmp_path / "token"
    path.write_text(f"  {TOKEN}\n")
    settings = load_settings({"NETWATCH_TELEGRAM_TOKEN_FILE": str(path)})
    assert read_token(settings, {}) == TOKEN


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (None, "no Telegram bot token at"),
        ("", "does not hold a bot token"),
        ("paste the token here", "does not hold a bot token"),
    ],
)
def test_a_missing_or_wrong_token_is_a_config_error(
    tmp_path: Path, content: str | None, message: str
) -> None:
    path = tmp_path / "token"
    if content is not None:
        path.write_text(content)
    settings = load_settings({"NETWATCH_TELEGRAM_TOKEN_FILE": str(path)})
    with pytest.raises(ConfigError, match=message) as caught:
        read_token(settings, {})
    assert TOKEN not in str(caught.value)


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX permissions, not root"
)
def test_an_unreadable_token_file_says_only_root_can_read_it(tmp_path: Path) -> None:
    path = tmp_path / "token"
    path.write_text(TOKEN)
    path.chmod(0)
    settings = load_settings({"NETWATCH_TELEGRAM_TOKEN_FILE": str(path)})
    with pytest.raises(ConfigError, match="only root can"):
        read_token(settings, {})
