"""A small Telegram Bot API client: send a message, list the chats that wrote to the bot.

Standard library only: each call is one HTTPS POST with a JSON body. The Bot API puts the token in
every request URL, so the token must never reach a log line or an error message. Errors carry
Telegram's own description instead ("Unauthorized", "Bad Request: chat not found"), and anything
built from an exception is scrubbed of the token as well.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from netwatch import __version__
from netwatch.config import Settings
from netwatch.errors import ConfigError, NetwatchError

TIMEOUT_S = 15.0
MAX_TEXT = 4096  # Telegram's limit for one message
#: The name the token has under systemd's LoadCredential= (see netwatch-notify.service).
CREDENTIAL_NAME = "telegram-bot-token"
# What @BotFather hands out: the bot's numeric ID, a colon, and a secret part.
_TOKEN = re.compile(r"[0-9]{3,20}:[A-Za-z0-9_-]{20,}")

#: (url, JSON body, timeout) -> (HTTP status, response body). Replaced by a fake in tests.
Transport = Callable[[str, bytes, float], tuple[int, bytes]]


class TelegramError(NetwatchError):
    """Telegram did not accept a request.

    ``temporary`` errors (no connection, a timeout, a server error, too many requests) are worth
    retrying unchanged; the others (a wrong token, an unknown chat, a bot the user blocked) need a
    person to fix the settings. ``retry_after`` is how long Telegram asked us to wait, if it did.
    """

    def __init__(self, message: str, *, temporary: bool, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.temporary = temporary
        self.retry_after = retry_after


@dataclass(frozen=True)
class Chat:
    id: int
    kind: str  # private, group, supergroup or channel
    name: str


def urllib_transport(url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": f"netwatch/{__version__}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        # An error status still has a JSON body with Telegram's description in it.
        with exc:
            return exc.code, exc.read()


def read_token(settings: Settings, environ: Mapping[str, str]) -> str:
    """The bot token: from systemd's credentials directory under the service, else the file."""
    credentials = environ.get("CREDENTIALS_DIRECTORY", "").strip()
    path = Path(credentials) / CREDENTIAL_NAME if credentials else settings.telegram_token_file
    try:
        token = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        raise ConfigError(f"no Telegram bot token at {path} (docs/alerting.md)") from None
    except PermissionError:
        raise ConfigError(
            f"cannot read {path}: only root can (sudo /opt/netwatch/current/venv/bin/netwatch ...)"
        ) from None
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from None
    if not _TOKEN.fullmatch(token):
        raise ConfigError(
            f"{path} does not hold a bot token: expected one line like 123456789:AAE..., as"
            " @BotFather gives it"
        )
    return token


class Bot:
    def __init__(self, token: str, api_url: str, transport: Transport = urllib_transport) -> None:
        self._token = token
        self._api_url = api_url.rstrip("/")
        self._transport = transport

    def send(self, chat_id: int, text: str, *, silent: bool = False) -> None:
        """Send plain text (no Markdown or HTML, so nothing needs escaping)."""
        if len(text) > MAX_TEXT:
            text = text[: MAX_TEXT - 3] + "..."
        self._call(
            "sendMessage",
            {
                "chat_id": chat_id,
                "text": text,
                "disable_notification": silent,
                "link_preview_options": {"is_disabled": True},
            },
        )

    def chats(self) -> list[Chat]:
        """The chats that have messaged the bot recently, to find the chat ID to set."""
        updates = self._call("getUpdates", {"allowed_updates": ["message"]})
        found: dict[int, Chat] = {}
        for update in updates if isinstance(updates, list) else []:
            chat = (update.get("message") or {}).get("chat") or {}
            if "id" not in chat:
                continue
            username = f"@{chat['username']}" if chat.get("username") else ""
            name = chat.get("title") or " ".join(
                part for part in (chat.get("first_name"), chat.get("last_name"), username) if part
            )
            found[int(chat["id"])] = Chat(int(chat["id"]), str(chat.get("type", "?")), name)
        return list(found.values())

    def _call(self, method: str, payload: dict[str, object]) -> object:
        url = f"{self._api_url}/bot{self._token}/{method}"
        try:
            status, raw = self._transport(url, json.dumps(payload).encode(), TIMEOUT_S)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", None) or exc
            raise TelegramError(
                self._scrub(f"cannot reach Telegram: {reason}"), temporary=True
            ) from None
        try:
            reply = json.loads(raw)
        except ValueError:
            reply = None
        if not isinstance(reply, dict):
            reply = {}
        if status == 200 and reply.get("ok") is True:
            return reply.get("result")
        description = str(reply.get("description") or f"HTTP {status}")
        parameters = reply.get("parameters")
        retry_after = parameters.get("retry_after") if isinstance(parameters, dict) else None
        raise TelegramError(
            self._scrub(f"Telegram refused {method}: {description}"),
            temporary=status == 429 or status >= 500,
            retry_after=float(retry_after) if isinstance(retry_after, int | float) else None,
        )

    def _scrub(self, text: str) -> str:
        return text.replace(self._token, "<token>")
