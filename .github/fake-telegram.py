"""A stand-in for the Telegram Bot API, for CI: answers like Telegram and records every message.

    python3 .github/fake-telegram.py PORT TOKEN MESSAGES_FILE

Listens on 127.0.0.1 only. A request with any other token gets Telegram's 401, so the test also
proves that netwatch-notify got the right token through LoadCredential=. Each sendMessage body
is appended to MESSAGES_FILE as one JSON line.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, TOKEN, MESSAGES = int(sys.argv[1]), sys.argv[2], sys.argv[3]
CHAT = {"id": 42, "type": "private", "first_name": "CI"}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        prefix = f"/bot{TOKEN}/"
        if not self.path.startswith(prefix):
            self._reply(401, {"ok": False, "error_code": 401, "description": "Unauthorized"})
            return
        method = self.path.removeprefix(prefix)
        if method == "sendMessage":
            with open(MESSAGES, "a", encoding="utf-8") as f:
                f.write(json.dumps(body) + "\n")
            self._reply(200, {"ok": True, "result": {"message_id": 1, "chat": CHAT}})
        elif method == "getUpdates":
            self._reply(200, {"ok": True, "result": [{"update_id": 1, "message": {"chat": CHAT}}]})
        else:
            self._reply(404, {"ok": False, "error_code": 404, "description": "Not Found"})

    def _reply(self, status: int, payload: dict[str, object]) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: object) -> None:
        pass  # the request line holds the token


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
