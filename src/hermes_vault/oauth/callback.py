"""Ephemeral OAuth callback HTTP server.

Handles exactly one GET request on /callback, extracts query parameters,
then signals the main thread and shuts down.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse


@dataclass
class CallbackResult:
    """Result from the OAuth provider callback."""
    code: str | None = None
    state: str | None = None
    error: str | None = None
    error_description: str | None = None


class CallbackHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for the OAuth callback route."""

    _result: CallbackResult | None = None
    _event: threading.Event | None = None

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/callback":
            self._send_html(404, "Not found", "Only /callback is served.")
            return

        qs = parse_qs(parsed.query)

        # parse_qs returns lists; flatten
        result = CallbackResult(
            code=self._first(qs.get("code")),
            state=self._first(qs.get("state")),
            error=self._first(qs.get("error")),
            error_description=self._first(qs.get("error_description")),
        )

        if CallbackHandler._result is not None:
            CallbackHandler._result.code = result.code
            CallbackHandler._result.state = result.state
            CallbackHandler._result.error = result.error
            CallbackHandler._result.error_description = result.error_description

        if CallbackHandler._event is not None:
            CallbackHandler._event.set()

        if result.error:
            self._send_html(
                200,
                "Authorization failed",
                (
                    f"Authorization failed: {result.error}.\n"
                    f"{result.error_description or ''}"
                ),
            )
        else:
            self._send_html(
                200,
                "Authorization complete",
                (
                    "Authorization complete.\n"
                    "You can close this tab and return to the terminal."
                ),
            )

    @staticmethod
    def _first(values: list[str] | None) -> str | None:
        return values[0] if values else None

    def _send_html(self, status: int, title: str, message: str) -> None:
        self.send_response(status)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        body = (
            f"<!DOCTYPE html><html><head><title>{title}</title></head>"
            f"<body><h2>{title}</h2><p>{message}</p></body></html>"
        )
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format: str, *args) -> None:
        """Suppress default HTTP access logging to avoid leaking state/code."""
        pass


class CallbackServer:
    """Ephemeral HTTP server bound to localhost.

    Accepts exactly one callback request, then shuts down.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0, timeout: int = 120):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.result = CallbackResult()
        self._event = threading.Event()
        self._server: socketserver.TCPServer | None = None
        self._thread: threading.Thread | None = None

    def _create_server(self) -> socketserver.TCPServer:
        """Create and bind the TCPServer, returning the handle."""
        return socketserver.TCPServer((self.host, self.port), CallbackHandler)

    def start(self) -> int:
        """Start the callback server in a background thread.

        Returns the actual port the server bound to.
        """
        CallbackHandler._result = self.result
        CallbackHandler._event = self._event
        self._server = self._create_server()
        actual_port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return actual_port

    def wait(self) -> CallbackResult:
        """Block until callback received or timeout.

        Returns the CallbackResult populated by the handler.
        If no callback arrives in time, error is set to 'timeout'.
        """
        if not self._event.wait(timeout=self.timeout):
            self.result.error = "timeout"
            self.result.error_description = f"No callback received within {self.timeout}s"
        self.shutdown()
        return self.result

    def shutdown(self) -> None:
        """Signal the server to shut down and clean up resources."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None
        CallbackHandler._result = None
        CallbackHandler._event = None
