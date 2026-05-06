"""Ephemeral OAuth callback server.

Handles exactly one GET request on /callback, extracts query parameters, then
signals the main thread and shuts down.

"""
from http.server import BaseHTTPRequestHandler, HTTPServer
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


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for the OAuth callback route."""
    result: CallbackResult | None = None
    event: threading.Event | None = None

    @staticmethod
    def _first(seq):
        """Return the first element of a list or None."""
        if seq and len(seq) > 0:
            return seq[0]
        return None

    def _send_html(self, status_code: int, message: str) -> None:
        """Send an HTML response with the given status code."""
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(f"<html><body><h1>{status_code}</h1><p>{message}</p></body></html>".encode("utf-8"))

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        if parsed.path != "/callback":
            self._send_html(404, "Not found")
            return

        qs = parse_qs(parsed.query)
        CallbackHandler.result = CallbackResult(
            code=self._first(qs.get("code")),
            state=self._first(qs.get("state")),
            error=self._first(qs.get("error")),
            error_description=self._first(qs.get("error_description")),
        )
        self._send_html(200, "Authorization received. You may close this window.")
        if CallbackHandler.event is not None:
            CallbackHandler.event.set()

    def log_message(self, format, *args):
        """Suppress default HTTP access logging to avoid leaking state/code."""


class CallbackServer:
    """Ephemeral TCPServer bound to 127.0.0.1, port 0 auto-assigned."""
    result: CallbackResult | None = None

    def __init__(self, host: str = "127.0.0.1", port: int = 0, timeout: int = 120):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._server: socketserver.TCPServer | None = None
        self._result: CallbackResult | None = None
        self._event: threading.Event | None = None

    def start(self) -> int:
        """Start the server in a background thread. Returns the actual port."""
        self._event = threading.Event()
        self._result = CallbackResult()
        CallbackHandler.event = self._event
        CallbackHandler.result = None
        self._server = socketserver.TCPServer((self.host, self.port), CallbackHandler)
        actual_port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return actual_port

    def wait(self) -> CallbackResult:
        """Block until callback result or timeout."""
        if not self._event.wait(timeout=self.timeout):
            self._result.error = "timeout"
            self._result.error_description = f"Timed out after {self.timeout}s. No callback received."
            self.shutdown()
            return self._result
        self.shutdown()
        if CallbackHandler.result is not None:
            return CallbackHandler.result
        return self._result

    def shutdown(self) -> None:
        """Signal the server to shut down and clean up resources."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
