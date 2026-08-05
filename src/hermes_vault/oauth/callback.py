"""Ephemeral OAuth callback server.

Handles exactly one GET request on /callback, extracts query parameters, then
signals the main thread and shuts down. Each callback server instance owns its
result and event state, so concurrent login flows stay isolated. The first
accepted callback is immutable: later callbacks cannot overwrite it and receive
a non-success response.

"""
from http.server import BaseHTTPRequestHandler
import socketserver
import threading
from dataclasses import dataclass
from typing import cast
from urllib.parse import parse_qs, urlparse


@dataclass
class CallbackResult:
    """Result from the OAuth provider callback."""
    code: str | None = None
    state: str | None = None
    error: str | None = None
    error_description: str | None = None


class CallbackHTTPServer(socketserver.TCPServer):
    """TCPServer carrying per-login callback result and event state.

    ``result`` and ``event`` live on the server instance (not on the handler
    class) so two simultaneous login flows cannot observe or consume each
    other's callback state.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.result: CallbackResult | None = None
        self.event: threading.Event | None = None
        self._accept_lock = threading.Lock()


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for the OAuth callback route."""

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

    @property
    def callback_server(self) -> CallbackHTTPServer:
        """The CallbackHTTPServer instance that spawned this handler."""
        return cast(CallbackHTTPServer, self.server)

    def do_GET(self):
        """Handle GET requests.

        Only the first accepted /callback request may populate the result.
        Later callbacks to the same server receive a non-success response and
        cannot overwrite the accepted code, state, or error.
        """
        parsed = urlparse(self.path)
        if parsed.path != "/callback":
            self._send_html(404, "Not found")
            return

        server = self.callback_server
        qs = parse_qs(parsed.query)

        # Serialize acceptance; the first callback wins atomically.
        with server._accept_lock:
            if server.result is not None:
                # A result is already accepted — never replace it.
                self._send_html(409, "Callback already received. Close this window.")
                return
            server.result = CallbackResult(
                code=self._first(qs.get("code")),
                state=self._first(qs.get("state")),
                error=self._first(qs.get("error")),
                error_description=self._first(qs.get("error_description")),
            )
            event = server.event

        self._send_html(200, "Authorization received. You may close this window.")
        if event is not None:
            event.set()

    def log_message(self, format, *args):
        """Suppress default HTTP access logging to avoid leaking state/code."""


class CallbackServer:
    """Ephemeral TCPServer bound to 127.0.0.1, port 0 auto-assigned."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, timeout: int = 120):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._server: CallbackHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        """Start the server in a background thread. Returns the actual port."""
        server = CallbackHTTPServer((self.host, self.port), CallbackHandler)
        server.event = threading.Event()
        server.result = None
        self._server = server
        actual_port = server.server_address[1]
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        return actual_port

    def wait(self) -> CallbackResult:
        """Block until callback result or timeout."""
        server = self._server
        if server is None or server.event is None:
            raise RuntimeError("Callback server must be started before wait().")
        if not server.event.wait(timeout=self.timeout):
            result = CallbackResult(
                error="timeout",
                error_description=f"Timed out after {self.timeout}s. No callback received.",
            )
            self.shutdown()
            return result
        accepted = server.result
        self.shutdown()
        if accepted is not None:
            return accepted
        return CallbackResult(error="timeout", error_description="No callback received.")

    def shutdown(self) -> None:
        """Signal the server to shut down, join its thread, and clear state.

        Safe to call repeatedly.
        """
        server = self._server
        if server is not None:
            server.shutdown()
            server.server_close()
            server.result = None
            server.event = None
            self._server = None
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5)
            self._thread = None
