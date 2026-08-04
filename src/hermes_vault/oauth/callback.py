"""Ephemeral OAuth callback server.

Handles exactly one GET request on /callback, extracts query parameters, then
signals the main thread and shuts down.

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

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        if parsed.path != "/callback":
            self._send_html(404, "Not found")
            return

        qs = parse_qs(parsed.query)
        server = cast("CallbackHTTPServer", self.server)
        server.result = CallbackResult(
            code=self._first(qs.get("code")),
            state=self._first(qs.get("state")),
            error=self._first(qs.get("error")),
            error_description=self._first(qs.get("error_description")),
        )
        self._send_html(200, "Authorization received. You may close this window.")
        server.event.set()

    def log_message(self, format, *args):
        """Suppress default HTTP access logging to avoid leaking state/code."""


class CallbackHTTPServer(socketserver.TCPServer):
    """Loopback callback server with state isolated to this instance."""

    def __init__(self, server_address: tuple[str, int], event: threading.Event):
        self.event = event
        self.result: CallbackResult | None = None
        super().__init__(server_address, CallbackHandler)


class CallbackServer:
    """Ephemeral TCPServer bound to 127.0.0.1, port 0 auto-assigned."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, timeout: int = 120):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._server: CallbackHTTPServer | None = None
        self._result: CallbackResult | None = None
        self._thread: threading.Thread | None = None
        self._shutdown_lock = threading.Lock()

    def start(self) -> int:
        """Start the server in a background thread. Returns the actual port."""
        with self._shutdown_lock:
            self._result = CallbackResult()
            server = CallbackHTTPServer((self.host, self.port), threading.Event())
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            self._server = server
            self._thread = thread
            actual_port = server.server_address[1]
            thread.start()
        return actual_port

    def wait(self) -> CallbackResult:
        """Block until callback result or timeout."""
        result = self._result
        server = self._server
        if result is None or server is None:
            raise RuntimeError("Callback server must be started before wait().")
        if not server.event.wait(timeout=self.timeout):
            result.error = "timeout"
            result.error_description = f"Timed out after {self.timeout}s. No callback received."
            self.shutdown()
            return result
        self.shutdown()
        if server.result is not None:
            return server.result
        return result

    def shutdown(self) -> None:
        """Signal the server to shut down and clean up resources."""
        with self._shutdown_lock:
            server = self._server
            thread = self._thread
            if server is None and thread is None:
                return

            if server is not None:
                server.shutdown()
                server.server_close()
            if thread is not None and thread is not threading.current_thread():
                thread.join()

            self._server = None
            self._thread = None
