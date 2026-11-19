"""Loopback proxy and private HTTP fixture with inert marker content."""

from functools import partial
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
from socketserver import UnixStreamServer
import sqlite3
from threading import Thread

from .policy import Denied, MARKER_PATH, PATHS
from .store import TargetStore


class _Handler(BaseHTTPRequestHandler):
    def setup(self) -> None:
        self.request.settimeout(0.25)
        super().setup()

    def log_message(self, *args) -> None:
        pass

    def reply(self, status: int, body: bytes, **headers: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _get_path(self) -> str:
        # Use the original target because the HTTP parser can normalize a leading //.
        return self.requestline.split()[1]


class _FixtureHandler(_Handler):
    def __init__(self, *args, target: str):
        self.target = target
        super().__init__(*args)

    def address_string(self) -> str:
        return "local"

    def do_GET(self) -> None:
        path = self._get_path()
        if path in PATHS:
            self.reply(200, f"{self.target}:{path}".encode())
        else:
            self.reply(404, b"unknown fixture route")


class _UnixHTTPConnection(HTTPConnection):
    def __init__(self, path: Path) -> None:
        super().__init__("fixture.internal", timeout=0.25)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


class _ProxyHandler(_Handler):
    def __init__(self, *args, lab_id: str, target: str, upstream: Path, store: TargetStore):
        self.lab_id = lab_id
        self.target = target
        self.upstream = upstream
        self.store = store
        super().__init__(*args)

    def _forward(self, path: str) -> tuple[int, bytes]:
        conn = _UnixHTTPConnection(self.upstream)
        try:
            conn.request("GET", path)
            response = conn.getresponse()
            return response.status, response.read(256)
        except (OSError, HTTPException):
            return 503, b"fixture upstream unavailable"
        finally:
            conn.close()

    def do_GET(self) -> None:
        path = self._get_path()
        if path not in PATHS:
            self.reply(404, b"unknown fixture route")
            return
        marker = path == MARKER_PATH
        replied = False
        try:
            with self.store.route(self.target, marker=marker) as state:
                headers = {
                    "X-Lab-Id": self.lab_id,
                    "X-Lab-Target": self.target,
                    "X-Lab-Fence": str(state.fence),
                }
                if state.mode == "restricted" and marker:
                    status, body = 403, b"fixture route restricted"
                elif state.mode not in {"open", "restricted"}:
                    status, body = 503, b"fixture quarantined"
                else:
                    status, body = self._forward(path)
                    if not self.store.response_permitted(state):
                        status, body = 503, b"fixture quarantined"
                replied = True
                self.reply(status, body, **headers)
        except (Denied, sqlite3.Error):
            if not replied:
                self.reply(503, b"fixture state unavailable")
        except OSError:
            self.close_connection = True


class RunningServer:
    def __init__(self, server: UnixStreamServer | ThreadingHTTPServer) -> None:
        self.server = server
        self._worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self._worker.start()

    def close(self) -> None:
        if self._worker.is_alive():
            self.server.shutdown()
            self._worker.join()
            self.server.server_close()


def start_fixture(target: str, path: Path) -> RunningServer:
    return RunningServer(UnixStreamServer(str(path), partial(_FixtureHandler, target=target)))


def start_proxy(lab_id: str, target: str, path: Path, store: TargetStore) -> RunningServer:
    handler = partial(_ProxyHandler, lab_id=lab_id, target=target, upstream=path, store=store)
    return RunningServer(ThreadingHTTPServer(("127.0.0.1", 0), handler))
