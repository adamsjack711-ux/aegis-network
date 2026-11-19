"""One bounded HTTPS request per TLS 1.3 mutual-authentication handshake."""

from dataclasses import dataclass
from http.client import HTTPException, HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
from pathlib import Path
import ssl
from threading import BoundedSemaphore
from time import time_ns
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import ValidationError

from ..evidence.records import Record, canonical, digest
from .protocol import DOMAIN, Denied, Unavailable, principal

MAX_BODY = 16_384
IO_TIMEOUT = 5


class AuthenticationFailed(Exception):
    """TLS peer authentication failed."""


@dataclass(frozen=True)
class Peer:
    uri: str
    key: str
    expires_ns: int

    def require(self, *names: str) -> None:
        if self.uri not in {principal(name) for name in names} or self.expires_ns <= time_ns():
            raise Denied("TLS identity or expiry is outside the operation's scope")


def spki(key) -> str:
    return digest(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))


def authenticated_peer(sock: ssl.SSLSocket) -> Peer:
    try:
        cert = x509.load_der_x509_certificate(sock.getpeercert(binary_form=True))
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        if len(uris) != 1 or not uris[0].startswith(DOMAIN):
            raise AuthenticationFailed("expected one lab SPIFFE URI")
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise AuthenticationFailed("peer certificate must be a leaf")
        expires = int(cert.not_valid_after_utc.timestamp()) * 1_000_000_000
        if expires <= time_ns():
            raise AuthenticationFailed("peer certificate expired")
        return Peer(uris[0], spki(cert.public_key()), expires)
    except (ValueError, x509.ExtensionNotFound) as exc:
        raise AuthenticationFailed("invalid lab peer certificate") from exc


@dataclass(frozen=True)
class Credentials:
    directory: Path

    def context(self, *, server: bool) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
        # The client verifies the exact URI after OpenSSL verifies the chain.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.options |= ssl.OP_NO_TICKET
        if server:
            ctx.num_tickets = 0
        ctx.load_verify_locations(cafile=str(self.directory / "ca.pem"))
        ctx.load_cert_chain(str(self.directory / "cert.pem"), str(self.directory / "key.pem"))
        return ctx


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    name: str


class _Connection(HTTPSConnection):
    def __init__(self, endpoint: Endpoint, context: ssl.SSLContext, timeout: float):
        super().__init__(endpoint.host, endpoint.port, context=context, timeout=timeout)
        self.endpoint = endpoint

    def connect(self) -> None:
        super().connect()
        if authenticated_peer(self.sock).uri != principal(self.endpoint.name):
            self.close()
            raise AuthenticationFailed("server URI differs from its configured role")


class Client:
    def __init__(self, credentials: Credentials, timeout: float = IO_TIMEOUT):
        self.context = credentials.context(server=False)
        leaf = x509.load_pem_x509_certificate((credentials.directory / "cert.pem").read_bytes())
        self.valid_from_ns = int(leaf.not_valid_before_utc.timestamp()) * 1_000_000_000
        self.valid_until_ns = int(leaf.not_valid_after_utc.timestamp()) * 1_000_000_000
        self.timeout = timeout

    def call(self, endpoint: Endpoint, route: str, body: Record | bytes | None = None) -> dict:
        if not self.valid_from_ns <= time_ns() < self.valid_until_ns:
            raise AuthenticationFailed("local TLS credential is outside its validity period")
        connection = _Connection(endpoint, self.context, self.timeout)
        try:
            payload = canonical(body) if isinstance(body, Record) else body or b"{}"
            connection.request("POST", route, payload,
                               {"Content-Type": "application/json", "Connection": "close"})
            with connection.getresponse() as response:
                raw = response.read(MAX_BODY + 1)
                if len(raw) > MAX_BODY:
                    raise Unavailable("oversized RPC response")
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise Unavailable("invalid RPC response")
                if response.status == 403:
                    raise Denied(result["error"])
                if response.status != 200:
                    raise Unavailable(result.get("error", "RPC unavailable"))
                return result
        except ssl.SSLError as exc:
            raise AuthenticationFailed("TLS handshake or peer validation failed") from exc
        except (OSError, HTTPException, ValueError) as exc:
            raise Unavailable("RPC endpoint unavailable") from exc
        finally:
            connection.close()


Dispatch = Callable[[Peer, str, bytes], Record | dict]


class Server(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], credentials: Credentials, dispatch: Dispatch):
        self.context = credentials.context(server=True)
        self.dispatch = dispatch
        self.slots = BoundedSemaphore(32)
        super().__init__(address, _Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(IO_TIMEOUT)
            with self.context.wrap_socket(request, server_side=True) as secured:
                super().process_request_thread(secured, client_address)
        except OSError:
            self.shutdown_request(request)
        finally:
            self.slots.release()


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        try:
            peer = authenticated_peer(self.connection)
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= MAX_BODY or self.headers.get("Transfer-Encoding"):
                raise Denied("invalid request framing")
            body = self.rfile.read(size)
            if len(body) != size:
                raise Denied("incomplete request body")
            result = self.server.dispatch(peer, self.path, body)
            status = 200
        except (AuthenticationFailed, Denied, ValidationError, ValueError) as exc:
            detail = str(exc) if isinstance(exc, Denied) else "invalid identity or request"
            status, result = 403, {"error": detail}
        except Unavailable as exc:
            status, result = 503, {"error": str(exc)}
        except Exception:
            logging.exception("identity lab RPC failed")
            status, result = 503, {"error": "local RPC service failed"}
        payload = canonical(result) if isinstance(result, Record) else json.dumps(result).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
        except OSError:
            pass

    def log_message(self, format, *args):
        pass
