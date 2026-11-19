"""Black-box HTTP oracle. Receives endpoint addresses and expected IDs only."""

from dataclasses import dataclass
from http.client import HTTPConnection, HTTPException
import time

from .policy import BENIGN_PATHS, MARKER_PATH, OBSERVATION_WINDOW_NS


class ObservationError(RuntimeError):
    """The expected HTTP behavior could not be established."""


@dataclass(frozen=True)
class Observation:
    lab_id: str
    mode: str
    fences: tuple[tuple[str, int], ...]
    started_ns: int
    finished_ns: int
    requests: int


class HttpObserver:
    def __init__(self, lab_id: str, endpoints: dict[str, tuple[str, int]]) -> None:
        self.lab_id = lab_id
        self._endpoints = dict(endpoints)

    def _probe(self, target: str, fence: int, path: str, status: int, body: bytes) -> None:
        host, port = self._endpoints[target]
        client = HTTPConnection(host, port, timeout=0.25)
        try:
            client.request("GET", path)
            response = client.getresponse()
            actual = (
                response.status,
                response.read(256),
                response.getheader("X-Lab-Id"),
                response.getheader("X-Lab-Target"),
                response.getheader("X-Lab-Fence"),
            )
        except (OSError, HTTPException) as exc:
            raise ObservationError(f"{target} {path}: observer could not reach proxy") from exc
        finally:
            client.close()
        if actual != (status, body, self.lab_id, target, str(fence)):
            raise ObservationError(f"{target} {path}: expected HTTP {status} at fence {fence}, got {actual!r}")

    def observe(self, mode: str, fences: tuple[tuple[str, int], ...]) -> Observation:
        if mode not in {"open", "restricted", "quarantined"} or not fences:
            raise ObservationError("invalid observation scope")
        started = time.monotonic_ns()
        for round_index in range(2):
            for target, fence in fences:
                for path in (MARKER_PATH, *BENIGN_PATHS):
                    if mode == "quarantined":
                        status, body = 503, b"fixture quarantined"
                    elif mode == "restricted" and path == MARKER_PATH:
                        status, body = 403, b"fixture route restricted"
                    else:
                        status, body = 200, f"{target}:{path}".encode()
                    self._probe(target, fence, path, status, body)
            if round_index == 0:
                time.sleep(OBSERVATION_WINDOW_NS / 1_000_000_000)
        return Observation(self.lab_id, mode, fences, started, time.monotonic_ns(), 6 * len(fences))
