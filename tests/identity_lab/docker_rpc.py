"""Issue bounded RPC calls inside a disposable actor's network namespace."""

from http.client import HTTPException, HTTPSConnection
import json
from pathlib import Path
import sys
from time import monotonic_ns

from aegis.identity_lab.protocol import Denied, Unavailable
from aegis.identity_lab.transport import AuthenticationFailed, Client, Credentials, Endpoint


def accepts_expired_peer(credential_dir, endpoint, payload):
    context = Credentials(credential_dir).context(server=False)
    connection = HTTPSConnection(endpoint.host, endpoint.port, timeout=2, context=context)
    try:
        connection.request("POST", "/claim", payload)
        return connection.getresponse().status == 200
    except (OSError, HTTPException):
        return False
    finally:
        connection.close()


def main():
    request = json.load(sys.stdin)
    endpoint = Endpoint(**request["endpoint"])
    body = request["body"].encode("ascii") if request["body"] is not None else None
    if request.get("expired_peer_probe"):
        print(json.dumps({"accepted": accepts_expired_peer(Path("/creds"), endpoint, body)}))
        return
    client = Client(Credentials(Path("/creds")), timeout=2)
    samples = []
    outcomes = []
    for _ in range(request["count"]):
        start = monotonic_ns()
        try:
            result = {"outcome": "ok", "result": client.call(endpoint, request["route"], body)}
        except (AuthenticationFailed, Denied, Unavailable) as exc:
            result = {"outcome": type(exc).__name__, "error": str(exc)}
        samples.append(monotonic_ns() - start)
        outcomes.append(result["outcome"])
    print(json.dumps(result | {"samples_ns": samples, "outcomes": outcomes}))


if __name__ == "__main__":
    main()
