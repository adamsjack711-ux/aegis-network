"""Run an explicitly provisioned role on a private laboratory address."""

import argparse
import json
from pathlib import Path

from .protocol import Enrollment
from .services import Anchor, Broker, Home, Target, initialize
from .transport import Client, Credentials, Endpoint, Server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("init", "serve"))
    parser.add_argument("name")
    parser.add_argument("config", type=Path)
    parser.add_argument("data", type=Path)
    parser.add_argument("--bind", default="127.0.0.1")
    args = parser.parse_args()
    policy = Enrollment.model_validate_json((args.config / "enrollment.json").read_bytes())
    endpoints = {name: Endpoint(name=name, **address) for name, address in
                 json.loads((args.config / "endpoints.json").read_bytes()).items()}
    path = args.data / "state.sqlite"
    if args.operation == "init":
        if args.name not in {"anchor", "home", *policy.targets}:
            parser.error("only the anchor, home and targets have a durable store")
        initialize(path, args.name, policy)
        return
    credentials = Credentials(args.config)
    if args.name == "anchor":
        service = Anchor(path)
    elif args.name == "home":
        service = Home(path, policy, Client(credentials), endpoints)
    elif args.name in policy.targets:
        service = Target(args.name, path, policy, Client(credentials), endpoints)
    elif args.name in policy.brokers:
        service = Broker(args.name, policy, Client(credentials), endpoints)
    else:
        parser.error("unenrolled role")
    address = (args.bind, endpoints[args.name].port)
    with Server(address, credentials, service.dispatch) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
