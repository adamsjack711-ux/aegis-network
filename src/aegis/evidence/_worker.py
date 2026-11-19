"""Fixed, stdlib-only verifier entry point for inert, registered marker fixtures."""

import base64
import json
import resource
import sys

# These literals are the complete input vocabulary. They name simulated states.
FAMILIES = ("feature-gate", "route-toggle", "service-access")
MAX_REQUEST = 2048


def materials(family, marker, observer):
    values = {
        "subject": f"{family}:{marker}",
        "configuration": f"{family}:{observer}",
        "dependencies": f"{family}:no-dependencies-v1",
        "recipe": f"{family}:marker-model-v1",
    }
    return {role: value.encode("ascii") for role, value in values.items()}


def observe(family, subject, config):
    if config == f"{family}:observer-offline".encode("ascii"):
        return None
    return subject == f"{family}:marker-on".encode("ascii")


def registered(family, objects):
    return family in FAMILIES and any(
        objects == materials(family, marker, observer)
        for marker in ("marker-on", "marker-off")
        for observer in ("observer-ready", "observer-offline")
    )


def check(family, objects):
    if not registered(family, objects):
        raise ValueError("fixture is not registered")
    config = objects["configuration"]
    positive = observe(family, materials(family, "marker-on", "observer-ready")["subject"], config)
    negative = observe(family, materials(family, "marker-off", "observer-ready")["subject"], config)
    if positive is not True or negative is not False:
        return {
            "outcome": "inconclusive",
            "reason": "oracle-unavailable" if positive is None or negative is None else "control-failed",
            "positive_control": positive is True,
            "negative_control": negative is False,
        }
    observed = observe(family, objects["subject"], config)
    return {
        "outcome": "reproduced" if observed else "not-reproduced",
        "reason": "marker-observed" if observed else "marker-absent",
        "positive_control": True,
        "negative_control": True,
    }


def restrict(event, args):
    if event in {"open", "exec", "compile"} or event.startswith(
        ("socket.", "subprocess.", "os.", "ctypes.", "import", "mmap.")
    ):
        raise PermissionError("worker operation is unavailable")


def main():
    resource.setrlimit(resource.RLIMIT_CPU, (1, 2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.platform.startswith("linux"):
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    sys.addaudithook(restrict)
    try:
        request = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(request) > MAX_REQUEST:
            return 2
        data = json.loads(request)
        objects = {role: base64.b64decode(value, validate=True) for role, value in data["objects"].items()}
        result = check(data["family"], objects)
    except (ValueError, TypeError, KeyError, AttributeError):
        return 2
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
