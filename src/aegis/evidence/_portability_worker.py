"""Finite marker models for Phase 4B. Only inert fixture inputs are admitted."""

import base64
import json
import resource
import runpy
import sys

FAMILY = "portability-marker"
VERSIONS = (b"v1", b"v2", b"v3")
BUILDS = (b"default", b"alternate")
FEATURES = (b"enabled", b"disabled")
RUNTIMES = (b"runtime-a", b"runtime-b", b"runtime-offline")
POLICIES = (b"policy-v1", b"policy-v2")
DEPENDENCIES = (b"lock-v1", b"lock-v2")
RECIPES = (b"recipe-v1", b"recipe-v2")
HARNESSES = ("harness-v1", "harness-v2", "harness-unavailable")


def registered(objects):
    subject = objects["subject"].split(b":")
    config = objects["configuration"].split(b":")
    return (
        len(config) == 3 and len(subject) in (3, 4)
        and subject[0] in VERSIONS and subject[1] in BUILDS
        and (subject[2:] == [b"original"] or (
            len(subject) == 4 and subject[2] == b"repackaged" and len(subject[3]) == 64
            and all(byte in b"0123456789abcdef" for byte in subject[3])
        ))
        and config[0] in FEATURES and config[1] in RUNTIMES and config[2] in POLICIES
        and objects["dependencies"] in DEPENDENCIES and objects["recipe"] in RECIPES
    )


def marker(subject, config, dependency):
    version, build, *_packaging = subject.split(b":")
    feature, runtime, policy = config.split(b":")
    return (version, build, feature, runtime, policy, dependency) == (
        b"v1", b"default", b"enabled", b"runtime-a", b"policy-v1", b"lock-v1",
    )


def observe(harness, subject, config, dependency):
    if harness == "harness-unavailable" or config.split(b":")[1] == b"runtime-offline":
        return None
    observed = marker(subject, config, dependency)
    if harness == "harness-v2":
        # The second harness reads a typed marker record instead of a boolean.
        return ({"marker": "present" if observed else "absent"}["marker"] == "present")
    return observed


def check(objects, harness):
    if not registered(objects) or harness not in HARNESSES:
        raise ValueError("fixture or harness is not registered")
    runtime = objects["configuration"].split(b":")[1]
    control_config = b"enabled:" + runtime + b":policy-v1"
    # Runtime B has working controls with their pinned reference runtime.
    # The offline target cannot initialize the observation channel.
    if runtime != b"runtime-offline":
        control_config = b"enabled:runtime-a:policy-v1"
    positive = observe(harness, b"v1:default:original", control_config, b"lock-v1")
    negative = observe(harness, b"v2:default:original", control_config, b"lock-v1")
    if positive is not True or negative is not False:
        return {"outcome": "inconclusive", "reason": "oracle-unavailable",
                "positive_control": positive is True, "negative_control": negative is False}
    observed = observe(harness, objects["subject"], objects["configuration"], objects["dependencies"])
    return {"outcome": "reproduced" if observed else "not-reproduced",
            "reason": "marker-observed" if observed else "marker-absent",
            "positive_control": True, "negative_control": True}


def main():
    # The runner stages and verifies both files before they execute.
    resource.setrlimit(resource.RLIMIT_CPU, (1, 2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.platform.startswith("linux"):
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    boundary = runpy.run_path(sys.argv[1])
    max_request = boundary["MAX_REQUEST"]
    sys.addaudithook(boundary["restrict"])
    try:
        request = sys.stdin.buffer.read(max_request + 1)
        if len(request) > max_request:
            return 2
        data = json.loads(request)
        if data["family"] != FAMILY:
            return 2
        objects = {role: base64.b64decode(value, validate=True) for role, value in data["objects"].items()}
        result = check(objects, sys.argv[2])
    except (ValueError, TypeError, KeyError, AttributeError):
        return 2
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
