"""Compare toy fixture observations with frozen Phase 3D expectations."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


FIXTURES = Path(__file__).with_name("fixtures")
WORLD = json.loads((FIXTURES / "world.json").read_text())
CASES = json.loads((FIXTURES / "scenarios.json").read_text())
TOPOLOGY = frozenset(
    (replica, route)
    for replica, routes in WORLD["inventory"]["routes"].items()
    for route in routes
)
DEFAULT_STEPS = [
    ["apply", 91, "cap-canary", "agent-a", "canary"],
    ["canary-probe", 92],
    ["apply", 93, "cap-peer", "agent-b", "peer"],
]


def encoded(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()


def fixture_key(verifier):
    # Public, deterministic test material.
    return Ed25519PrivateKey.from_private_bytes(bytes([verifier["seed"]]) * 32)


def sample_attestations(specifications):
    for signer, outcome, *variants in specifications:
        variant = variants[0] if variants else None
        body = {
            "signer": signer,
            "scope": "other-toy" if variant == "other-scope" else WORLD["scope"],
            "evidence": WORLD["evidence_sha256"],
            "controls_passed": variant != "failed-control",
            "outcome": "inconclusive" if variant == "tamper" else outcome,
        }
        signing_key = fixture_key(WORLD["verifiers"].get(signer, {"seed": 6}))
        signature = signing_key.sign(encoded(body))
        yield body | {"outcome": outcome}, signature


def check_evidence(evidence, attestations):
    digest = hashlib.sha256(evidence.encode()).hexdigest()
    if digest != WORLD["evidence_sha256"]:
        return "evidence-digest"

    positive_orgs = set()
    for body, signature in attestations:
        enrollment = WORLD["verifiers"].get(body["signer"])
        if enrollment is None:
            continue
        try:
            fixture_key(enrollment).public_key().verify(signature, encoded(body))
        except InvalidSignature:
            continue
        if (enrollment["org"] == WORLD["submitter"] or body["scope"] != WORLD["scope"]
                or body["evidence"] != digest or not body["controls_passed"]):
            continue
        if body["outcome"] == "not-reproduced":
            return "contested"
        if body["outcome"] == "reproduced":
            positive_orgs.add(enrollment["org"])
    return "eligible" if len(positive_orgs) >= 2 else "quorum"


@dataclass(frozen=True)
class Reading:
    fence: int
    marker_count: int
    benign_successes: int


@dataclass(frozen=True)
class Write:
    at: int
    replica: str
    state: str
    capability: str | None = None
    agent: str | None = None


@dataclass(frozen=True)
class Probe:
    at: int
    readings: dict[tuple[str, str], Reading]


class ToyFixture:
    """A recorder that permits scripted bad writes for the negative controls."""

    def __init__(self, faults):
        self.states = {replica: "open" for replica, _ in TOPOLOGY}
        self.faults = faults
        assert set(faults) <= {f"{replica}/{route}" for replica, route in TOPOLOGY}

    def write(self, write):
        self.states[write.replica] = write.state

    def probe(self, at, only_replica=None):
        readings = {}
        for replica, route in sorted(TOPOLOGY):
            if only_replica is not None and replica != only_replica:
                continue
            fault = self.faults.get(f"{replica}/{route}")
            if fault == "unobserved":
                continue
            state = self.states[replica]
            readings[replica, route] = Reading(
                fence=WORLD["fence"] - (fault == "old-fence"),
                marker_count=int(state == "open" or (state == "restricted" and fault == "bypass")),
                benign_successes=0 if state == "quarantined" or fault == "service-down" else 3,
            )
        return Probe(at, readings)


def observe(probe, expected_routes, *, require_benign):
    if any(reading.marker_count > 0 or (require_benign and reading.benign_successes < 3)
           for reading in probe.readings.values() if reading.fence == WORLD["fence"]):
        return "failed"
    if (probe.readings.keys() != expected_routes
            or any(reading.fence != WORLD["fence"] for reading in probe.readings.values())):
        return "inconclusive"
    return "confirmed"


def eligible_at(at, status, inventory, evidence_result):
    if status["withdrawn"]:
        return "withdrawn"
    if (not status["complete"] or at >= status["valid_until"]
            or status["trust_generation"] != WORLD["status"]["trust_generation"]
            or status["withdrawal_generation"] != WORLD["status"]["withdrawal_generation"]):
        return "stale-status"
    if inventory != WORLD["inventory"]:
        return "inventory-mismatch"
    return evidence_result


def check_writes(journal, eligibility, live_inventory_generation):
    failures = []
    consumed = set()
    canary_routes = {pair for pair in TOPOLOGY if pair[0] == "canary"}
    canary_write_at = None
    canary_verified = False
    lease_start, lease_end = WORLD["lease"]
    for entry in journal:
        if isinstance(entry, Probe):
            canary_verified = (
                canary_write_at is not None and canary_write_at < entry.at
                and observe(entry, canary_routes, require_benign=True) == "confirmed"
            )
            continue
        if entry.capability is None:
            if entry.state != "quarantined":
                failures.append("unsafe-rollback")
            canary_verified = False
            continue

        grant = WORLD["capabilities"].get(entry.capability, {})
        if (entry.agent, entry.replica) != (grant.get("agent"), grant.get("replica")):
            failures.append("capability-binding")
        elif grant["fence"] != WORLD["fence"]:
            failures.append("stale-fence")
        if entry.capability in consumed:
            failures.append("capability-replay")
        if entry.replica == "peer" and not canary_verified:
            failures.append("advance-without-canary")
        if not lease_start <= entry.at < lease_end:
            failures.append("inactive-lease")
        if live_inventory_generation != WORLD["inventory"]["generation"]:
            failures.append("inventory-drift")
        if eligibility(entry.at) != "eligible":
            failures.append("ineligible-at-write")
        consumed.add(entry.capability)
        if entry.replica == "canary":
            canary_write_at = entry.at
            canary_verified = False
    return failures


def run_fixture(case):
    fixture = ToyFixture(case.get("route_faults", {}))
    journal = []
    steps = case.get("steps", DEFAULT_STEPS) + case.get("extra_steps", [])
    now = case.get("now", 95)
    times = [step[1] for step in steps]
    assert times == sorted(set(times)) and all(at <= now for at in times)
    for operation, at, *args in steps:
        if operation == "canary-probe":
            journal.append(fixture.probe(at, only_replica="canary"))
            continue
        if operation == "apply":
            capability, agent, replica = args
            write = Write(at, replica, "restricted", capability, agent)
        else:
            assert operation == "recover"
            replica, state = args
            write = Write(at, replica, state)
        fixture.write(write)
        journal.append(write)
    return journal, fixture.probe(now)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_validation_scenario(case):
    status = WORLD["status"] | case.get("status", {})
    inventory = WORLD["inventory"] | case.get("inventory", {})
    evidence_result = check_evidence(
        case.get("evidence", WORLD["evidence"]),
        sample_attestations(case.get("attestations", [["v1", "reproduced"], ["v2", "reproduced"]])),
    )

    def eligibility(at):
        if at >= case.get("withdrawn_at", float("inf")):
            return "withdrawn"
        return eligible_at(at, status, inventory, evidence_result)

    journal, current = run_fixture(case)
    write_failures = check_writes(
        journal, eligibility, case.get("live_inventory_generation", inventory["generation"]),
    )
    recovering = case.get("recovering", False)
    active_lease = WORLD["lease"][0] <= current.at < WORLD["lease"][1]
    protection = "unconfirmed"
    if not recovering and active_lease and not write_failures and eligibility(current.at) == "eligible":
        protection = observe(current, TOPOLOGY, require_benign=True)
    recovery = "none"
    if recovering:
        safety = observe(current, TOPOLOGY, require_benign=False)
        recovery = "safe-hold" if safety == "confirmed" else "recovery-required"

    expected = {
        "eligibility": "eligible", "write_failures": [], "protection": "confirmed", "recovery": "none",
    } | case.get("expect", {})
    assert {
        "eligibility": eligibility(90),
        "write_failures": write_failures,
        "protection": protection,
        "recovery": recovery,
    } == expected


@pytest.mark.parametrize(
    ("state", "fault", "marker", "benign", "verdict"),
    [
        ("open", None, 1, 3, "failed"),
        ("restricted", None, 0, 3, "confirmed"),
        ("restricted", "service-down", 0, 0, "failed"),
        ("restricted", "unobserved", None, None, "inconclusive"),
    ],
    ids=["affected", "restricted", "benign-regression", "observer-loss"],
)
def test_probe_controls(state, fault, marker, benign, verdict):
    faults = {"canary/alternate": fault} if fault else {}
    fixture = ToyFixture(faults)
    for replica in fixture.states:
        fixture.write(Write(91, replica, state))
    observed = fixture.probe(92)
    expected = None if marker is None else Reading(WORLD["fence"], marker, benign)
    assert observed.readings.get(("canary", "alternate")) == expected
    assert observe(observed, TOPOLOGY, require_benign=True) == verdict
