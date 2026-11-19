"""Phase 4E acceptance observations over disposable Aegis fixtures."""

import asyncio
from contextlib import ExitStack, closing, contextmanager
from dataclasses import replace
from hashlib import sha256
from http.client import HTTPConnection
import json
import sqlite3
import time
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis import ownership
from aegis.artifact import sign
from aegis.core import InventoryItem, LocalAgent, LocalPolicy
from aegis.evidence import Evidence
from aegis.evidence.records import Trust, Withdrawal, sign_record
from aegis.evidence.service import Verifier
from aegis.evidence.status import RelyingStatus, StatusProof, StatusWitness
from aegis.evidence.status_protocol import StatusPolicy, WitnessGrant, observe
from aegis.evidence.synthetic import create_lab
from aegis.journal.protocol import JournalBlocked
from aegis.mitigation.lab import Lab
from aegis.mitigation.policy import Denied, LocalOperator
from aegis.mitigation.store import TargetStore
from aegis.ownership import IdentitySession, lease_proof
from aegis.phase3c import (
    COHORT, EvidenceGate, MESH_TEMPLATE, MeshIntake, PACKAGE, VERSION, VerifiedLab, publishable_finding,
)
from aegis.storage import SqliteAudit
from aegis.trust_lab.native_evidence import NativeEvidenceStatus
from test_journal import Network


TARGETS = ("canary", "replica-a", "replica-b")
ROUTES = ("/fixture-marker", "/health", "/ok")
PRINCIPAL = "spiffe://aegis.lab/validation/holder"
STATUS_DOMAIN = b"AEGIS-EVIDENCE-STATUS/v1\0"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def retain(record_property, stage, observation):
    record_property(stage, canonical(observation).decode())


@contextmanager
def readonly(path):
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as db:
        db.execute("BEGIN")
        yield db


def snapshot(path):
    with readonly(path) as db:
        lab_id, = db.execute("SELECT id FROM lab").fetchone()
        targets = db.execute("SELECT id, fence, mode FROM target ORDER BY id").fetchall()
        audit = [(seq, event, plan, json.loads(detail)) for seq, event, plan, detail in
                 db.execute("SELECT seq, event, plan, detail FROM audit ORDER BY seq")]
        phase = db.execute("SELECT phase FROM rollout").fetchone()
    return {"lab": lab_id, "targets": targets, "audit": audit, "phase": phase[0] if phase else None}


def probe(endpoints, missing=()):
    observed = {}
    assert set(endpoints) == set(TARGETS)
    for target in TARGETS:
        if target in missing:
            continue
        host, port = endpoints[target]
        assert host == "127.0.0.1"
        for route in ROUTES:
            with closing(HTTPConnection(host, port, timeout=0.5)) as connection:
                connection.request("GET", route)
                response = connection.getresponse()
                observed[f"{target}{route}"] = {
                    "status": response.status,
                    "body": response.read(512).decode("ascii"),
                    "lab": response.getheader("X-Lab-Id"),
                    "target": response.getheader("X-Lab-Target"),
                    "fence": response.getheader("X-Lab-Fence"),
                }
    return observed


def assert_routes(observed, lab_id, modes):
    assert set(observed) == {f"{target}{route}" for target in modes for route in ROUTES}
    for target, (mode, fence) in modes.items():
        for route in ROUTES:
            got = observed[f"{target}{route}"]
            if mode == "quarantined":
                expected = 503, "fixture quarantined"
            elif mode == "restricted" and route == ROUTES[0]:
                expected = 403, "fixture route restricted"
            else:
                expected = 200, f"{target}:{route}"
            assert (got["status"], got["body"]) == expected
            assert (got["lab"], got["target"], got["fence"]) == (lab_id, target, str(fence))


class StatusFixture:
    def __init__(self, path, researcher, bundle, audience):
        self.path, self.researcher, self.bundle, self.audience = path, researcher, bundle, audience
        self.reader_path = path / "evidence-status.sqlite"
        keys = [Ed25519PrivateKey.generate() for _ in range(2)]
        grants = tuple(WitnessGrant(f"witness-{i}", f"status-org-{i}", key.public_key())
                       for i, key in enumerate(keys))
        self.policy = StatusPolicy("phase4e-validation", COHORT, "research-org", "local-operator",
                                   researcher.trust, grants)
        self.witnesses = tuple(StatusWitness(path / f"{grant.witness_id}.sqlite", self.policy,
                                             grant.witness_id, key, provision=True)
                               for grant, key in zip(grants, keys, strict=True))
        wires = (bundle.manifest, *(observe(self.policy, verifier, bundle, clock=time.time)
                                    for verifier in researcher.verifiers))
        self.admit(*wires)
        self.reader = self.open_reader(provision=True)
        self.last = None
        self.unavailable = False

    def open_reader(self, *, provision=False):
        return RelyingStatus(self.reader_path, self.policy, self.audience, provision=provision)

    def admit(self, *wires):
        for i, witness in enumerate(self.witnesses):
            for wire in wires:
                witness.admit(wire)
                pin = sha256(wire).hexdigest()
                with readonly(self.path / f"witness-{i}.sqlite") as db:
                    assert db.execute("SELECT wire FROM status_records WHERE digest = ?", (pin,)).fetchone() == (wire,)

    def fetch(self, challenge_wire):
        if self.unavailable:
            return StatusProof((), ())
        left, right = (witness.endorse(challenge_wire) for witness in self.witnesses)
        assert left.records == right.records
        endorsements = left.endorsements + right.endorsements
        challenge = json.loads(challenge_wire)
        assert challenge["audience"] == self.audience
        assert challenge["scope"]["bundle_sha256"] == self.bundle.sha256
        pins = sorted(sha256(wire).hexdigest() for wire in left.records)
        root = sha256(STATUS_DOMAIN + b"archive\0" + b"".join(bytes.fromhex(pin) for pin in pins)).hexdigest()
        verified = []
        for grant, wire in zip(self.policy.witnesses, endorsements, strict=True):
            envelope = json.loads(wire)
            body = envelope["body"]
            grant.public_key.verify(bytes.fromhex(envelope["signature"]),
                                    STATUS_DOMAIN + b"endorsement\0" + canonical(body))
            assert body["witness_id"] == grant.witness_id
            assert body["challenge_sha256"] == sha256(challenge_wire).hexdigest()
            assert body["head"] == {"revision": len(pins), "root_sha256": root}
            assert body["issued_at"] <= int(time.time()) < body["expires_at"]
            verified.append({"public_key": grant.public_key.public_bytes_raw().hex(), "wire": envelope})
        self.last = {"challenge": challenge, "endorsements": verified, "record_digests": pins}
        return StatusProof(endorsements, left.records)

    def appraise(self, *, reader=None):
        manifest = json.loads(self.bundle.manifest)["body"]
        return (reader or self.reader).evaluate(
            self.bundle, expected_bundle_sha256=self.bundle.sha256,
            expected_claim_sha256=manifest["claim_sha256"],
            expected_environment_sha256=manifest["environment_sha256"], fetch=self.fetch,
        )


def test_E03_signed_verifier_withdrawal_survives_reader_restart(tmp_path, record_property):
    researcher = create_lab()
    status = StatusFixture(tmp_path, researcher, researcher.bundle("disposable withdrawal control"), "deployment-a")
    assert status.appraise().binding is not None
    retain(record_property, "healthy_signed_status", status.last)
    verifier = researcher.verifiers[0]
    grant = researcher.trust.grants[verifier.issuer, verifier.key_id]
    now = int(time.time())
    withdrawal = sign_record(Withdrawal(
        kind="aegis.evidence.withdrawal.v1", issuer="review", key_id="lab-v1", cohort=COHORT,
        record_id=uuid4().hex, issued_at=now, expires_at=now + 10, target_kind="verifier-key",
        target_issuer=verifier.issuer, target_sha256=sha256(grant.public_key.public_bytes_raw()).hexdigest(),
        reason="withdrawn",
    ), researcher.revoker)
    status.admit(withdrawal)
    result = status.appraise()
    assert (result.binding, result.reason) == (None, "revoked")
    retain(record_property, "withdrawn_signed_status", status.last)
    restarted = status.appraise(reader=status.open_reader())
    with readonly(status.reader_path) as db:
        floor, blocked = db.execute("SELECT floor, blocked FROM status_state").fetchone()
    retain(record_property, "restarted_reader", {"floor": json.loads(floor), "blocked": blocked,
                                                  "outcome": restarted.outcome, "reason": restarted.reason})
    assert sha256(withdrawal).hexdigest() in json.loads(floor)
    assert (restarted.binding, restarted.reason) == (None, "revoked")


def test_E01_unenrolled_verifier_never_adds_corroboration(tmp_path, record_property):
    researcher = create_lab()
    status = StatusFixture(tmp_path, researcher, researcher.bundle("disposable enrollment control"), "deployment-a")
    assert status.appraise().binding is not None
    enrolled = researcher.verifiers[0]
    grant = researcher.trust.grants[enrolled.issuer, enrolled.key_id]
    separate = Verifier("separate-fixture-verifier", grant.key_id, Ed25519PrivateKey.generate())
    separate_grant = replace(grant, issuer=separate.issuer, public_key=separate.private_key.public_key())
    other_policy = replace(status.policy, trust=Trust([*researcher.trust.grants.values(), separate_grant]))
    wire = observe(other_policy, separate, status.bundle, clock=time.time)
    pin = sha256(wire).hexdigest()
    with pytest.raises(ValueError):
        status.witnesses[0].admit(wire)
    with readonly(tmp_path / "witness-0.sqlite") as db:
        pins = [row[0] for row in db.execute("SELECT digest FROM status_records ORDER BY digest")]
    assert status.appraise().binding is not None
    retain(record_property, "enrollment_readback", {"untrusted_digest": pin, "stored_digests": pins})
    assert pin not in pins and pins == status.last["record_digests"]


def test_W04_offline_journal_reconciles_an_expired_withdrawal(tmp_path, record_property):
    async def run():
        with ExitStack() as stack:
            network = Network(tmp_path, stack)
            finding = sign(network.finding(), network.author)
            network.archive.append(network.receive(finding))
            network.publish(network.seal())
            journal = network.client()
            binding, deadline = await journal.refresh()
            assert journal.current(finding, binding)
            withdrawal = network.withdrawal(finding)
            network.archive.append(network.receive(withdrawal))
            network.time.move(60)
            assert network.time.mono > deadline and network.now() > network.retirement
            assert not journal.current(finding, binding)

            class Offline:
                async def latest(self):
                    raise OSError("disposable history service offline")

            restarted = network.client(heads=Offline(), resume=True)
            with pytest.raises(JournalBlocked):
                await restarted.refresh()
            with readonly(tmp_path / "agent.db") as db:
                assert db.execute("SELECT count(*) FROM leaves").fetchone() == (1,)

            cut = network.publish(network.seal())
            restarted = network.client(resume=True)
            current, _ = await restarted.refresh()
            assert not restarted.current(finding, current)
            with readonly(tmp_path / "agent.db") as db:
                head = json.loads(db.execute("SELECT wire FROM checkpoint").fetchone()[0])
                leaves = [json.loads(row[0]) for row in db.execute("SELECT wire FROM leaves ORDER BY position")]
            retain(record_property, "reconnected_journal",
                   {"head": head, "stored_withdrawal": leaves[1]["envelope"], "revoker_retired": True})
            assert len(leaves) == 2 and head == cut.head.model_dump(mode="json")
            assert leaves[1]["envelope"] == withdrawal.model_dump(mode="json")
            reopened = network.client(resume=True)
            current, _ = await reopened.refresh()
            assert not reopened.current(finding, current)

    asyncio.run(run())


def test_I01_I03_signed_home_transfer(tmp_path, record_property):
    store = TargetStore(tmp_path / "ownership.sqlite", LocalOperator())
    store.create()
    home = store.ownership
    key = Ed25519PrivateKey.generate()
    deployment = str(uuid4())
    home.enroll(deployment, PRINCIPAL, key.public_key(), ("broker-a", "broker-b"))

    def claim(broker):
        proof = lease_proof("claim", home.candidate(broker), key)
        body = proof.body.model_dump(mode="json")
        key.public_key().verify(bytes.fromhex(proof.signature), b"AEGIS-OWNERSHIP/v1\0lease\0" + canonical(body))
        retain(record_property, f"signed_request_{broker}",
               {"body": body, "public_key": key.public_key().public_bytes_raw().hex(), "signature": proof.signature})
        return home.accept(proof, peer_principal=PRINCIPAL, broker=broker)

    first = claim("broker-a")
    with pytest.raises(Denied):
        home.enroll(deployment, "spiffe://aegis.lab/validation/second", key.public_key(), ("broker-b",))
    with pytest.raises(Denied):
        claim("broker-b")
    home.fence(first.generation)
    second = claim("broker-b")
    with pytest.raises(Denied):
        home.check(first)
    home.check(second)
    with readonly(store.path) as db:
        current = db.execute("SELECT principal, broker, generation FROM ownership").fetchone()
        events = db.execute("SELECT action, generation, broker FROM ownership_audit ORDER BY seq").fetchall()
    retain(record_property, "ownership_readback", {"current": current, "events": events})
    assert current == (PRINCIPAL, "broker-b", second.generation)
    assert second.generation > first.generation
    assert [(action, generation) for action, generation, _ in events if action == "claim"] == [
        ("claim", first.generation), ("claim", second.generation),
    ]


@pytest.mark.parametrize("case", ["M01_stale", "M02_missing", "healthy", "C04_status_loss", "I04_expiry"])
def test_local_writer_boundaries(tmp_path, record_property, monkeypatch, case):
    async def run():
        with ExitStack() as stack:
            network = Network(tmp_path, stack)
            researcher = create_lab()
            collector = stack.enter_context(Evidence(tmp_path / "collector.sqlite", researcher.trust,
                                                     researcher.verifiers))
            evidence = stack.enter_context(Evidence(tmp_path / "relying.sqlite", researcher.trust))
            finding, bundle, verification = publishable_finding(network.finding(), network.author,
                                                                researcher, collector)
            network.archive.append(network.receive(finding))
            network.publish(network.seal())
            audit = SqliteAudit(tmp_path / "rapid.sqlite", str(uuid4()))
            stack.enter_context(closing(audit.db))
            agent = LocalAgent(LocalPolicy(network.trust, frozenset({MESH_TEMPLATE}), True),
                               [InventoryItem(PACKAGE, VERSION)], audit)
            agent.evaluate_event(finding)
            with readonly(tmp_path / "rapid.sqlite") as db:
                row = db.execute("SELECT authenticated, outcome FROM decisions WHERE artifact_id = ?",
                                 (str(finding.finding.artifact_id),)).fetchone()
            assert row == (1, "allow_dry_run")
            status = StatusFixture(tmp_path, researcher, bundle, audit.agent_id)
            key = Ed25519PrivateKey.generate()
            store = TargetStore(tmp_path / "target.sqlite", LocalOperator())
            store.create()
            home = store.ownership
            home.enroll(audit.agent_id, PRINCIPAL, key.public_key(), ("broker-a",))
            assignment = home.accept(lease_proof("claim", home.candidate("broker-a"), key),
                                     peer_principal=PRINCIPAL, broker="broker-a")

            def coordinator(_):
                pytest.fail("witnessed fixture queried the coordinator")

            async with httpx.AsyncClient(transport=httpx.MockTransport(coordinator)) as remote:
                intake = MeshIntake(agent, None, remote, journal=network.client())
                intake.lease = SimpleNamespace(ensure=lambda: asyncio.sleep(0))
                gate = EvidenceGate(finding, bundle, verification, intake, collector, evidence,
                                    independent_evidence=NativeEvidenceStatus(status.reader, status.fetch))
                writer = VerifiedLab(gate, store.path, identity=IdentitySession(assignment, key))
                with writer.lab as lab:
                    controller = lab.controller
                    plan = await writer.prepare(3_000)
                    lab_id = snapshot(store.path)["lab"]
                    open_modes = dict.fromkeys(TARGETS, ("open", 0))
                    assert_routes(probe(lab.endpoints), lab_id, open_modes)
                    retain(record_property, "appraised_status", status.last)
                    if case in {"M01_stale", "M02_missing"}:
                        digest = "" if case == "M02_missing" else plan.digest
                        if case == "M01_stale":
                            plan = await writer.prepare(3_000)
                        with pytest.raises(Denied):
                            await writer.execute(plan, digest)
                        state, routes = snapshot(store.path), probe(lab.endpoints)
                        retain(record_property, "denied", {"db": state, "http": routes})
                        assert state["audit"] == [] and state["phase"] is None
                        assert state["targets"] == [(target, 0, "open") for target in TARGETS]
                        assert_routes(routes, lab_id, open_modes)
                        return
                    if case == "healthy":
                        await writer.execute(plan, plan.digest)
                        state, routes = snapshot(store.path), probe(lab.endpoints)
                        retain(record_property, "confirmed", {"db": state, "http": routes})
                        assert state["phase"] == "confirmed"
                        assert all(event[2] == plan.digest for event in state["audit"])
                        assert_routes(routes, lab_id, dict.fromkeys(TARGETS, ("restricted", 1)))
                        return

                    approval = lab.operator.approve(plan, plan.digest)
                    await writer.transition(controller.start, plan, approval, action="begin")
                    await writer.transition(controller.restrict, plan, approval, TARGETS[0],
                                            action="restrict", target=TARGETS[0])
                    await writer.transition(controller.verify, plan, canary=True, action="verify-canary")
                    canary_modes = open_modes | {TARGETS[0]: ("restricted", 1)}
                    assert_routes(probe(lab.endpoints), lab_id, canary_modes)
                    if case == "I04_expiry":
                        with readonly(store.path) as db:
                            mono_expiry, wall_expiry = db.execute(
                                "SELECT until_ns, until_utc_ns FROM ownership"
                            ).fetchone()
                        monkeypatch.setattr(ownership, "monotonic_ns", lambda: mono_expiry)
                        monkeypatch.setattr(ownership, "time_ns", lambda: wall_expiry)
                        retain(record_property, "expiry_boundary",
                               {"mono_ns": mono_expiry, "wall_ns": wall_expiry, "generation": assignment.generation})
                    else:
                        status.unavailable = True
                    with pytest.raises(Denied):
                        await writer.transition(controller.restrict, plan, approval, TARGETS[1],
                                                action="restrict", target=TARGETS[1])
                    state, routes = snapshot(store.path), probe(lab.endpoints)
                    retain(record_property, "authority_loss", {"db": state, "http": routes})
                    assert state["targets"] == [("canary", 1, "restricted"),
                                                ("replica-a", 0, "open"), ("replica-b", 0, "open")]
                    assert [row[3]["target"] for row in state["audit"] if row[1] == "restricted"] == [TARGETS[0]]
                    fences = dict(zip(TARGETS, (1, 0, 0), strict=True))
                    assert_routes(routes, lab_id, {target: ("quarantined", f) for target, f in fences.items()})
                with Lab(store.path, authorize=gate.authorize, status_current=gate.status_current,
                         require_identity=True) as restarted:
                    state, routes = snapshot(store.path), probe(restarted.endpoints)
                    retain(record_property, "restart_during_outage", {"db": state, "http": routes})
                    assert state["phase"] == "safe_hold"
                    assert [row[3]["target"] for row in state["audit"] if row[1] == "restricted"] == [TARGETS[0]]
                    assert_routes(routes, lab_id, {target: ("quarantined", f + 1) for target, f in fences.items()})

    asyncio.run(run())


def test_M05_unavailable_replica_blocks_verified_hold(tmp_path, record_property):
    path = tmp_path / "quarantine.sqlite"
    with Lab(path) as lab:
        plan = lab.controller.prepare(5_000)
        approval = lab.operator.approve(plan, plan.digest)
        lab.controller.execute(plan, approval)
        lab_id = snapshot(path)["lab"]
        assert_routes(probe(lab.endpoints), lab_id, dict.fromkeys(TARGETS, ("restricted", 1)))
        unavailable = TARGETS[-1]
        lab.proxies[unavailable].close()
        host, port = lab.endpoints[unavailable]
        assert host == "127.0.0.1"
        with closing(HTTPConnection(host, port, timeout=0.5)) as connection, pytest.raises(OSError):
            connection.request("GET", ROUTES[0])
        lab.controller.rollback("local observation unavailable")
        state, routes = snapshot(path), probe(lab.endpoints, missing=(unavailable,))
        retain(record_property, "quarantine_readback", {"db": state, "http": routes, "missing": unavailable})
        assert state["phase"] == "recovery_required"
        assert state["audit"][-1][1] == "recovery_unobserved"
        assert all(row[1] != "safe_hold" for row in state["audit"])
        assert_routes(routes, lab_id, dict.fromkeys(TARGETS[:-1], ("quarantined", 2)))
    with Lab(path) as restarted:
        state, routes = snapshot(path), probe(restarted.endpoints)
        retain(record_property, "reobserved_after_restart", {"db": state, "http": routes})
        assert state["phase"] == "safe_hold"
        assert_routes(routes, lab_id, dict.fromkeys(TARGETS, ("quarantined", 2)))
