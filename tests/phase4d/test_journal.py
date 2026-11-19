"""Defensive checks against signed but incomplete history in disposable stores."""

import asyncio
from contextlib import AsyncExitStack, ExitStack, closing
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import os
import shutil
import sqlite3
import subprocess
import time
from types import SimpleNamespace
from uuid import uuid4

import httpx
import nats
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException, Request

from aegis.api import ensure_streams
from aegis.artifact import Evidence as Reference
from aegis.artifact import Finding, Revocation, Software, sign, sign_revocation
from aegis.core import InventoryItem, LocalAgent, LocalPolicy
from aegis.evidence import Evidence
from aegis.evidence.synthetic import create_lab
from aegis.identity import IdentityLease, IdentityLost
from aegis.journal.client import ArchiveSource, JournalClient, ProtectedHead, UNINITIALIZED, finding_target
from aegis.journal.http import HTTPArchive, HTTPHeads, HTTPWitness, archive_router, witness_router
from aegis.journal.merkle import EMPTY, Tree, verify_consistency, verify_inclusion
from aegis.journal.monitor import Monitor
from aegis.journal.protocol import Clock, Cut, JournalBlocked, Leaf, Policy, canonical, digest, vote
from aegis.journal.storage import EMPTY_CHAIN, SQLitePin
from aegis.journal.witness import Archive, Witness, WitnessHeads, collect_receipt
from aegis.mesh import STREAM, SUBJECT
from aegis.mitigation.policy import Denied
from aegis.phase3c import EvidenceGate, MESH_TEMPLATE, MeshIntake, PACKAGE, VERSION, VerifiedLab, publishable_finding
from aegis.storage import SqliteAudit
from aegis.trust import PublisherGrant, TrustStore


class Time:
    def __init__(self):
        self.utc = float(int(time.time() // 10) * 10 + 2)
        self.mono = time.monotonic()

    def move(self, seconds):
        self.utc += seconds
        self.mono += seconds

    def clock(self):
        return Clock(lambda: self.utc, lambda: self.mono)


class Network:
    def __init__(self, directory, resources):
        self.directory, self.resources = directory, resources
        self.time = Time()
        self.coordinator = Ed25519PrivateKey.generate()
        self.author = Ed25519PrivateKey.generate()
        self.reviewer = Ed25519PrivateKey.generate()
        self.keys = {f"w{i}": Ed25519PrivateKey.generate() for i in range(4)}
        start = self.now() - timedelta(hours=1)
        end = self.now() + timedelta(hours=2)
        self.retirement = self.now() + timedelta(seconds=45)
        self.trust = TrustStore([
            PublisherGrant("author", "default", self.author.public_key(), frozenset({"finding"}), start, end),
            PublisherGrant("review", "default", self.reviewer.public_key(), frozenset({"revocation"}),
                           start, self.retirement, revocation_publishers=frozenset({"author"})),
        ])
        self.policy = Policy("mesh-v1", "lab-blue", self.coordinator.public_key(),
                             {name: key.public_key() for name, key in self.keys.items()},
                             3, 1, 10, 3, 20, self.trust)
        self.archive = self.new_archive("archive")
        self.witnesses = []
        for name in self.keys:
            self.pin(name, EMPTY_CHAIN)
            self.witnesses.append(self.open_witness(name))
        self.heads = WitnessHeads(self.policy, self.witnesses)

    def pin(self, name, genesis=None):
        pin = SQLitePin(self.directory / f"{name}-protected.db", name)
        if genesis is not None:
            pin.provision(genesis)
        return pin

    def new_archive(self, name):
        archive = Archive(self.directory / f"{name}.db", self.policy)
        self.resources.callback(archive.close)
        return archive

    def open_witness(self, name):
        witness = Witness(name, self.keys[name], self.policy, self.directory / f"{name}.db",
                          self.pin(name), self.time.clock())
        self.resources.callback(witness.close)
        return witness

    def now(self):
        return datetime.fromtimestamp(self.time.utc, timezone.utc)

    def finding(self, sequence=1):
        issued = min(self.now(), datetime.now(timezone.utc)) - timedelta(seconds=2)
        return Finding(schema_version="1.0", artifact_id=uuid4(), publisher_id="author", sequence=sequence,
                       issued_at=issued, expires_at=self.now() + timedelta(hours=1),
                       vulnerability_id="PHASE4D-DISPOSABLE-FIXTURE",
                       software=Software(purl=PACKAGE, affected_versions=[VERSION]),
                       evidence=[Reference(uri="urn:fixture", sha256="0" * 64, method="lab-reproduction")],
                       applicability="authorized-lab", mitigation_template=MESH_TEMPLATE)

    def withdrawal(self, finding):
        publisher, identity, body = finding_target(finding)
        return sign_revocation(Revocation(schema_version="1.1", revocation_id=uuid4(), publisher_id="review",
                                          sequence=1, issued_at=self.now() - timedelta(seconds=1),
                                          expires_at=self.now() + timedelta(seconds=8), target_artifact_id=identity,
                                          target_sha256=body, target_publisher_id=publisher, reason="withdrawn"),
                               self.reviewer, "default")

    def receive(self, envelope, indexes=(0, 1, 2, 3)):
        receipt = collect_receipt(self.policy, (self.witnesses[i].admit(envelope) for i in indexes))
        return Leaf(receipt=receipt, envelope=envelope)

    def seal(self):
        self.time.move(10 - self.time.utc % 10 + 1)
        return int(self.time.utc // 10) - 1

    def publish(self, epoch, *, indexes=(0, 1, 2), archive=None):
        archive = archive or self.archive
        signed = archive.propose(self.coordinator, epoch)
        votes = tuple(self.witnesses[i].cosign(signed, archive) for i in indexes)
        return Cut(signed=signed, votes=votes)

    def client(self, name="agent", *, heads=None, archives=None, resume=False, cache=None):
        pin = self.pin(name, None if resume else UNINITIALIZED)
        return JournalClient(self.policy, heads or self.heads,
                             archives if archives is not None else (ArchiveSource(self.archive),),
                             pin, cache or self.directory / f"{name}.db", self.time.clock())


@pytest.fixture
def network(tmp_path):
    with ExitStack() as stack:
        yield Network(tmp_path, stack)


def run(coroutine):
    return asyncio.run(coroutine)


def fixed(cut):
    async def latest():
        return cut
    return SimpleNamespace(latest=latest)


def test_merkle_exhaustive_shape_and_malformed_proofs():
    """Use an independent recursive root oracle and every prefix through 65 leaves."""
    wires = [f"security record {index}".encode() for index in range(65)]

    def root(entries):
        if len(entries) < 2:
            return sha256(b"\x00" + entries[0] if entries else b"").digest()
        left = 2 ** ((len(entries) - 1).bit_length() - 1)
        return sha256(b"\x01" + root(entries[:left]) + root(entries[left:])).digest()

    tree = Tree()
    for wire in wires:
        tree.append(wire)
    roots = [root(wires[:size]) for size in range(len(wires) + 1)]
    for size, expected in enumerate(roots):
        assert tree.root(size) == expected
        for index, wire in enumerate(wires[:size]):
            proof = tree.inclusion(index, size)
            assert verify_inclusion(wire, index, size, expected, proof)
            assert not verify_inclusion(wire + b"x", index, size, expected, proof)
            assert not verify_inclusion(wire, size, size, expected, proof)
            assert not verify_inclusion(wire, index, size, expected, proof + (EMPTY,))
            if proof:
                assert not verify_inclusion(wire, index, size, expected, proof[:-1])
        for before in range(size + 1):
            proof = tree.consistency(before, size)
            assert verify_consistency(before, size, roots[before], expected, proof)
            assert not verify_consistency(before, size, EMPTY if before else b"x" * 32, expected, proof)
            assert not verify_consistency(before, size, roots[before], expected, proof + (EMPTY,))
            if proof:
                assert not verify_consistency(before, size, roots[before], expected, proof[:-1])
                assert not verify_consistency(before, size, roots[before], b"x" * 32, proof)


def test_receipted_withdrawal_cannot_be_omitted_even_with_a_byzantine_vote(network):
    n = network
    finding = sign(n.finding(), n.author)
    n.archive.append(n.receive(finding))
    first = n.publish(n.seal())
    agent = n.client()
    binding, _ = run(agent.refresh())
    assert agent.current(finding, binding)

    withdrawal = n.receive(n.withdrawal(finding), (0, 1, 2))
    epoch = n.seal()
    omitted = n.archive.propose(n.coordinator, epoch)
    for index in (0, 1, 2):
        with pytest.raises(JournalBlocked, match="omits"):
            n.witnesses[index].cosign(omitted, n.archive)
    honest_outside_intake = n.witnesses[3].cosign(omitted, n.archive)
    unauthorized = Cut(signed=omitted, votes=(vote("w0", n.keys["w0"], omitted), honest_outside_intake))
    agent.heads = fixed(unauthorized)
    with pytest.raises(JournalBlocked, match="quorum"):
        run(agent.refresh())
    assert not agent.current(finding, binding)

    # A previously fresh view has a fixed deadline, even if replayed after isolation.
    n.time.move(11)
    agent.heads = fixed(first)
    with pytest.raises(JournalBlocked, match="stale"):
        run(agent.refresh())
    monitor = Monitor(n.policy, n.directory / "monitor.db")
    assert monitor.merge_status(withdrawal.receipt, n.time.utc, None, None) == "merge_proof_unavailable"


def test_witnesses_verify_coverage_conflicts_and_monitor_retains_signed_evidence(network):
    n = network
    a = n.receive(sign(n.finding(1), n.author))
    n.archive.append(a)
    epoch = n.seal()
    cut = n.publish(epoch)
    b = n.receive(sign(n.finding(2), n.author))
    alternate = n.new_archive("alternate")
    alternate.append(b)
    conflicting = alternate.propose(n.coordinator, epoch)
    monitor_path = n.directory / "monitor.db"
    assert Monitor(n.policy, monitor_path).observe(cut.signed) == ()
    monitor = Monitor(n.policy, monitor_path)
    assert monitor.observe(conflicting) == ((cut.signed, conflicting),)
    with pytest.raises(JournalBlocked, match="conflict"):
        monitor.check_extension(cut.signed, conflicting, ())
    for index in (0, 1, 2):
        with pytest.raises(JournalBlocked, match="rollback or conflict"):
            n.witnesses[index].cosign(conflicting, alternate)

    c = n.receive(sign(n.finding(3), n.author))
    alternate.append(c)
    n.archive.append(b)
    n.archive.append(c)
    epoch = n.seal()
    unrelated_extension = alternate.propose(n.coordinator, epoch)
    for index in (0, 1, 2):
        with pytest.raises(JournalBlocked, match="consistency"):
            n.witnesses[index].cosign(unrelated_extension, alternate)

    # One enrolled operator is offline. Three honest witnesses can still sign.
    newer = n.publish(epoch)
    agent = n.client(heads=WitnessHeads(n.policy, n.witnesses[:3]))
    binding, _ = run(agent.refresh())
    assert newer.head.size == 3 and agent.current(b.envelope, binding)


def test_corrupt_pages_hold_and_resume_from_independent_mirror_after_broker_loss(network):
    n = network
    finding = sign(n.finding(), n.author)
    leaf = n.receive(finding)
    n.archive.append(leaf)
    first = n.publish(n.seal())
    agent = n.client()
    binding, _ = run(agent.refresh())
    assert agent.current(finding, binding)

    # No broker message or coordinator replay reaches this agent.
    missing = n.receive(n.withdrawal(finding))
    mirror = n.new_archive("independent-mirror")
    mirror.append(leaf)
    mirror.append(missing)
    second = n.publish(n.seal(), archive=mirror)

    class Omission(ArchiveSource):
        async def page(self, head, start, limit):
            return ()

    bad = Omission(mirror)
    agent.archives = (bad,)
    with pytest.raises(JournalBlocked, match="complete verified page"):
        run(agent.refresh())
    assert not agent.current(finding, binding)
    assert agent.replay.head == first.head
    assert agent.pin.read() == canonical(ProtectedHead(verified=second.head))

    # A restart after a partial replay cannot be downgraded to the old cut,
    # even inside the old cut's signed freshness window.
    restarted = n.client(heads=fixed(first), resume=True)
    with pytest.raises(JournalBlocked, match="consistency|rolls back"):
        run(restarted.refresh())

    # Damage the replay database on disk and recover from an independent mirror.
    cache = n.directory / "agent.db"
    with closing(sqlite3.connect(cache)) as db, db:
        db.execute("UPDATE leaves SET wire = ? WHERE position = 0", (b"corrupt",))
    n.time.move(50)  # Both the withdrawal and planned revoker grant have expired.
    recovered_cut = n.publish(n.seal(), archive=mirror)
    restarted = n.client(resume=True, archives=(bad, ArchiveSource(mirror)))
    recovered, _ = run(restarted.refresh())
    assert restarted.replay.head == recovered_cut.head
    assert not restarted.current(finding, recovered)
    assert restarted.replay.denials == {finding_target(finding)}
    with closing(sqlite3.connect(cache)) as db:
        assert db.execute("SELECT count(*) FROM leaves").fetchone() == (2,)
    assert n.trust.grants["review", "default"].expires_at <= n.now()

    cache.write_bytes(b"unreadable SQLite file")
    corrupted = n.client(resume=True, archives=(ArchiveSource(mirror),))
    with pytest.raises(JournalBlocked, match="file is not a database"):
        run(corrupted.refresh())
    rebuilt = n.client(resume=True, archives=(ArchiveSource(mirror),),
                       cache=n.directory / "agent-restored.db")
    restored, _ = run(rebuilt.refresh())
    assert not rebuilt.current(finding, restored)
    assert rebuilt.replay.denials == {finding_target(finding)}

    monitor = Monitor(n.policy, n.directory / "receipt-monitor.db")
    timely = n.policy.cutoff(second.head.epoch) + 1
    entry = mirror.page(second.head, 1, 1)[0]
    assert monitor.merge_status(missing.receipt, timely, second, entry) == "included"
    late = n.policy.cutoff(second.head.epoch) + n.policy.merge_seconds + 1
    assert monitor.merge_status(missing.receipt, late, None, None) == "included"
    other = Monitor(n.policy, n.directory / "late-receipt-monitor.db")
    assert other.merge_status(missing.receipt, late, None, None) == "merge_proof_unavailable"
    assert other.merge_status(missing.receipt, late, second, entry) == "included_when_observed_after_deadline"


def test_failed_consistency_coordinator_signature_and_cutoff_refresh_cannot_renew(network):
    n = network
    finding = sign(n.finding(), n.author)
    n.archive.append(n.receive(finding))
    first = n.publish(n.seal())
    agent = n.client()
    binding, original = run(agent.refresh())
    n.time.move(1)
    assert run(agent.refresh()) == (binding, original)

    forged = Cut(signed=first.signed, votes=())
    agent.heads = fixed(forged)
    with pytest.raises(JournalBlocked, match="quorum"):
        run(agent.refresh())
    assert not agent.current(finding, binding)

    n.archive.append(n.receive(sign(n.finding(2), n.author)))
    second = n.publish(n.seal())

    class InvalidProof(ArchiveSource):
        async def consistency(self, before, head):
            return ("aa" * 32,)

    agent.heads, agent.archives = fixed(second), (InvalidProof(n.archive),)
    with pytest.raises(JournalBlocked, match="consistency"):
        run(agent.refresh())
    assert agent.pin.read() == canonical(ProtectedHead(verified=first.head, pending=second.head))
    restored = n.client(heads=fixed(first), resume=True)
    with pytest.raises(JournalBlocked, match="rolls back"):
        run(restored.refresh())

    n.time.move(20)
    with pytest.raises(JournalBlocked, match="stale"):
        run(agent.refresh())


def test_witness_rejects_restore_and_corruption_and_preserves_pending_admissions(network):
    n = network
    witness = n.witnesses[0]
    path = n.directory / "w0.db"
    prior = n.directory / "older.db"
    shutil.copyfile(path, prior)
    leaf = n.receive(sign(n.finding(), n.author))
    exact = n.witnesses[0].admit(leaf.envelope)
    assert exact == (leaf.receipt.admission, leaf.receipt.votes[0])
    epoch = n.seal()
    restarted = n.open_witness("w0")
    assert restarted.admitted(leaf.receipt.admission.event, leaf.receipt.admission.epoch) == (leaf.envelope, *exact)
    with pytest.raises(JournalBlocked, match="omits"):
        restarted.cosign(n.archive.propose(n.coordinator, epoch), n.archive)

    exact_backup = n.directory / "current.db"
    shutil.copyfile(path, exact_backup)
    shutil.copyfile(prior, path)
    with pytest.raises(JournalBlocked, match="protected pin"):
        n.open_witness("w0")

    shutil.copyfile(exact_backup, path)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("UPDATE ops SET wire = ? WHERE position = 0", (b"fake-op",))
    with pytest.raises(JournalBlocked, match="protected pin"):
        n.open_witness("w0")

    shutil.copyfile(exact_backup, path)
    restored = n.open_witness("w0")
    n.archive.append(leaf)
    signed = n.archive.propose(n.coordinator, epoch)
    signature = restored.cosign(signed, n.archive)
    n.policy.check_vote(signed, signature)
    assert restored.published() == (signed, signature)


def test_wrong_scope_signature_and_quorum_are_rejected(network):
    n = network
    from dataclasses import replace

    keys = {name: key.public_key() for name, key in n.keys.items()}
    with pytest.raises(ValueError, match="own signing key"):
        replace(n.policy, operators={**keys, "w0": n.coordinator.public_key()})
    with pytest.raises(ValueError, match="intersection"):
        replace(n.policy, quorum=2)
    with pytest.raises(ValueError, match="own signing key"):
        replace(n.policy, operators={**keys, "w1": keys["w0"]})

    finding = sign(n.finding(), n.author)
    wrong_signature = finding.model_copy(update={"signature": "AA=="})
    with pytest.raises(JournalBlocked, match="invalid signature"):
        n.witnesses[0].admit(wrong_signature)
    withdrawal = n.withdrawal(finding)
    cross_scope = withdrawal.revocation.model_copy(update={"target_publisher_id": "another"})
    with pytest.raises(JournalBlocked, match="outside grant scope"):
        n.witnesses[0].admit(sign_revocation(cross_scope, n.reviewer, "default"))
    leaf = n.receive(finding)
    with pytest.raises(JournalBlocked, match="distinct canonical quorum"):
        n.policy.check_receipt(leaf.receipt.model_copy(update={"votes": (leaf.receipt.votes[0],) * 3}))
    with pytest.raises(JournalBlocked, match="outside the pinned"):
        replace(n.policy, cohort="lab-green").check_receipt(leaf.receipt)

    retry = n.archive.append(leaf)
    assert n.archive.append(leaf) == retry == 0
    conflict = sign(n.finding(), n.author)
    with pytest.raises(JournalBlocked, match="conflicting"):
        n.witnesses[0].admit(conflict)


def test_clock_rollback_and_missing_witness_quorum_clear_eligibility(network):
    n = network
    finding = sign(n.finding(), n.author)
    n.archive.append(n.receive(finding))
    n.publish(n.seal())
    agent = n.client()
    binding, _ = run(agent.refresh())
    n.time.utc -= 1
    assert not agent.current(finding, binding)
    with pytest.raises(JournalBlocked, match="clock rolled back"):
        run(agent.refresh())
    n.time.utc += 1
    agent.heads = WitnessHeads(n.policy, n.witnesses[:2])
    with pytest.raises(JournalBlocked, match="no available quorum"):
        run(agent.refresh())
    assert not agent.current(finding, binding)


def test_witnessed_write_gate_blocks_peers_after_canary_without_legacy_journal(network):
    n = network
    researcher = create_lab()
    with (Evidence(n.directory / "collector.db", researcher.trust, researcher.verifiers) as collector,
          Evidence(n.directory / "relying.db", researcher.trust) as relying):
        finding, bundle, appraisal = publishable_finding(n.finding(), n.author, researcher, collector)
        n.archive.append(n.receive(finding))
        first = n.publish(n.seal())
        journal = n.client()
        audit = SqliteAudit(n.directory / "rapid.db", str(uuid4()))

        async def prove():
            def legacy(request):
                pytest.fail("witnessed write gate queried the legacy coordinator")

            async with httpx.AsyncClient(base_url="http://legacy.invalid", transport=httpx.MockTransport(legacy)) as remote:
                agent = LocalAgent(LocalPolicy(n.trust, frozenset({MESH_TEMPLATE}), True),
                                   [InventoryItem(PACKAGE, VERSION)], audit)
                intake = MeshIntake(agent, None, remote, journal=journal)
                intake.lease = SimpleNamespace(ensure=lambda: asyncio.sleep(0))
                gate = EvidenceGate(finding, bundle, appraisal, intake, collector, relying)
                defense = VerifiedLab(gate, n.directory / "fixture.db")
                with defense.lab:
                    old_plan = await defense.prepare(5_000)
                    old_approval = defense.lab.operator.approve(old_plan, old_plan.digest)
                    assert gate.binding_context["mesh_checkpoint_sha256"] == digest(first.head)

                    # A newer sealed empty epoch commits to the same tree but
                    # invalidates a review bound to the previous cutoff.
                    empty_epoch = n.publish(n.seal())
                    assert empty_epoch.head.root == first.head.root
                    with pytest.raises(JournalBlocked, match="no current, complete"):
                        await defense.transition(defense.lab.controller.start, old_plan, old_approval)
                    assert defense.lab.store.status() == "ready"
                    plan = await defense.prepare(5_000)
                    assert plan.evidence_binding != old_plan.evidence_binding
                    approval = defense.lab.operator.approve(plan, plan.digest)
                    await defense.transition(defense.lab.controller.start, plan, approval)
                    await defense.transition(defense.lab.controller.restrict, plan, approval, plan.targets[0])
                    await defense.transition(defense.lab.controller.verify, plan, canary=True)
                    # Independently receipted withdrawal has no broker delivery.
                    n.archive.append(n.receive(n.withdrawal(finding)))
                    n.publish(n.seal())
                    with pytest.raises(Denied, match="withdrawn"):
                        await defense.transition(defense.lab.controller.restrict, plan, approval, plan.targets[1])
                    assert defense.lab.controller.rollback("witnessed withdrawal") == "safe_hold"
                    rows = defense.lab.store.history()
                    assert [row["detail"]["target"] for row in rows if row["event"] == "restricted"] == ["canary"]
                    assert rows[-1]["event"] == "safe_hold"
                    assert audit.journal_position() == 0

        try:
            run(prove())
        finally:
            audit.db.close()


@pytest.mark.skipif(os.getenv("AEGIS_PHASE4D_LIVE") != "1",
                    reason="set AEGIS_PHASE4D_LIVE=1 for a disposable loopback NATS replacement")
def test_live_broker_loss_and_replacement_reconcile_with_independent_archive(network):
    n = network
    finding = sign(n.finding(), n.author)
    leaf = n.receive(finding)
    n.archive.append(leaf)
    n.publish(n.seal())
    mirror = n.new_archive("disconnected-mirror")
    mirror.append(leaf)
    journal = n.client(archives=(ArchiveSource(n.archive), ArchiveSource(mirror)))

    def docker(*args):
        return subprocess.run(["docker", *args], text=True, check=True, capture_output=True, timeout=30).stdout.strip()

    names = set()

    async def broker():
        name = f"aegis-phase4d-{uuid4().hex}"
        docker("run", "--detach", "--rm", "--pull", "never", "--name", name,
               "--publish", "127.0.0.1::4222", "nats:2.10-alpine", "-js")
        names.add(name)
        host = docker("port", name, "4222/tcp")
        for _ in range(30):
            try:
                nc = await nats.connect(f"nats://{host}", allow_reconnect=False, connect_timeout=1)
                return name, nc
            except (OSError, nats.errors.NoServersError):
                await asyncio.sleep(.05)
        raise AssertionError("disposable NATS did not start")

    async def prove():
        async with httpx.AsyncClient(base_url="http://legacy.invalid", transport=httpx.MockTransport(
                lambda _: httpx.Response(503))) as remote:
            with closing(audit.db):
                agent = LocalAgent(LocalPolicy(n.trust, frozenset({MESH_TEMPLATE}), True),
                                   [InventoryItem(PACKAGE, VERSION)], audit)
                name, nc = await broker()
                try:
                    js = nc.jetstream()
                    await ensure_streams(js)
                    await js.publish(SUBJECT, finding.model_dump_json().encode())
                    intake = MeshIntake(agent, js, remote, journal=journal)
                    intake.lease = await IdentityLease.claim(js, audit.agent_id)
                    await intake.fresh(finding)
                    assert (await js.stream_info(STREAM)).state.messages == 1
                    docker("stop", name)
                    names.remove(name)
                    with pytest.raises((TimeoutError, nats.errors.Error, IdentityLost)):
                        await intake.fresh(finding)
                finally:
                    await nc.close()

                # The withdrawal has no broker or original archive copy.
                missed = n.receive(n.withdrawal(finding))
                mirror.append(missed)
                with n.archive.db:
                    n.archive.db.execute("DELETE FROM leaves WHERE position = 0")
                n.publish(n.seal(), archive=mirror)
                binding, _ = await journal.refresh()
                assert not journal.current(finding, binding)

                _, replacement = await broker()
                try:
                    js = replacement.jetstream()
                    await ensure_streams(js)
                    assert (await js.stream_info(STREAM)).state.messages == 0
                    intake = MeshIntake(agent, js, remote, journal=journal)
                    intake.lease = await IdentityLease.claim(js, audit.agent_id)
                    with pytest.raises(Denied, match="withdrawn"):
                        await intake.fresh(finding)
                    assert journal.replay.denials == {finding_target(finding)}
                    assert audit.journal_position() == 0
                finally:
                    await replacement.close()

    audit = SqliteAudit(n.directory / "live-rapid.db", str(uuid4()))
    try:
        run(prove())
    finally:
        for name in names:
            docker("rm", "-f", name)


def test_authenticated_wire_roundtrip_and_independent_witness_roster(network):
    n = network

    async def authorize(request: Request):
        # This test exercises route authorization. Deployment authenticates
        # separately enrolled TLS clients with operation-specific permissions.
        if request.headers.get("Authorization") != "fixture-role":
            raise HTTPException(401, "not admitted")

    async def prove():
        async with AsyncExitStack() as stack:
            async def connect(router, allowed=True):
                app = FastAPI()
                app.include_router(router)
                return await stack.enter_async_context(httpx.AsyncClient(
                    base_url="https://fixture.invalid", transport=httpx.ASGITransport(app=app),
                    headers={"Authorization": "fixture-role"} if allowed else {},
                ))

            coordinator = HTTPArchive(await connect(archive_router(n.archive, authorize)))
            archives, witnesses = [], {}
            for witness in n.witnesses:
                mirror = n.new_archive(f"mirror-{witness.name}")
                archives.append(HTTPArchive(await connect(archive_router(mirror, authorize))))
                witnesses[witness.name] = HTTPWitness(await connect(
                    witness_router(witness, mirror, authorize), allowed=witness.name != "w3"))

            finding = sign(n.finding(), n.author)
            with pytest.raises(httpx.HTTPStatusError) as error:
                await witnesses["w3"].admit(finding)
            assert error.value.response.status_code == 401
            votes = await asyncio.gather(*(endpoint.admit(finding) for endpoint in tuple(witnesses.values())[:3]))
            receipt = collect_receipt(n.policy, ((value.admission, value.vote) for value in votes))
            recovered = await witnesses["w0"].admitted(receipt.admission.event, receipt.admission.epoch)
            assert recovered.envelope == finding and recovered.vote == votes[0].vote
            leaf = Leaf(receipt=receipt, envelope=finding)
            for archive in [coordinator, *archives]:
                assert await archive.append(leaf) == 0
            proposal = n.archive.propose(n.coordinator, n.seal())
            for endpoint in tuple(witnesses.values())[:3]:
                await endpoint.cosign(proposal)
            client = n.client(heads=HTTPHeads(n.policy, witnesses), archives=(archives[0],))
            binding, _ = await client.refresh()
            assert client.current(finding, binding)

    run(prove())


def test_missing_final_page_never_promotes_partial_replay(network):
    n = network
    finding = sign(n.finding(), n.author)
    n.archive.append(n.receive(finding, (0, 1, 2)))
    n.publish(n.seal())
    agent = n.client()
    prior, _ = run(agent.refresh())
    n.archive.append(n.receive(n.withdrawal(finding), (0, 1, 2)))
    for sequence in range(2, 130):
        n.archive.append(n.receive(sign(n.finding(sequence), n.author), (0, 1, 2)))
    final = n.publish(n.seal())

    class TruncateSecondPage(ArchiveSource):
        async def page(self, head, start, limit):
            entries = await super().page(head, start, limit)
            return entries[:-1] if start > 1 else entries

    agent.archives = (TruncateSecondPage(n.archive),)
    with pytest.raises(JournalBlocked, match="complete verified page"):
        run(agent.refresh())
    assert not agent.current(finding, prior)
    assert agent.replay.head.size == 1
    with closing(sqlite3.connect(n.directory / "agent.db")) as db:
        assert db.execute("SELECT count(*) FROM leaves").fetchone() == (1,)

    agent.archives = (ArchiveSource(n.archive),)
    binding, _ = run(agent.refresh())
    assert agent.replay.head == final.head and agent.replay.denials == {finding_target(finding)}
    assert not agent.current(finding, binding)
