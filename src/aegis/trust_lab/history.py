"""Full-prefix transparency and independently signed Evidence status."""

import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Literal

from aegis.evidence.records import canonical

from .identity import Hash, Hold, Name, Record, Signature, Tick, commitment, quorum, sign

REQUIRED_WITNESSES = 3
EVENT_ROLES = {
    "finding": "publisher",
    "corroboration": "verifier",
    "contradiction": "verifier",
    "mesh-withdrawal": "revoker",
    "evidence-withdrawal": "revoker",
}
MAX_EVENTS = 10_000


class Subject(Record):
    finding: Hash
    evidence: Hash


class Event(Record):
    scope: Name
    id: Name
    kind: Literal["finding", "corroboration", "contradiction", "mesh-withdrawal", "evidence-withdrawal"]
    subject: Subject
    issued: Tick
    expires: Tick


class SignedEvent(Record):
    body: Event
    signature: Signature


class Admission(Record):
    scope: Name
    event: Hash
    epoch: Tick
    trust: Hash


class Leaf(Record):
    body: Admission
    event: SignedEvent
    signatures: tuple[Signature, ...]


class Prefix(Record):
    receipts: tuple[Admission, ...]


class Checkpoint(Record):
    scope: Name
    epoch: Tick
    size: Tick
    root: Hash
    trust: Hash


class Coverage(Record):
    checkpoint: Checkpoint
    nonce: Hash


class Cut(Record):
    body: Coverage
    signatures: tuple[Signature, ...]
    leaves: tuple[Leaf, ...]


def prefix(leaves):
    return Prefix(receipts=tuple(leaf.body for leaf in leaves))


def checkpoint(trust, epoch, leaves):
    return Checkpoint(scope=trust.current.scope, epoch=epoch, size=len(leaves),
                      root=commitment(prefix(leaves)), trust=trust.head)


def authenticate_event(event, trust, epoch, version=None):
    body = event.body
    if body.scope != trust.current.scope or not body.issued <= epoch < body.expires:
        raise Hold("invalid event scope or time at admission")
    grant = trust.authenticate(event.signature, "event", body, EVENT_ROLES[body.kind], epoch, version)
    if body.issued < grant.starts:
        raise Hold("event predates its delegation")
    return grant


def verify_archive(leaves, head, trust):
    if len(leaves) > MAX_EVENTS or head != checkpoint(trust, head.epoch, leaves):
        raise Hold("incomplete archive or checkpoint mismatch")
    last_epoch = -1
    ids = set()
    for leaf in leaves:
        record = leaf.body
        if (record.scope != head.scope or not last_epoch <= record.epoch <= head.epoch
                or record.event != commitment(leaf.event) or leaf.event.body.id in ids):
            raise Hold("invalid archive ordering, event binding or duplicate event")
        quorum(leaf.signatures, "admission", record, trust.witnesses(record.epoch, record.trust), REQUIRED_WITNESSES)
        authenticate_event(leaf.event, trust, record.epoch, record.trust)
        ids.add(leaf.event.body.id)
        last_epoch = record.epoch


def check_extension(old_head, leaves, head):
    if (head.epoch < old_head.epoch or len(leaves) < old_head.size
            or commitment(prefix(leaves[:old_head.size])) != old_head.root
            or (head.epoch == old_head.epoch and head != old_head)
            or (len(leaves) > old_head.size and leaves[old_head.size].body.epoch <= old_head.epoch)):
        raise Hold("checkpoint rollback, fork or late insertion")


@contextmanager
def transaction(path, *, create=False):
    mode = "rwc" if create else "rw"
    with closing(sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode={mode}", uri=True)) as db:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        with db:
            yield db


class Witness:
    """One durable admission and seal state machine per fixed witness identity."""

    @classmethod
    def provision(cls, path, key_id, private_key, root, clock):
        with transaction(path, create=True) as db:
            db.execute("CREATE TABLE state (identity TEXT PRIMARY KEY, head BLOB, trust TEXT, tick INTEGER NOT NULL)")
            db.execute("INSERT INTO state VALUES (?, NULL, NULL, -1)", (key_id,))
            db.execute("CREATE TABLE obligations (id TEXT PRIMARY KEY, epoch INTEGER, receipt TEXT)")
        return cls(path, key_id, private_key, root, clock)

    def __init__(self, path, key_id, private_key, root, clock):
        self.path, self.key_id, self.private_key = path, key_id, private_key
        self.root, self.clock = root, clock

    def _state(self, db, trust, now):
        row = db.execute("SELECT head, trust, tick FROM state WHERE identity = ?", (self.key_id,)).fetchone()
        keys = trust.witnesses(now)
        if (row is None or now < row[2] or row[1] is not None and row[1] not in trust.versions
                or self.key_id not in keys
                or keys[self.key_id].public_bytes_raw() != self.private_key.public_key().public_bytes_raw()):
            raise Hold("unavailable witness state, clock or delegation")
        return Checkpoint.model_validate_json(row[0]) if row[0] is not None else None

    def admit(self, event, chain):
        now = self.clock.wall()
        trust = self.root.appraise(chain, now)
        authenticate_event(event, trust, now)
        receipt = Admission(scope=trust.current.scope, event=commitment(event), epoch=now, trust=trust.head)
        pin = commitment(receipt)
        with transaction(self.path) as db:
            prior = self._state(db, trust, now)
            if prior and now <= prior.epoch:
                raise Hold("admission epoch is sealed")
            row = db.execute("SELECT receipt FROM obligations WHERE id = ?", (event.body.id,)).fetchone()
            if row is not None and row[0] != pin:
                raise Hold("admission ID already used")
            db.execute("INSERT OR IGNORE INTO obligations VALUES (?, ?, ?)", (event.body.id, now, pin))
            db.execute("UPDATE state SET trust = ?, tick = ?", (trust.head, now))
            if self.clock.wall() != now:
                raise Hold("admission crossed an epoch boundary")
        return receipt, sign(self.key_id, self.private_key, "admission", receipt)

    def endorse(self, coverage, leaves, chain):
        now = self.clock.wall()
        trust = self.root.appraise(chain, now)
        head = coverage.checkpoint
        if now == 0 or head.epoch != now - 1:
            raise Hold("coverage does not seal the latest closed epoch")
        verify_archive(leaves, head, trust)
        covered = {commitment(leaf.body) for leaf in leaves}
        with transaction(self.path) as db:
            old = self._state(db, trust, now)
            if old:
                check_extension(old, leaves, head)
            obligations = db.execute("SELECT receipt FROM obligations WHERE epoch <= ?", (head.epoch,))
            if any(row[0] not in covered for row in obligations):
                raise Hold("receipted event missing from seal")
            db.execute("UPDATE state SET head = ?, trust = ?, tick = ?", (canonical(head), trust.head, now))
            if self.clock.wall() != now:
                raise Hold("coverage crossed an epoch boundary")
        return sign(self.key_id, self.private_key, "coverage", coverage)


class Appraisal(Record):
    outcome: Literal["current", "unknown", "withdrawn", "contested"]
    votes: tuple[Hash, ...] = ()
    ends: Tick = 0


class EvidenceStatus(Record):
    scope: Name
    subject: Subject
    checkpoint: Hash
    version: Tick
    nonce: Hash
    expires: Tick
    appraisal: Appraisal


class SignedStatus(Record):
    body: EvidenceStatus
    signature: Signature


def assess(leaves, subject, trust, now):
    """Return mesh eligibility and exact-scope Evidence status."""
    active = []
    mesh_denied = False
    withdrawn = False
    contested = False
    for leaf in leaves:
        event = leaf.event.body
        if event.kind == "mesh-withdrawal" and event.subject.finding == subject.finding:
            mesh_denied = True
        if event.subject != subject:
            continue
        cutoff = trust.cuts.get(leaf.event.signature.key)
        if cutoff is not None and (leaf.body.epoch >= cutoff or (
                now >= cutoff and event.kind in {"finding", "corroboration"}
        )):
            # An uncertain negative still closes the gate. Previously known
            # denials cannot disappear under a new compromise snapshot.
            if event.kind in {"evidence-withdrawal", "contradiction"}:
                contested = True
            continue
        if event.kind == "evidence-withdrawal":
            withdrawn = True
        elif event.kind == "contradiction":
            contested = True
        elif event.kind in {"finding", "corroboration"} and now < event.expires:
            try:
                grant = trust.grant(leaf.event.signature.key, EVENT_ROLES[event.kind], now)
            except Hold:
                continue
            active.append((leaf, grant.organization, min(event.expires, grant.ends, cutoff if cutoff is not None else grant.ends)))

    finding = [entry for entry in active if entry[0].event.body.kind == "finding"]
    if withdrawn:
        return False, Appraisal(outcome="withdrawn")
    if contested:
        return False, Appraisal(outcome="contested")
    if len(finding) != 1:
        return False, Appraisal(outcome="unknown")
    _, submitter, finding_end = finding[0]
    votes = {}
    for leaf, organization, ends in active:
        if leaf.event.body.kind == "corroboration" and organization != submitter:
            votes.setdefault(organization, (commitment(leaf.body), ends))
    if len(votes) < 2:
        return False, Appraisal(outcome="unknown")
    return not mesh_denied, Appraisal(
        outcome="current", votes=tuple(sorted(pin for pin, _ in votes.values())),
        ends=min(finding_end, *(ends for _, ends in votes.values())),
    )


def status_for(head, leaves, subject, trust, now, nonce):
    _, appraisal = assess(leaves, subject, trust, now)
    return EvidenceStatus(scope=head.scope, subject=subject, checkpoint=commitment(head),
                          version=head.epoch + 1, nonce=nonce, expires=head.epoch + 2, appraisal=appraisal)


class EvidenceAuthority:
    """A separate signer appraises only a complete, witnessed cut."""

    def __init__(self, key_id, private_key, root, clock):
        self.key_id, self.private_key = key_id, private_key
        self.root, self.clock = root, clock

    def issue(self, cut, chain, subject):
        now = self.clock.wall()
        trust = self.root.appraise(chain, now)
        head = cut.body.checkpoint
        if head.epoch != now - 1:
            raise Hold("status requires the latest closed epoch")
        quorum(cut.signatures, "coverage", cut.body, trust.witnesses(now), REQUIRED_WITNESSES)
        verify_archive(cut.leaves, head, trust)
        body = status_for(head, cut.leaves, subject, trust, now, cut.body.nonce)
        signature = sign(self.key_id, self.private_key, "status", body)
        trust.authenticate(signature, "status", body, "status", now)
        if self.clock.wall() != now:
            raise Hold("status crossed an epoch boundary")
        return SignedStatus(body=body, signature=signature)
