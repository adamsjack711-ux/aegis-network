"""Bounded archive, direct witness intake and independently verifiable reconciliation."""

from contextlib import closing
import json
from pathlib import Path
import sqlite3

from ..journal.merkle import Tree, verify_inclusion
from ..journal.protocol import Admission, JournalBlocked, SignedHead, canonical, digest, vote
from ..journal.storage import WitnessLedger
from ..journal.witness import verify_extension
from .protocol import (Leaf, MAX_ORDINARY, MAX_RECORDS, Snapshot, View, Wire, WithdrawalView,
                       is_withdrawal, message, view_binding, withdrawal_binding)


class Archive:
    """This store is replaceable. Signed heads authenticate the original leaf bytes."""

    def __init__(self, path: Path, policy):
        self.path, self.policy = path, policy
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS leaves (position INTEGER PRIMARY KEY, wire BLOB NOT NULL)")

    def append(self, leaf):
        record, _, _ = self.policy.check_leaf(leaf, leaf.receipt.admission.epoch)
        wire = canonical(leaf)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT position, wire FROM leaves ORDER BY position").fetchall()
            for index, current in rows:
                if Leaf.model_validate_json(current).receipt.admission.event == leaf.receipt.admission.event:
                    return index
            capacity = MAX_RECORDS if is_withdrawal(record) else MAX_ORDINARY
            if len(rows) >= capacity or (rows and rows[-1][0] != len(rows) - 1):
                raise JournalBlocked("archive capacity or dense indexes failed")
            db.execute("INSERT INTO leaves VALUES (?, ?)", (len(rows), wire))
            return len(rows)

    def snapshot(self, size):
        with closing(sqlite3.connect(self.path)) as db:
            rows = db.execute("SELECT position, wire FROM leaves WHERE position < ? ORDER BY position",
                              (size,)).fetchall()
        leaves = []
        for position, wire in rows:
            leaf = Leaf.model_validate_json(wire)
            if position != len(leaves) or canonical(leaf) != wire:
                raise JournalBlocked("archive has missing or noncanonical bytes")
            leaves.append(leaf)
        return Snapshot(leaves=tuple(leaves))


class History:
    def __init__(self, snapshot, policy, head):
        if len(snapshot.leaves) != head.size:
            raise JournalBlocked("archive withheld required leaves")
        self.tree = make_tree(snapshot)
        if self.tree.root(head.size).hex() != head.root:
            raise JournalBlocked("archive root mismatch")
        self.events, self.identities = {}, {}
        self.withdrawals = ()
        self.withdrawal_floor = None
        for leaf in snapshot.leaves:
            record, identities, _ = policy.check_leaf(leaf, head.epoch)
            event = leaf.receipt.admission.event
            if event in self.events or any(identity in self.identities for identity in identities):
                raise JournalBlocked("archive contains a repeated or conflicting record")
            self.events[event] = (leaf, record)
            self.identities.update(dict.fromkeys(identities, event))

    def require_extension(self, older, head):
        if older is not None and older.size > head.size:
            raise JournalBlocked("checkpoint size rolled back")
        before = older.size if older else 0
        proof = tuple(node.hex() for node in self.tree.consistency(before, head.size))
        verify_extension(older, head, proof)


def make_tree(snapshot):
    tree = Tree()
    for leaf in snapshot.leaves:
        tree.append(canonical(leaf))
    return tree


def reconcile(archives, policy, head):
    for fetch in archives:
        try:
            return History(fetch(head.size), policy, head)
        except (JournalBlocked, ValueError, OSError, sqlite3.Error):
            continue
    raise JournalBlocked("no archive or mirror supplied complete verified history")


def receipt_coverage(policy, leaf, cut, index, proof, now):
    """Classify what the monitor has verified by its own observation time."""
    epoch = leaf.receipt.admission.epoch
    policy.check_leaf(leaf, epoch)
    deadline = policy.journal.cutoff(epoch) + policy.journal.merge_seconds
    if cut is not None:
        policy.journal.check_cut(cut)
        head = cut.head
        if head.epoch >= epoch and index is not None and verify_inclusion(
                canonical(leaf), index, head.size, bytes.fromhex(head.root), proof):
            return "included-late" if now >= deadline else "included"
    return "missing-proof" if now >= deadline else "pending"


class Witness:
    def __init__(self, name, key, policy, clock, path, pin, archives):
        if key.public_key() != policy.journal.operators[name]:
            raise ValueError("witness key does not match its pinned enrollment")
        self.name, self.key, self.policy, self.clock, self.archives = name, key, policy, clock, archives
        self.ledger = WitnessLedger(path, pin, bytes.fromhex(policy.context) + name.encode())
        self.intake, self.votes, self.pending, self.identities = {}, {}, {}, {}
        self.withdrawals = {}
        self.latest = None
        self.exhausted = False
        self.last_epoch = -1
        for operation in self.ledger.records:
            self._remember(operation)
        self.ledger.records.clear()

    def _remember(self, operation):
        record = json.loads(operation)
        if record["kind"] == "admit":
            admission = Admission.model_validate(record["admission"])
            wire = Wire.model_validate(record["wire"])
            event = admission.event
            self.last_epoch = max(self.last_epoch, admission.epoch)
            self.intake[event] = (wire, admission)
            self.votes[event, admission.epoch] = (wire, admission)
            self.pending.setdefault(event, (admission.epoch, record["withdrawal"]))
            if record["withdrawal"]:
                self.withdrawals.setdefault(event, admission.epoch)
            self.identities.update((tuple(identity), event) for identity in record["identities"])
        elif record["kind"] == "exhausted":
            self.exhausted = True
        else:
            self.latest = SignedHead.model_validate(record["head"])
            for event in record["covered"]:
                self.pending.pop(event, None)
            self.identities.update((tuple(identity), event) for identity, event in record["identities"])

    def _persist(self, record):
        operation = canonical(record)
        self.ledger.append(operation)
        self._remember(operation)

    def admit(self, wire, principal):
        with self.ledger.lock:
            self.ledger.ensure()
            now = self.clock.sample()
            width = self.policy.journal.epoch_seconds
            epoch = int(now.lower // width)
            if epoch != int(now.upper // width) or epoch < self.last_epoch:
                raise JournalBlocked("admission epoch uncertain or rolled back")
            record, identities, enrolled = self.policy.authenticate(wire, now.lower)
            self.policy.authenticate(wire, now.upper)
            if enrolled != principal:
                raise PermissionError("transport principal does not own the record key and role")
            event = digest(wire)
            previous = self.votes.get((event, epoch))
            if previous is None and event not in self.pending:
                previous = self.intake.get(event)
            if previous is not None:
                _, admission = previous
                return admission, vote(self.name, self.key, admission)
            if self.exhausted or (self.latest and epoch <= self.latest.head.epoch):
                raise JournalBlocked("intake held or epoch already sealed")
            if any(self.identities.get(identity, event) != event for identity in identities):
                raise JournalBlocked("admission would introduce a conflicting identity")
            withdrawal = is_withdrawal(record)
            capacity = MAX_RECORDS if withdrawal else MAX_ORDINARY
            if event not in self.intake and len(self.intake) >= capacity:
                if withdrawal:
                    self._persist({"kind": "exhausted"})
                raise JournalBlocked("intake capacity exceeded")
            admission = Admission(context=self.policy.context, epoch=epoch, event=event)
            self._persist({"kind": "admit", "admission": admission.model_dump(), "wire": wire.model_dump(),
                           "identities": identities, "withdrawal": withdrawal})
            return admission, vote(self.name, self.key, admission)

    def recover(self, event, epoch):
        with self.ledger.lock:
            self.ledger.ensure()
            if (event, epoch) not in self.votes:
                raise JournalBlocked("receipt unavailable from this witness")
            return self._receipt(event, epoch)

    def _receipt(self, event, epoch):
        wire, admission = self.votes[event, epoch]
        return Leaf(wire=wire, receipt={"admission": admission, "votes": (vote(self.name, self.key, admission),)})

    def seal(self, signed):
        with self.ledger.lock:
            self.ledger.ensure()
            self.policy.journal.check_head(signed)
            head = signed.head
            self.policy.journal.deadline(head, self.clock.sample())
            if signed != self.latest:
                history = reconcile(self.archives, self.policy, head)
                history.require_extension(self.latest.head if self.latest else None, head)
                if any(epoch <= head.epoch and event not in history.events
                       for event, (epoch, _) in self.pending.items()):
                    raise JournalBlocked("checkpoint omits a due independently admitted record")
                if any(self.identities.get(identity, event) != event
                       for identity, event in history.identities.items()):
                    raise JournalBlocked("checkpoint conflicts with witness intake")
                self.policy.journal.deadline(head, self.clock.sample())
                self._persist({"kind": "seal", "head": signed.model_dump(), "covered": list(history.events),
                               "identities": list(history.identities.items())})
            return vote(self.name, self.key, signed)

    def view(self, challenge):
        with self.ledger.lock:
            self.ledger.ensure()
            if self.exhausted or self.latest is None or any(withdrawal for _, withdrawal in self.pending.values()):
                raise JournalBlocked("checkpoint unavailable or awaiting an admitted withdrawal")
            self.policy.expiry(challenge, self.latest.head, self.clock.sample())
            return View(signed=self.latest, coverage=vote(self.name, self.key, self.latest),
                        signature=self.key.sign(message("view", view_binding(challenge, self.latest))).hex())


    def withdrawal_view(self, challenge):
        with self.ledger.lock:
            self.ledger.ensure()
            if self.policy.status_profile != "withdrawal-v2" or self.exhausted:
                raise JournalBlocked("withdrawal view unavailable")
            self.policy.challenge_deadline(challenge, self.clock.sample())
            leaves = tuple(self._receipt(event, epoch) for event, epoch in self.withdrawals.items())
            self.policy.challenge_deadline(challenge, self.clock.sample())
            signature = self.key.sign(message("withdrawal-view.v2", withdrawal_binding(challenge, self.name, leaves)))
            return WithdrawalView(witness=self.name, leaves=leaves, signature=signature.hex())
