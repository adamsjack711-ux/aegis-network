"""Independent intake, durable coverage witnesses, and an untrusted archive."""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from pydantic import TypeAdapter

from ..artifact import SignedEvent, event_id, event_payload, parse_event

from .merkle import EMPTY, Tree, verify_consistency, verify_inclusion
from .protocol import (Admission, Clock, Cut, Entry, Head, JournalBlocked, Leaf, Policy, Proof, Receipt,
                       SignedHead, Vote, canonical, digest, event_keys, sign_head, vote)
from .storage import Pin, WitnessLedger

PAGE_SIZE = 128
proof_wire = TypeAdapter(Proof)


class Archive:
    """Reference append log and mirror. Verifiers treat every response as untrusted."""

    def __init__(self, path: Path, policy: Policy):
        self.policy = policy
        self.db = sqlite3.connect(path)
        self.tree = Tree()
        self.events: dict[str, tuple[str, int]] = {}
        self.sequences = {}
        try:
            with self.db:
                self.db.execute("CREATE TABLE IF NOT EXISTS leaves (position INTEGER PRIMARY KEY, wire BLOB NOT NULL)")
            for index, wire in self.db.execute("SELECT position, wire FROM leaves ORDER BY position"):
                if index != self.tree.size:
                    raise JournalBlocked("archive is missing a leaf")
                leaf = Leaf.model_validate_json(wire)
                if wire != canonical(leaf):
                    raise JournalBlocked("archive leaf encoding is invalid")
                self._remember(leaf, wire)
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def _remember(self, leaf, wire):
        identity, sequence = event_keys(leaf)
        self.events[identity] = (leaf.receipt.admission.event, self.tree.size)
        self.sequences[sequence] = identity
        self.tree.append(wire)

    def append(self, leaf: Leaf) -> int:
        self.policy.check_leaf(leaf, leaf.receipt.admission.epoch)
        identity, sequence = event_keys(leaf)
        event = leaf.receipt.admission.event
        previous = self.events.get(identity)
        if previous is not None:
            if previous[0] != event:
                raise JournalBlocked("archive received conflicting event identity")
            return previous[1]
        if sequence in self.sequences:
            raise JournalBlocked("archive received conflicting publisher sequence")
        index = self.tree.size
        wire = canonical(leaf)
        with self.db:
            self.db.execute("INSERT INTO leaves VALUES (?, ?)", (index, wire))
        self._remember(leaf, wire)
        return index

    def propose(self, key, epoch: int) -> SignedHead:
        return sign_head(key, Head(context=self.policy.context, epoch=epoch, size=self.tree.size,
                                   root=self.tree.root(self.tree.size).hex()))

    def _check_head(self, head: Head):
        if head.context != self.policy.context or self.tree.root(head.size).hex() != head.root:
            raise JournalBlocked("archive does not contain the requested checkpoint")

    def consistency(self, before: int, head: Head):
        self._check_head(head)
        return tuple(node.hex() for node in self.tree.consistency(before, head.size))

    def page(self, head: Head, start: int, limit: int):
        self._check_head(head)
        if not 0 <= start <= head.size or not 1 <= limit <= PAGE_SIZE:
            raise JournalBlocked("archive page coordinates are invalid")
        stop = min(start + limit, head.size)
        rows = self.db.execute("SELECT position, wire FROM leaves WHERE position >= ? AND position < ? ORDER BY position",
                               (start, stop))
        return tuple(Entry(index=index, leaf=Leaf.model_validate_json(wire),
                           proof=tuple(node.hex() for node in self.tree.inclusion(index, head.size)))
                     for index, wire in rows)


def verify_extension(previous: Head | None, head: Head, proof) -> None:
    before, old_root = (previous.size, bytes.fromhex(previous.root)) if previous else (0, EMPTY)
    if previous and (head.epoch < previous.epoch or
                     (head.epoch == previous.epoch and head != previous)):
        raise JournalBlocked("checkpoint epoch rollback or conflict")
    if not verify_consistency(before, head.size, old_root, bytes.fromhex(head.root),
                              tuple(bytes.fromhex(node) for node in proof_wire.validate_python(proof))):
        raise JournalBlocked("checkpoint consistency proof failed")


def verify_page(policy, head, start, limit, entries):
    if len(entries) != min(limit, head.size - start):
        raise JournalBlocked("archive page omitted required indexes")
    for index, entry in enumerate(entries, start):
        wire = canonical(entry.leaf)
        if entry.index != index or not verify_inclusion(
                wire, index, head.size, bytes.fromhex(head.root),
                tuple(bytes.fromhex(node) for node in entry.proof)):
            raise JournalBlocked("archive inclusion proof or dense index failed")
        policy.check_leaf(entry.leaf, head.epoch)
        yield entry.leaf


class Witness:
    def __init__(self, name, key, policy: Policy, path: Path, pin: Pin, clock: Clock):
        if name not in policy.operators or key.public_key() != policy.operators[name]:
            raise ValueError("witness key is outside its pinned roster slot")
        self.name, self.key, self.policy, self.clock = name, key, policy, clock
        self.ledger = WitnessLedger(path, pin, bytes.fromhex(policy.context) + name.encode())
        self.voted = {}
        self.pending = {}
        self.intake = {}
        self.events = {}
        self.sequences = {}
        self.included = set()
        self.latest_admission = -1
        self.latest = None
        try:
            for wire in self.ledger.records:
                record = json.loads(wire)
                if record["kind"] == "admission":
                    self._remember_admission(Admission.model_validate(record["admission"]),
                                             record["identity"], tuple(record["sequence"]),
                                             canonical(record["envelope"]))
                else:
                    self._remember_cut(SignedHead.model_validate(record["signed"]), record["entries"])
            self.ledger.records.clear()
        except BaseException:
            self.close()
            raise

    def close(self):
        self.ledger.close()

    def _remember_admission(self, admission, identity, sequence, wire):
        self.latest_admission = max(self.latest_admission, admission.epoch)
        self.voted[admission.event, admission.epoch] = admission
        self.intake[admission.event] = wire
        self.events[identity] = admission.event
        self.sequences[sequence] = identity
        if admission.event not in self.included:
            self.pending.setdefault(admission.event, admission.epoch)

    def _remember_cut(self, signed, entries):
        for event, identity, sequence in entries:
            self.included.add(event)
            self.pending.pop(event, None)
            self.events[identity] = event
            self.sequences[tuple(sequence)] = identity
        self.latest = signed

    def admit(self, envelope: SignedEvent) -> tuple[Admission, Vote]:
        with self.ledger.lock:
            self.ledger.ensure()
            now = self.clock.sample()
            epoch = int(now.lower // self.policy.epoch_seconds)
            if epoch < 0 or epoch != int(now.upper // self.policy.epoch_seconds):
                raise JournalBlocked("admission time overlaps an epoch boundary")
            event = digest(envelope)
            previous = self.voted.get((event, epoch))
            if previous is not None:
                return previous, vote(self.name, self.key, previous)
            if (epoch < self.latest_admission or (self.latest and epoch <= self.latest.head.epoch)):
                raise JournalBlocked("cannot admit into a sealed epoch")
            payload = event_payload(envelope)
            bounds = [datetime.fromtimestamp(t, timezone.utc) for t in (now.lower, now.upper)]
            for when in bounds:
                self.policy.validate_event(envelope, when)
            grant = self.policy.trust.grants[(payload.publisher_id, envelope.key_id)]
            cutoff = datetime.fromtimestamp(self.policy.cutoff(epoch), timezone.utc)
            if grant.revoked_at is not None and grant.revoked_at < cutoff:
                raise JournalBlocked("compromise overlaps admission epoch")
            identity, sequence = event_id(envelope), (payload.publisher_id, payload.sequence)
            if (self.events.get(identity, event) != event
                    or self.sequences.get(sequence, identity) != identity):
                raise JournalBlocked("conflicting journal event identity or publisher sequence")
            admission = Admission(context=self.policy.context, epoch=epoch, event=event)
            self.ledger.append(canonical({"kind": "admission", "admission": admission.model_dump(),
                                          "identity": identity, "sequence": sequence,
                                          "envelope": envelope.model_dump(mode="json")}))
            self._remember_admission(admission, identity, sequence, canonical(envelope))
            return admission, vote(self.name, self.key, admission)

    def admitted(self, event: str, epoch: int):
        """Recover exact signed bytes and a previously issued vote after an outage."""
        with self.ledger.lock:
            self.ledger.ensure()
            admission = self.voted.get((event, epoch))
            if admission is None:
                return None
            return parse_event(self.intake[event]), admission, vote(self.name, self.key, admission)

    def cosign(self, signed: SignedHead, archive: Archive) -> Vote:
        with self.ledger.lock:
            self.ledger.ensure()
            self.policy.check_head(signed)
            head = signed.head
            self.policy.deadline(head, self.clock.sample())
            if signed == self.latest:
                return vote(self.name, self.key, signed)
            previous = self.latest.head if self.latest else None
            start = previous.size if previous else 0
            verify_extension(previous, head, archive.consistency(start, head))
            events, sequences, covered, records = set(), set(), set(), []
            for offset in range(start, head.size, PAGE_SIZE):
                entries = archive.page(head, offset, PAGE_SIZE)
                for leaf in verify_page(self.policy, head, offset, PAGE_SIZE, entries):
                    event = leaf.receipt.admission.event
                    identity, sequence = event_keys(leaf)
                    if (identity in events or sequence in sequences or event in self.included
                            or self.events.get(identity, event) != event
                            or self.sequences.get(sequence, identity) != identity):
                        raise JournalBlocked("witness found a conflicting or duplicate leaf")
                    events.add(identity)
                    sequences.add(sequence)
                    covered.add(event)
                    records.append([event, identity, sequence])
            if any(epoch <= head.epoch and event not in covered for event, epoch in self.pending.items()):
                raise JournalBlocked("checkpoint omits a due independently admitted event")
            self.policy.deadline(head, self.clock.sample())
            self.ledger.append(canonical({"kind": "cut", "signed": signed.model_dump(), "entries": records}))
            self._remember_cut(signed, records)
            return vote(self.name, self.key, signed)

    def published(self):
        with self.ledger.lock:
            self.ledger.ensure()
            if self.latest is not None:
                return self.latest, vote(self.name, self.key, self.latest)


def collect_receipt(policy: Policy, responses) -> Receipt:
    matches = {}
    for admission, signature in responses:
        matches.setdefault(admission, []).append(signature)
    for admission, votes in sorted(matches.items(), key=lambda item: item[0].epoch, reverse=True):
        if admission.context != policy.context or len(votes) < policy.quorum:
            continue
        valid = policy.valid_votes(admission, votes)
        if len(valid) >= policy.quorum:
            return Receipt(admission=admission, votes=valid)
    raise JournalBlocked("no independent admission quorum agreed on an epoch")


def choose_cut(policy: Policy, responses) -> Cut:
    groups = {}
    for signed, signature in responses:
        groups.setdefault(signed, []).append(signature)
    for signed, votes in sorted(groups.items(), key=lambda item: item[0].head.epoch, reverse=True):
        if len(votes) < policy.quorum:
            continue
        try:
            policy.check_head(signed)
        except JournalBlocked:
            continue
        valid = policy.valid_votes(signed, votes)
        if len(valid) >= policy.quorum:
            return Cut(signed=signed, votes=valid)
    raise JournalBlocked("independent checkpoints have no available quorum")


class WitnessHeads:
    """Reference independent checkpoint source. No coordinator 'latest' call."""

    def __init__(self, policy, witnesses):
        self.policy, self.witnesses = policy, tuple(witnesses)

    async def latest(self) -> Cut:
        responses = []
        for witness in self.witnesses:
            try:
                response = witness.published()
            except (JournalBlocked, OSError, sqlite3.Error):
                continue
            if response is not None:
                responses.append(response)
        return choose_cut(self.policy, responses)
