"""Offline reconciliation against independent checkpoint and archive sources."""

import asyncio
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Protocol

from ..artifact import SignedFinding, SignedRevocation, StrictModel, canonical_bytes
from .merkle import Tree
from .protocol import Clock, Cut, Entry, Head, JournalBlocked, Leaf, Policy, Proof, canonical, digest, event_keys
from .storage import Pin
from .witness import PAGE_SIZE, verify_extension, verify_page

UNINITIALIZED = b"aegis-journal-v1/genesis"


class HeadSource(Protocol):
    async def latest(self) -> Cut: ...


class ProofSource(Protocol):
    async def consistency(self, before: int, head: Head) -> Proof: ...
    async def page(self, head: Head, start: int, limit: int) -> tuple[Entry, ...]: ...


class ArchiveSource:
    """In-process adapter. A remote implementation authenticates and bounds requests."""

    def __init__(self, archive):
        self.archive = archive

    async def consistency(self, before, head):
        return self.archive.consistency(before, head)

    async def page(self, head, start, limit):
        return self.archive.page(head, start, limit)


@dataclass
class Replay:
    head: Head | None = None
    findings: set[str] = field(default_factory=set)
    denials: set[tuple[str, str, str]] = field(default_factory=set)
    identities: set[str] = field(default_factory=set)
    sequences: set[tuple[str, int]] = field(default_factory=set)

    def copy(self):
        return Replay(self.head, self.findings.copy(), self.denials.copy(),
                      self.identities.copy(), self.sequences.copy())

    def apply(self, leaf: Leaf):
        identity, sequence = event_keys(leaf)
        if identity in self.identities or sequence in self.sequences:
            raise JournalBlocked("replay contains a conflicting or duplicate event")
        self.identities.add(identity)
        self.sequences.add(sequence)
        envelope = leaf.envelope
        if isinstance(envelope, SignedRevocation):
            event = envelope.revocation
            self.denials.add((event.target_publisher_id, str(event.target_artifact_id), event.target_sha256))
        else:
            self.findings.add(leaf.receipt.admission.event)


def finding_target(envelope: SignedFinding) -> tuple[str, str, str]:
    finding = envelope.finding
    return finding.publisher_id, str(finding.artifact_id), sha256(canonical_bytes(finding)).hexdigest()


class ProtectedHead(StrictModel, frozen=True):
    """An observed newer cut blocks rollback while its continuity is unresolved."""

    verified: Head | None = None
    pending: Head | None = None


class AgentCache:
    """Journal cursor and replay effects are represented by one verified leaf prefix."""

    def __init__(self, path: Path, policy: Policy):
        self.path, self.policy = path, policy

    def load(self) -> Replay:
        if not self.path.exists():
            return Replay()
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute("SELECT wire FROM checkpoint WHERE slot = 1").fetchone()
            head = Head.model_validate_json(row[0])
            if head.context != self.policy.context:
                raise JournalBlocked("cached checkpoint is outside the pinned history")
            tree, replay = Tree(), Replay(head)
            for index, wire in db.execute("SELECT position, wire FROM leaves ORDER BY position"):
                leaf = Leaf.model_validate_json(wire)
                if index != tree.size or wire != canonical(leaf):
                    raise JournalBlocked("agent cache has a gap or malformed leaf")
                self.policy.check_leaf(leaf, head.epoch)
                tree.append(wire)
                replay.apply(leaf)
            if tree.size != head.size or tree.root(tree.size).hex() != head.root:
                raise JournalBlocked("cached leaves do not match their checkpoint")
            return replay

    def save(self, previous: Head | None, head: Head, wires: list[bytes]):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS checkpoint (slot INTEGER PRIMARY KEY CHECK (slot = 1), wire BLOB NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS leaves (position INTEGER PRIMARY KEY, wire BLOB NOT NULL)")
            if previous is None:
                db.execute("DELETE FROM leaves")
                start = 0
            else:
                current = db.execute("SELECT wire FROM checkpoint WHERE slot = 1").fetchone()
                if current != (canonical(previous),):
                    raise JournalBlocked("cached checkpoint changed during replay")
                start = previous.size
            db.executemany("INSERT INTO leaves VALUES (?, ?)", enumerate(wires, start))
            db.execute("INSERT OR REPLACE INTO checkpoint VALUES (1, ?)", (canonical(head),))


class JournalClient:
    def __init__(self, policy: Policy, heads: HeadSource, archives: tuple[ProofSource, ...],
                 pin: Pin, cache: Path, clock: Clock):
        self.policy, self.heads, self.archives, self.pin, self.clock = policy, heads, archives, pin, clock
        self.cache = AgentCache(cache, policy)
        self._refresh_lock = asyncio.Lock()
        self._lock = RLock()
        self._usable: tuple[str, float] | None = None
        self._last_deadline: tuple[Head, float] | None = None
        self.replay = Replay()

    @staticmethod
    def _blocked(exc):
        return JournalBlocked(f"witnessed journal unavailable: {exc}")

    async def _extension(self, before, head):
        if before is None or before.size == head.size:
            verify_extension(before, head, ())
            return
        if before.size > head.size or before.epoch > head.epoch:
            raise JournalBlocked("checkpoint rolls back the protected anchor")
        for source in self.archives:
            try:
                proof = await source.consistency(before.size, head)
                verify_extension(before, head, proof)
                return
            except Exception:
                continue
        raise JournalBlocked("no archive supplied a valid consistency proof")

    async def refresh(self) -> tuple[str, float]:
        async with self._refresh_lock:
            try:
                return await self._refresh()
            except asyncio.CancelledError:
                self.invalidate()
                raise
            except Exception as exc:
                self.invalidate()
                raise self._blocked(exc) from exc

    def invalidate(self) -> None:
        with self._lock:
            self._usable = None

    def _advance(self, pin: bytes, state: ProtectedHead) -> bytes:
        updated = canonical(state)
        with self._lock:
            self._usable = None
            self.pin.advance(pin, updated)
        return updated

    @staticmethod
    def _check_coordinates(previous, head):
        if previous is None:
            return
        if head.epoch < previous.epoch or head.size < previous.size:
            raise JournalBlocked("checkpoint rolls back the protected anchor")
        if ((head.epoch == previous.epoch and head != previous)
                or (head.size == previous.size and head.root != previous.root)):
            raise JournalBlocked("checkpoint conflicts with the protected anchor")

    async def _refresh(self) -> tuple[str, float]:
        pin = self.pin.read()
        anchor = ProtectedHead() if pin == UNINITIALIZED else ProtectedHead.model_validate_json(pin)
        if (pin != UNINITIALIZED and
                (pin != canonical(anchor) or any(head.context != self.policy.context
                 for head in (anchor.pending, anchor.verified) if head is not None))):
            raise JournalBlocked("agent pin is outside the pinned history")
        cut = await self.heads.latest()
        self.policy.check_cut(cut)
        head = cut.head
        deadline = self.policy.deadline(head, self.clock.sample())
        previous = anchor.verified
        self._check_coordinates(anchor.pending or previous, head)
        if anchor.pending is not None:
            await self._extension(previous, anchor.pending)
            previous = anchor.pending
            pin = self._advance(pin, ProtectedHead(verified=previous))
        if previous != head:
            # Persist an unresolved cut before requesting consistency or pages.
            pin = self._advance(pin, ProtectedHead(verified=previous, pending=head))
            await self._extension(previous, head)
            pin = self._advance(pin, ProtectedHead(verified=head))

        if self.replay.head is None:
            try:
                cached = self.cache.load()
            except (sqlite3.Error, ValueError, TypeError, JournalBlocked):
                cached = Replay()
        else:
            cached = self.replay

        # An authenticated prefix can be reused after failover. A corrupt or
        # unrelated cache can only be replaced by a complete verified replay.
        if cached.head != previous:
            try:
                await self._extension(cached.head, head)
            except JournalBlocked:
                cached = Replay()

        if cached.head == head:
            replay, wires = cached, []
        else:
            replay, wires = await self._replay(cached, head)
            self.cache.save(cached.head, head, wires)

        deadline = min(deadline, self.policy.deadline(head, self.clock.sample()))
        with self._lock:
            if self.pin.read() != pin:
                raise JournalBlocked("agent pin changed before journal promotion")
            if self._last_deadline is not None and self._last_deadline[0] == head:
                deadline = min(deadline, self._last_deadline[1])
            if self.clock.monotonic() >= deadline:
                raise JournalBlocked("checkpoint expired during replay")
            self.replay = replay
            self._last_deadline = (head, deadline)
            self._usable = (digest(head), deadline)
            return self._usable

    async def _replay(self, cached, head):
        replay, wires = cached.copy(), []
        start = cached.head.size if cached.head else 0
        for position in range(start, head.size, PAGE_SIZE):
            for source in self.archives:
                try:
                    entries = await source.page(head, position, PAGE_SIZE)
                    leaves = tuple(verify_page(self.policy, head, position, PAGE_SIZE, entries))
                except Exception:
                    continue
                break
            else:
                raise JournalBlocked("no archive supplied a complete verified page")
            for leaf in leaves:
                replay.apply(leaf)
                wires.append(canonical(leaf))
        replay.head = head
        return replay, wires

    def current(self, envelope: SignedFinding, binding: str) -> bool:
        # One reference read for the proxy, which holds a target transaction.
        usable = self._usable
        if usable is None or usable[0] != binding:
            return False
        try:
            now = self.clock.sample()
            self.policy.deadline(self.replay.head, now)
        except Exception:
            return False
        return (now.monotonic < usable[1] and digest(envelope) in self.replay.findings
                and finding_target(envelope) not in self.replay.denials)

    @contextmanager
    def authorize(self, envelope: SignedFinding, binding: str):
        with self._lock:
            if not self.current(envelope, binding):
                raise JournalBlocked("finding has no current, complete and unwithdrawn journal status")
            yield
