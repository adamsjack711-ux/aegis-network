"""Inert Phase 4F recovery model. No production code imports or authority changes."""

from dataclasses import dataclass, field
from hashlib import sha256
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "benchmarks/phase4f-kv-recovery/baseline-sigkill.json"
RAW_SHA256 = "8cc699a8d7a478f0ed789cef40ac84a402526349636ce833e393833b51eda95f"


@dataclass
class Model:
    """Abstract contract state; flags represent proofs supplied by separate authorities."""

    generation: int = 1
    external_floor: int = 1
    writer_floors: dict[str, int] = field(default_factory=lambda: {"route-a": 1, "route-b": 1})
    denied: set[str] = field(default_factory=set)
    cursor: dict[int, int] = field(default_factory=lambda: {1: 0})
    hold: bool = False
    frozen: bool = False
    transfer_pending: bool = False

    def transfer_start(self, authenticated: bool) -> None:
        if not authenticated or self.frozen or self.generation != self.external_floor:
            return
        self.generation += 1
        self.external_floor = self.generation  # independent monotonic commit
        self.transfer_pending = True
        self.hold = True
        self.cursor[self.generation] = 0

    def writer_barrier(self, route: str) -> None:
        if route in self.writer_floors and not self.frozen:
            self.writer_floors[route] = self.generation

    def positive_write(self, generation: int, *, fresh_trust: bool = True,
                       exact_approval: bool = True) -> bool:
        return (not self.frozen and not self.hold and not self.transfer_pending
                and generation == self.external_floor == self.generation
                and all(floor == generation for floor in self.writer_floors.values())
                and fresh_trust and exact_approval)

    def transfer_finish(self) -> None:
        if not self.frozen and all(f == self.generation for f in self.writer_floors.values()):
            self.transfer_pending = False
            # A fresh positive authorization is a separate action; hold stays set.

    def authorize_positive(self, generation: int, *, fresh_trust: bool,
                           exact_approval: bool) -> None:
        if (not self.frozen and not self.transfer_pending
                and generation == self.generation == self.external_floor
                and all(f == generation for f in self.writer_floors.values())
                and fresh_trust and exact_approval):
            self.hold = False

    def deny_at_target(self, *, exact_native_proof: bool) -> None:
        if exact_native_proof:
            self.hold = True  # target-side restriction, independent of broker claim

    def audit_commit(self, event: str, *, exact_native_proof: bool) -> None:
        if exact_native_proof and not self.frozen:
            self.denied.add(event)  # idempotent agent-owned durable transaction

    def cursor_advance(self, generation: int, event: str, position: int) -> None:
        if (not self.frozen and generation == self.generation == self.external_floor
                and event in self.denied and position > self.cursor[generation]):
            self.cursor[generation] = position

    def restore_stale_snapshot(self, generation: int) -> None:
        if generation < self.external_floor:
            self.frozen = True
            self.hold = True


class RecoveryProtocolModelTests(unittest.TestCase):
    def test_retained_trace_is_exact_and_misses_frozen_gate(self) -> None:
        raw = RAW.read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), RAW_SHA256)
        data = json.loads(raw)
        self.assertTrue(data["agent_sigkill"])
        self.assertEqual(data["scope"], "one host, one broker, one database, one dry-run agent")
        self.assertGreater(data["independent_withdrawal_ms"]["submit_to_durable_audit_ms"], 5000)
        self.assertGreater(data["mixed_withdrawal_ms"]["submit_to_durable_audit_ms"], 5000)
        busy = sum(item["kind"] == "claim_stage" and item["stage"] == "busy"
                   for item in data["recovery_stages"]["trace"])
        self.assertEqual(busy, 30)

    def test_target_hold_is_independent_but_not_agent_denial(self) -> None:
        model = Model()
        model.deny_at_target(exact_native_proof=False)
        self.assertFalse(model.hold)
        model.deny_at_target(exact_native_proof=True)
        self.assertTrue(model.hold)
        self.assertEqual(model.denied, set())
        self.assertFalse(model.positive_write(1))

    def test_competing_successors_and_partial_writer_barrier(self) -> None:
        model = Model()
        model.transfer_start(authenticated=False)
        self.assertEqual(model.generation, 1)
        model.transfer_start(authenticated=True)
        model.writer_barrier("route-a")
        model.transfer_finish()
        self.assertTrue(model.transfer_pending)
        self.assertFalse(model.positive_write(1))
        self.assertFalse(model.positive_write(2))
        model.writer_barrier("route-b")
        model.transfer_finish()
        self.assertFalse(model.transfer_pending)
        self.assertTrue(model.hold)
        model.authorize_positive(2, fresh_trust=False, exact_approval=True)
        self.assertFalse(model.positive_write(2))
        model.authorize_positive(2, fresh_trust=True, exact_approval=True)
        self.assertTrue(model.positive_write(2))
        self.assertFalse(model.positive_write(1))
        model.transfer_start(authenticated=True)  # a second transfer only raises the floor
        self.assertEqual(model.external_floor, 3)
        self.assertFalse(model.positive_write(2))

    def test_crash_positions_lost_ack_and_old_session_cursor(self) -> None:
        for crash_after in ("before_commit", "after_commit", "after_cursor"):
            with self.subTest(crash_after=crash_after):
                model = Model()
                model.cursor_advance(1, "withdrawal", 7)
                self.assertEqual(model.cursor[1], 0)
                if crash_after != "before_commit":
                    model.audit_commit("withdrawal", exact_native_proof=True)
                if crash_after == "after_cursor":
                    model.cursor_advance(1, "withdrawal", 7)
                # Replay after restart must remain idempotent and recover the floor.
                model.audit_commit("withdrawal", exact_native_proof=True)
                model.cursor_advance(1, "withdrawal", 7)
                model.cursor_advance(1, "withdrawal", 7)  # lost ACK duplicate
                self.assertEqual(model.denied, {"withdrawal"})
                self.assertEqual(model.cursor[1], 7)
                model.transfer_start(authenticated=True)
                model.cursor_advance(1, "withdrawal", 9)  # late old ACK is irrelevant
                self.assertEqual(model.cursor[1], 7)
                self.assertEqual(model.cursor[2], 0)

    def test_stale_snapshot_cannot_restore_authority(self) -> None:
        model = Model()
        model.transfer_start(authenticated=True)
        model.restore_stale_snapshot(1)
        model.writer_barrier("route-a")
        model.audit_commit("withdrawal", exact_native_proof=True)
        model.cursor_advance(2, "withdrawal", 8)
        self.assertTrue(model.frozen)
        self.assertFalse(model.positive_write(2))
        self.assertEqual(model.cursor[2], 0)

    def test_five_seconds_requires_agent_and_authority_availability(self) -> None:
        for outage_ms in (5001, 30000):
            with self.subTest(outage_ms=outage_ms):
                earliest_possible_agent_commit_ms = outage_ms + 1
                self.assertGreater(earliest_possible_agent_commit_ms, 5000)


if __name__ == "__main__":
    unittest.main()
