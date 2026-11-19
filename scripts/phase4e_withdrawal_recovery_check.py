"""Independently check withdrawal ordering and durable audit recovery in a local lab."""

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import sys
import tempfile
from types import SimpleNamespace
from uuid import uuid4

import httpx


async def check(bench, directory, env, ordinary_count, kill_agent, priority):
    from aegis.artifact import event_id, event_payload, parse_event, sign_revocation
    if priority:
        from aegis.mesh import CRITICAL_STREAM

    class Lab(bench.Lab):
        def prepare_keys(self):
            super().prepare_keys()
            trust = json.loads(self.trust_path.read_text())
            mixed = next(grant for grant in trust["grants"] if grant["publisher_id"] == self.publishers[1])
            mixed["roles"] = ["finding", "revocation"]
            mixed["revocation_publishers"] = [self.publishers[0]]
            self.trust_path.write_text(json.dumps(trust))
            self.mixed_key_id = mixed["key_id"]

    lab = Lab(SimpleNamespace(coordinators=1, sample_interval=0.5, timeout=90), directory, env)
    agent_id = str(uuid4())
    async with httpx.AsyncClient(trust_env=False, timeout=10) as client:
        try:
            await lab.start_services(client)
            worker, log = lab.fleet.start(agent_id, index=2)
            await lab.wait(lambda: any(row["kind"] == "ready" for row in log.rows), "agent startup")
            publisher, mixed = lab.publishers[:2]
            targets = [lab.make_finding(publisher, sequence) for sequence in (1, 2)]
            for target in targets:
                await lab.post(client, target, "preexisting")
            await lab.wait_acks(list(lab.events))
            ordinary_stream = await lab.js.stream_info(bench.STREAM)
            heads = {bench.STREAM: ordinary_stream.state.last_seq}
            if priority:
                heads[CRITICAL_STREAM] = (await lab.js.stream_info(CRITICAL_STREAM)).state.last_seq
                capacity = await lab.js.stream_info(bench.STREAM)
                capacity.config.max_bytes = ordinary_stream.state.bytes
                await lab.js.update_stream(capacity.config)

            await asyncio.to_thread(lab.compose, "stop", "-t", "0", "nats")
            ordinary = []
            for sequence in range(3, ordinary_count + 3):
                ordinary.append(await lab.post(client, lab.make_finding(publisher, sequence), "ordinary"))
            earlier = await lab.post(client, lab.make_finding(mixed, 1), "mixed-earlier")
            withdraw = await lab.post(client, bench.revocation(lab.revoker, targets[0], 1), "withdrawal")
            other = bench.revocation(lab.publisher, targets[1], 2).revocation
            mixed_revoke = sign_revocation(other.model_copy(update={"publisher_id": mixed}),
                                           lab.publisher, lab.mixed_key_id)
            mixed_withdraw = await lab.post(client, mixed_revoke, "mixed-withdrawal")
            later = await lab.post(client, lab.make_finding(mixed, 3), "mixed-later")
            queued = set(ordinary) | {earlier, withdraw, mixed_withdraw, later}

            rows = await asyncio.to_thread(lab.outbox_rows)
            assert [row["event_id"] for row in rows] == [*map(event_id, targets), *ordinary, earlier,
                                                       withdraw, mixed_withdraw, later]
            assert {row["event_id"] for row in rows if row["sent_at"] is None} == queued
            if kill_agent:
                lab.fleet.signal(agent_id, signal.SIGKILL)
                await asyncio.to_thread(worker.wait, 10)
                lab.fleet.processes.pop(agent_id)
            restart_requested_ns = bench.now()
            await asyncio.to_thread(lab.compose, "start", "nats")
            if kill_agent:
                worker, _ = lab.fleet.start(agent_id, index=2)
            isolation = None
            if priority:
                await lab.wait_acks([withdraw, mixed_withdraw])
                still_pending = {row["event_id"] for row in await asyncio.to_thread(lab.outbox_rows)
                                 if row["sent_at"] is None}
                normal_head = (await lab.js.stream_info(bench.STREAM)).state.last_seq
                _, _, negative, _, _, _ = bench.read_audit(directory / agent_id / "audit.db")
                assert normal_head == heads[bench.STREAM]
                assert still_pending >= set(ordinary) | {earlier, later}
                assert negative == {(event_id(target),) for target in targets}
                isolation = {"normal_stream_head_while_critical_acked": normal_head,
                             "ordinary_outbox_rows_still_pending": len(still_pending - {withdraw, mixed_withdraw}),
                             "critical_ack_count": 2, "durable_effective_denial_count": len(negative)}
                await lab.js.update_stream(ordinary_stream.config)
            await lab.wait_acks(list(queued))

            order = []
            for stream, head in heads.items():
                end = (await lab.js.stream_info(stream)).state.last_seq
                for sequence in range(head + 1, end + 1):
                    message = await lab.js.get_msg(stream, seq=sequence)
                    event = parse_event(message.data)
                    order.append({"stream": stream, "stream_sequence": sequence, "event_id": event_id(event),
                                  "kind": event.kind, "publisher": event_payload(event).publisher_id,
                                  "publisher_sequence": event_payload(event).sequence})

            # Check the earliest delivery for every logical envelope. Keep all
            # stream records so physical redelivery remains observable.
            first = {}
            for row in order:
                first.setdefault(row["event_id"], (row["stream"], row["stream_sequence"]))
            assert set(first) == queued
            assert [first[eid] for eid in ordinary] == sorted(first[eid] for eid in ordinary)
            assert first[earlier] < first[later]
            if priority:
                assert {first[withdraw][0], first[mixed_withdraw][0]} == {CRITICAL_STREAM}
                assert {first[eid][0] for eid in [*ordinary, earlier, later]} == {bench.STREAM}
            else:
                assert first[earlier] < first[mixed_withdraw] < first[later]
            async with asyncio.timeout(10):
                while True:
                    after = await asyncio.to_thread(lab.outbox_rows)
                    if all(row["sent_at"] is not None for row in after):
                        break
                    await asyncio.sleep(0.05)
            assert [(r["position"], r["event_id"]) for r in after] == [
                (r["position"], r["event_id"]) for r in rows
            ]

            records, revocations, effective, rejected, owner, cursor = bench.read_audit(directory / agent_id / "audit.db")
            findings = {eid for eid, row in lab.events.items() if row["kind"] == "finding"}
            assert owner == agent_id
            assert not rejected
            assert len(records) == len(findings)
            assert {row[0] for row in records} == findings
            assert all(row[2:] == ("EXACT_MATCH_ALLOWED", 1, 1) for row in records)
            assert len(revocations) == 2
            assert {row[0] for row in revocations} == {withdraw, mixed_withdraw}
            assert all(row[3:] == ("REVOCATION_ACCEPTED", 1) for row in revocations)
            assert effective == {(event_id(target),) for target in targets}

            def timing(eid):
                started = lab.events[eid]["start"]
                committed = lab.fleet.commits[eid][agent_id]["ns"]
                acked = lab.fleet.acks[eid][agent_id]["acked"]
                assert started <= committed <= acked
                return {"submit_to_durable_audit_ms": bench.ms(started, committed),
                        "submit_to_confirmed_ack_ms": bench.ms(started, acked),
                        "restart_request_to_durable_audit_ms": bench.ms(restart_requested_ns, committed),
                        "restart_request_to_confirmed_ack_ms": bench.ms(restart_requested_ns, acked)}

            return {
                "source": bench.git_identity(),
                "oracle_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "postgres_source_sha256": hashlib.sha256((bench.ROOT / "src/aegis/postgres.py").read_bytes()).hexdigest(),
                "platform": platform.platform(),
                "python": platform.python_version(),
                "docker_image_ids": lab.images,
                "scope": "one host, one broker, one database, one dry-run agent",
                "profile": "priority" if priority else "legacy",
                "agent_sigkill": kill_agent,
                "ordinary_enqueued": ordinary_count,
                "ordinary_findings_ahead_of_independent_withdrawal": (
                    None if priority else sum(first[eid] < first[withdraw] for eid in ordinary)
                ),
                "ordinary_capacity_isolation": isolation,
                "all_logical_broker_acks": len(queued),
                "effective_denials_from_read_only_sqlite": sorted(row[0] for row in effective),
                "legacy_replay_cursor_at_readback": cursor,
                "queued_journal_order": rows,
                "broker_order_after_restart": order,
                "independent_withdrawal_id": withdraw,
                "mixed_withdrawal_id": mixed_withdraw,
                "independent_withdrawal_ms": timing(withdraw),
                "mixed_withdrawal_ms": timing(mixed_withdraw),
            }
        finally:
            await lab.stop()
            if lab.failures:
                raise RuntimeError("; ".join(lab.failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    parser.add_argument("--authorize-local-lab", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ordinary-count", type=int, default=4)
    parser.add_argument("--kill-agent", action="store_true")
    parser.add_argument("--priority", action="store_true", help="exercise the opt-in separate priority stream")
    args = parser.parse_args()
    if not 1 <= args.ordinary_count <= 200:
        parser.error("--ordinary-count must be between 1 and 200")
    checkout = args.checkout.resolve()
    if args.priority:
        os.environ["AEGIS_PHASE4E_PRIORITY"] = "1"
    else:
        os.environ.pop("AEGIS_PHASE4E_PRIORITY", None)
    sys.path[:0] = [str(checkout / "src"), str(checkout / "scripts")]
    import phase4a_bench as bench

    with tempfile.TemporaryDirectory(prefix="a4e-withdrawal-", dir="/tmp") as directory, bench.local_docker() as env:
        result = asyncio.run(check(bench, Path(directory), env, args.ordinary_count, args.kill_agent, args.priority))
    bench.write_json(args.output, result)


if __name__ == "__main__":
    sys.exit(main())
