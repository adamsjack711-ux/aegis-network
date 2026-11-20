"""An independent dry-run deployment using the regular agent consumer loop."""

import argparse
import asyncio
from dataclasses import asdict
import ctypes
import json
import logging
import os
from pathlib import Path
import resource
import signal
import sys
import time

import httpx
import nats

from aegis.agent_runtime import consume, durable_name
from aegis.config import load_local
from aegis.core import LocalAgent
from aegis.identity import IdentityInUse, IdentityLease, renew_lease
from aegis.mesh import CRITICAL_SUBJECT, priority_enabled
from aegis.storage import SqliteAudit


def report(kind, **fields):
    print(json.dumps(dict(kind=kind, ns=time.perf_counter_ns(), **fields),
                     separators=(",", ":")), flush=True)


def resources():
    usage = resource.getrusage(resource.RUSAGE_SELF)
    rss_bytes = usage.ru_maxrss if sys.platform == "darwin" else usage.ru_maxrss * 1024
    return dict(cpu_s=usage.ru_utime + usage.ru_stime, peak_rss_bytes=rss_bytes,
                memory_charge_bytes=memory_charge(rss_bytes))


def memory_charge(fallback):
    if sys.platform == "darwin":
        # Darwin's rusage_info_v0 starts with 16 UUID bytes then ten uint64s.
        # ri_phys_footprint follows ri_resident_size, at offset 72.
        usage = (ctypes.c_uint64 * 12)()
        libproc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        if libproc.proc_pid_rusage(os.getpid(), 0, ctypes.byref(usage)) == 0:
            return usage[9]
    elif sys.platform == "linux":
        try:
            for line in Path("/proc/self/smaps_rollup").read_text().splitlines():
                if line.startswith("Pss:"):
                    return int(line.split()[1]) * 1024
        except OSError:
            pass
    return fallback


def timed_audit_write(method):
    def write(self, *args, **kwargs):
        start = time.perf_counter_ns()
        changes = self.db.total_changes
        result = method(self, *args, **kwargs)
        if self.db.total_changes != changes:
            decision = next((arg for arg in args if hasattr(arg, "event_id")), None)
            report("audit", operation=method.__name__, start=start,
                   decision=asdict(decision) if decision is not None else None)
        return result
    return write


class MeasuredAudit(SqliteAudit):
    record = timed_audit_write(SqliteAudit.record)
    record_revocation = timed_audit_write(SqliteAudit.record_revocation)
    record_override = timed_audit_write(SqliteAudit.record_override)

    def advance_journal(self, position, *, critical=False):
        before = self.journal_position(critical=critical)
        start = time.perf_counter_ns()
        super().advance_journal(position, critical=critical)
        report("cursor_advance", lane="critical" if critical else "ordinary",
               before=before, after=self.journal_position(critical=critical), start=start)


async def run(args):
    report("process_started", pid=os.getpid())
    async def disconnected():
        report("disconnected")

    async def reconnected():
        report("reconnected")

    async def error(exc):
        logging.warning("NATS client error: %s", type(exc).__name__)

    connection = await nats.connect(f"nats://127.0.0.1:{args.broker_port}",
                                    name=f"phase4a-{args.id}", error_cb=error,
                                    disconnected_cb=disconnected, reconnected_cb=reconnected)
    report("broker_connected")
    js = connection.jetstream()
    start = time.perf_counter_ns()
    def claim_stage(stage, ns, revision):
        report("claim_stage", stage=stage, stage_ns=ns, revision=revision)
    try:
        try:
            lease = await IdentityLease.claim(js, args.id, wait_seconds=args.claim_timeout,
                                              on_attempt=claim_stage)
        except IdentityInUse:
            report("identity_in_use", start=start, pid=os.getpid())
            return 3
        report("claimed", start=start, pid=os.getpid(), revision=lease.revision)
        renew = asyncio.create_task(renew_lease(lease))
        audit = None
        try:
            policy, inventory = load_local(args.config)
            audit = MeasuredAudit(args.audit, args.id)
            agent = LocalAgent(policy, inventory, audit)
            ready = False

            def reconciled(count, begin, end):
                nonlocal ready
                report("reconcile", events=count, start=begin, end=end,
                       cursor=audit.journal_position())
                if not ready:
                    report("ready", pid=os.getpid(), **resources())
                    ready = True

            async def before_message(message):
                await asyncio.sleep(args.delay)
                report("attempt", sequence=message.metadata.sequence.stream,
                       delivery=message.metadata.num_delivered)

            def critical_committed(message, decision, received, committed):
                report("withdrawal_commit", decision=asdict(decision), received=received,
                       committed=committed)
                if args.stop_before_withdrawal_ack:
                    os.kill(os.getpid(), signal.SIGSTOP)

            def critical_stage(stage, ns, detail):
                report("critical_stage", stage=stage, stage_ns=ns, detail=detail)

            def acked(message, decision, received, leased, committed, ack):
                metadata = message.metadata
                report("ack", lane="withdrawal" if message.subject == CRITICAL_SUBJECT else "ordinary", decision=asdict(decision), received=received, leased=leased,
                       committed=committed, acked=ack, sequence=metadata.sequence.stream,
                       delivery=metadata.num_delivered,
                       broker_timestamp=metadata.timestamp.isoformat())

            async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{args.coordinator_port}",
                                         trust_env=False, timeout=10) as client:
                await consume(agent, audit, js, lease, renew, client, durable_name(args.id),
                              before_message=before_message if args.delay else None,
                              on_reconcile=reconciled, on_ack=acked, priority=priority_enabled(),
                              on_critical_commit=critical_committed,
                              on_critical_stage=critical_stage)
        finally:
            renew.cancel()
            await asyncio.gather(renew, return_exceptions=True)
            if audit is not None:
                audit.db.close()
            await lease.release()
    finally:
        await connection.close()
        report("exit", **resources())
    return 0


async def main(args):
    task = asyncio.current_task()
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, task.cancel)
    asyncio.get_running_loop().add_signal_handler(signal.SIGINT, task.cancel)
    try:
        return await run(args)
    except asyncio.CancelledError:
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--broker-port", type=int, required=True)
    parser.add_argument("--coordinator-port", type=int, required=True)
    parser.add_argument("--id", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--claim-timeout", type=float, default=45)
    parser.add_argument("--delay", type=float, default=0)
    parser.add_argument("--stop-before-withdrawal-ack", action="store_true",
                        help="disposable fault harness: SIGSTOP after withdrawal audit and before broker ACK")
    logging.basicConfig(level=logging.WARNING)
    sys.exit(asyncio.run(main(parser.parse_args())))
