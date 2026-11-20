"""Run request-independent native loss trials against a clean exact source pin."""

import argparse
import asyncio
from contextlib import ExitStack, closing
from dataclasses import asdict, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Event, Thread
from time import monotonic_ns, sleep
from types import SimpleNamespace
from uuid import uuid4

from phase4e_observer_order import event, external_probe, native_state, timed


def require_pin(root, pin):
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if actual != pin:
        raise ValueError(f"source pin mismatch: {actual} != {pin}")
    for args in (["git", "diff", "--quiet"], ["git", "diff", "--cached", "--quiet"]):
        if subprocess.run(args, cwd=root, check=False).returncode:
            raise ValueError("candidate worktree has uncommitted tracked changes")
    if subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"],
                               cwd=root, text=True).strip():
        raise ValueError("candidate worktree has untracked files")


async def trial(root, scenario, pin):
    from test_defensive_validation import Network, StatusFixture
    import httpx
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from aegis.core import InventoryItem, LocalAgent, LocalPolicy
    from aegis.evidence import Evidence
    from aegis.evidence.synthetic import create_lab
    from aegis.journal.protocol import JournalBlocked
    from aegis.mitigation.lab import Lab
    from aegis.mitigation.observer import ObservationError
    from aegis.mitigation.policy import Denied, LocalOperator
    from aegis.mitigation.store import TargetStore
    from aegis.ownership import IdentitySession, lease_proof
    from aegis.phase3c import (
        EvidenceGate, MeshIntake, MESH_TEMPLATE, PACKAGE, VERSION, VerifiedLab, publishable_finding,
    )
    from aegis.storage import SqliteAudit
    from aegis.trust_lab.native_evidence import NativeEvidenceStatus

    trace = []
    root.mkdir()
    with ExitStack() as stack:
        network = Network(root, stack)
        researcher = create_lab()
        collector = stack.enter_context(Evidence(root / "collector.db", researcher.trust, researcher.verifiers))
        evidence = stack.enter_context(Evidence(root / "relying.db", researcher.trust))
        finding, bundle, verification = publishable_finding(network.finding(), network.author, researcher, collector)
        network.archive.append(network.receive(finding))
        network.publish(network.seal())
        audit = SqliteAudit(root / "rapid.db", str(uuid4()))
        stack.enter_context(closing(audit.db))
        agent = LocalAgent(LocalPolicy(network.trust, frozenset({MESH_TEMPLATE}), True),
                           [InventoryItem(PACKAGE, VERSION)], audit)
        if agent.evaluate_event(finding).outcome != "allow_dry_run":
            raise AssertionError("healthy signed finding control failed")
        status = StatusFixture(root, researcher, bundle, audit.agent_id)
        key = Ed25519PrivateKey.generate()
        path = root / "target.db"
        provision = TargetStore(path, LocalOperator())
        provision.create()
        home = provision.ownership
        principal = "spiffe://aegis.lab/phase-next-validation/holder"
        home.enroll(audit.agent_id, principal, key.public_key(), ("broker-a", "broker-b"))

        def claim(broker):
            proof = lease_proof("claim", home.candidate(broker), key)
            return IdentitySession(home.accept(proof, peer_principal=principal, broker=broker), key)

        old = claim("broker-a")

        async with httpx.AsyncClient(transport=httpx.MockTransport(
                lambda _: (_ for _ in ()).throw(AssertionError("legacy coordinator queried")))) as remote:
            journal = network.client()
            intake = MeshIntake(agent, None, remote, journal=journal)
            intake.lease = SimpleNamespace(ensure=lambda: asyncio.sleep(0))
            gate = EvidenceGate(finding, bundle, verification, intake, collector, evidence,
                                independent_evidence=NativeEvidenceStatus(status.reader, status.fetch))
            writer = VerifiedLab(gate, path, identity=old)
            with writer.lab as lab:
                plan = await writer.prepare(4500)
                if scenario == "stale_approval":
                    approval = lab.operator.approve(plan, plan.digest)
                    superseding = await writer.prepare(4500)
                    before = timed(trace, "before_negative_write", lambda: native_state(path))
                    try:
                        await writer.transition(lab.controller.start, superseding, approval, action="begin")
                        event(trace, "negative_write_result", outcome="authorized")
                    except Denied as exc:
                        event(trace, "negative_write_result", outcome="denied", reason=str(exc))
                    timed(trace, "after_negative_write", lambda: native_state(path))
                    return {"source_commit": pin, "scenario": scenario, "trace": trace,
                            "baseline_unchanged": before == native_state(path)}
                if scenario in {"interrupted_transaction", "revoked_evidence", "stale_trust_cut"}:
                    approval = lab.operator.approve(plan, plan.digest)
                    await writer.transition(lab.controller.start, plan, approval, action="begin")
                    await writer.transition(lab.controller.restrict, plan, approval, plan.targets[0],
                                            action="restrict", target=plan.targets[0])
                    await writer.transition(lab.controller.verify, plan, canary=True, action="verify-canary")
                    before = timed(trace, "before_negative_write", lambda: native_state(path))
                    calls = 0
                    if scenario == "interrupted_transaction":
                        def expire_at_commit():
                            nonlocal calls
                            calls += 1
                            return calls == 1
                        lab.store._status_current = expire_at_commit
                    elif scenario == "revoked_evidence":
                        status.withdraw("research", "bundle", bundle.sha256)
                    else:
                        network.archive.append(network.receive(network.withdrawal(finding)))
                        network.publish(network.seal())
                        journal.archives = ()
                    try:
                        peer = plan.targets[1]
                        if scenario == "interrupted_transaction":
                            lab.controller.restrict(plan, approval, peer,
                                                    command=old.command("restrict", plan.digest, peer))
                        else:
                            await writer.transition(lab.controller.restrict, plan, approval, peer,
                                                    action="restrict", target=peer)
                        event(trace, "negative_write_result", outcome="authorized")
                    except (Denied, JournalBlocked) as exc:
                        event(trace, "negative_write_result", outcome="denied", reason=str(exc))
                    finally:
                        lab.store._status_current = gate.status_current
                    timed(trace, "after_negative_write", lambda: native_state(path))
                    return {"source_commit": pin, "scenario": scenario, "trace": trace,
                            "baseline_unchanged": before == native_state(path),
                            "status_checks": calls}
                await writer.execute(plan, plan.digest)
                await gate.refresh()
                healthy_http = external_probe(trace, "healthy_http_control", lab.endpoints)
                baseline = timed(trace, "healthy_disk", lambda: native_state(path))
                if [row["status"] for row in healthy_http] != [403, 200, 200] * 3:
                    raise AssertionError("healthy route control failed: " +
                                         repr([row["status"] for row in healthy_http]))
                if baseline["rollout"][0] != "confirmed":
                    raise AssertionError("healthy committed control failed")
                original_probe = lab.observer._probe
                first_internal = True

                def capture_probe(target, fence, route, expected_status, body):
                    nonlocal first_internal
                    fields = {}
                    if first_internal:
                        first_internal = False
                        fields = {"snapshot_started_ns": monotonic_ns(), "disk": native_state(path)}
                    event(trace, "internal_probe_start", target=target, route=route,
                          expected_status=expected_status, **fields)
                    return original_probe(target, fence, route, expected_status, body)

                lab.observer._probe = capture_probe
                idle = scenario.endswith("_idle") or scenario == "ownership_snapshot_race"
                monitor = None if idle else asyncio.create_task(writer.monitor(plan))
                if scenario == "ownership_snapshot_race":
                    with lab.store.route("canary", marker=True) as prepared_route:
                        event(trace, "prepared_route_snapshot", state=asdict(prepared_route))
                    start_transfer = Event()
                    transfer_result = {}

                    def transfer():
                        start_transfer.wait()
                        event(trace, "authority_cut_started")
                        try:
                            home.fence(old.assignment.generation)
                            successor = claim("broker-b")
                            transfer_result["successor"] = successor
                            event(trace, "authority_cut_applied", generation=successor.assignment.generation)
                        except Exception as exc:
                            transfer_result["error"] = type(exc).__name__ + ": " + str(exc)

                    worker = Thread(target=transfer)
                    worker.start()
                    start_transfer.set()
                    while worker.is_alive():
                        sample_start = monotonic_ns()
                        event(trace, "concurrent_readonly_snapshot", started_ns=sample_start,
                              disk=native_state(path))
                        sleep(.001)
                    worker.join()
                    if "error" in transfer_result:
                        raise AssertionError(transfer_result["error"])
                    successor = transfer_result["successor"]
                    event(trace, "stale_route_response_check",
                          permitted=lab.store.response_permitted(prepared_route))
                else:
                    event(trace, "authority_cut_started")
                    if scenario.startswith("ownership"):
                        home.fence(old.assignment.generation)
                        successor = claim("broker-b")
                        generation = successor.assignment.generation
                    else:
                        status.unavailable = True
                        generation = old.assignment.generation
                    event(trace, "authority_cut_applied", generation=generation)
                if idle:
                    if scenario == "evidence_idle":
                        deadline = min(gate._fresh_until, gate.valid_until_ns, plan.expires_ns)
                        event(trace, "authority_deadline", deadline_ns=deadline)
                        await asyncio.sleep(max(0.5, (deadline - monotonic_ns()) / 1_000_000_000 + .05))
                    else:
                        await asyncio.sleep(0.5)
                    timed(trace, "pre_external_probe_disk", lambda: native_state(path))
                    external_probe(trace, "first_post_fault_external_gets", lab.endpoints)
                    timed(trace, "post_external_probe_disk", lambda: native_state(path))
                    monitor = asyncio.create_task(writer.monitor(plan))
                try:
                    result = await asyncio.wait_for(monitor, timeout=5)
                    event(trace, "monitor_result", result=result)
                except Exception as exc:
                    event(trace, "monitor_error", error=type(exc).__name__ + ": " + str(exc))
                timed(trace, "durable_after_monitor_before_external_gets", lambda: native_state(path))
                external_probe(trace, "separate_read_only_gets_after_hold", lab.endpoints)
                timed(trace, "post_gets_disk", lambda: native_state(path))
                if scenario.startswith("ownership"):
                    held_state = native_state(path)
                    prior_approval = lab.operator.approve(plan, plan.digest)
                    try:
                        peer = plan.targets[1]
                        lab.controller.restrict(plan, prior_approval, peer,
                                                command=old.command("restrict", plan.digest, peer))
                        event(trace, "old_owner_reopen_attempt", outcome="authorized")
                    except (Denied, ObservationError) as exc:
                        event(trace, "old_owner_reopen_attempt", outcome="denied", reason=str(exc))
                    next_plan = replace(plan, nonce=uuid4().hex,
                                        ownership_binding=successor.assignment.binding,
                                        expected_fences=tuple(row[1] for row in held_state["targets"]))
                    next_approval = lab.operator.approve(next_plan, next_plan.digest)
                    try:
                        lab.controller.start(next_plan, next_approval,
                                             command=successor.command("begin", next_plan.digest))
                        event(trace, "fresh_successor_reopen_attempt", outcome="authorized")
                    except (Denied, ObservationError) as exc:
                        event(trace, "fresh_successor_reopen_attempt", outcome="denied", reason=str(exc))
                    timed(trace, "after_reopen_attempts_disk", lambda: native_state(path))
                    if native_state(path)["targets"] != held_state["targets"]:
                        raise AssertionError("reopen attempt changed held targets")
            status.unavailable = False
            if scenario in {"ownership_idle", "ownership_monitor", "ownership_snapshot_race",
                            "evidence_idle", "evidence_monitor"}:
                await gate.refresh()
                before_restart = native_state(path)
                with Lab(path, authorize=gate.authorize, status_current=gate.status_current,
                         require_identity=True) as reboot:
                    restarted = timed(trace, "restart_disk", lambda: native_state(path))
                    external_probe(trace, "read_only_gets_after_restart", reboot.endpoints)
                    timed(trace, "post_restart_gets_disk", lambda: native_state(path))
                    if restarted["targets"] != before_restart["targets"]:
                        raise AssertionError("restart changed held target fences")
    return {"source_commit": pin, "scenario": scenario, "trace": trace}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--source-pin", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario", action="append", choices=("ownership_idle", "ownership_monitor",
                        "ownership_snapshot_race", "evidence_idle", "evidence_monitor",
                        "stale_approval", "interrupted_transaction",
                        "revoked_evidence", "stale_trust_cut"))
    parser.add_argument("--env", action="append", default=[], metavar="NAME=VALUE",
                        help="explicit candidate opt-in environment variable")
    args = parser.parse_args()
    candidate = args.candidate_root.resolve()
    require_pin(candidate, args.source_pin)
    for item in args.env:
        name, separator, value = item.partition("=")
        if not separator or not name.startswith("AEGIS_"):
            raise ValueError("--env requires AEGIS_ NAME=VALUE")
        os.environ[name] = value
    sys.path[:0] = [str(candidate / p) for p in ("src", "tests/phase4e", "tests/phase4d")]
    with TemporaryDirectory(prefix="phase-next-native-") as directory:
        root = Path(directory)
        scenarios = args.scenario or ("ownership_idle", "ownership_monitor", "ownership_snapshot_race",
                                      "evidence_idle", "evidence_monitor",
                                      "stale_approval", "interrupted_transaction", "revoked_evidence",
                                      "stale_trust_cut")
        rows = [asyncio.run(trial(root / scenario, scenario, args.source_pin)) for scenario in scenarios]
    args.output.write_text(json.dumps({"environment": {"when_utc": datetime.now(timezone.utc).isoformat(),
                                                       "topology": "one-host loopback fixture",
                                                       "candidate_env": args.env},
                                       "trials": rows}, indent=2) + "\n")


if __name__ == "__main__":
    main()
