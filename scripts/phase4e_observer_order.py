"""Run observer-order trials against exact Phase 4E source pins in disposable loopback labs."""

import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing, contextmanager
from datetime import datetime, timezone
from http.client import HTTPConnection
import io
import json
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory
from threading import Barrier
from time import monotonic_ns, sleep
from types import SimpleNamespace
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
B_PIN = "11ecb948de82ef094f4fc48261786ff7600d64de"
NATIVE_PIN = "1fff1c572a461adf7fc4bad057f092cb2f61f70d"
ROUTES = ("/fixture-marker", "/health", "/ok")


def event(trace, name, **fields):
    row = {"event": name, "at_ns": monotonic_ns(), **fields}
    trace.append(row)
    return row


def timed(trace, name, operation):
    started = monotonic_ns()
    result = operation()
    event(trace, name, started_ns=started, result=result)
    return result


@contextmanager
def read_only(path):
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        yield db


def denied(trace, name, operation, *expected):
    started = monotonic_ns()
    try:
        operation()
    except expected as exc:
        return event(trace, name, started_ns=started, outcome=type(exc).__name__, reason=str(exc))
    raise AssertionError(f"{name} unexpectedly authorized")


def probe_process():
    endpoints = json.load(sys.stdin)
    samples = []
    for target, (host, port) in endpoints.items():
        assert host == "127.0.0.1"
        for path in ROUTES:
            started = monotonic_ns()
            with closing(HTTPConnection(host, port, timeout=1)) as conn:
                conn.request("GET", path)
                response = conn.getresponse()
                body = response.read(256).decode("ascii")
                event(samples, "GET", started_ns=started, path=path, target=target,
                      status=response.status, body=body, lab=response.getheader("X-Lab-Id"),
                      served_target=response.getheader("X-Lab-Target"),
                      fence=int(response.getheader("X-Lab-Fence")))
    json.dump(samples, sys.stdout)


def external_probe(trace, name, endpoints):
    # This subprocess receives only loopback addresses and issues GET requests.
    return timed(trace, name, lambda: json.loads(subprocess.check_output(
        [sys.executable, str(Path(__file__).resolve()), "probe"],
        input=json.dumps(endpoints), text=True, env={"PYTHONDONTWRITEBYTECODE": "1"}, timeout=8,
    )))


def b_state(lab, target):
    with read_only(lab.database(target)) as db:
        stored = json.loads(db.execute("SELECT body FROM record").fetchone()[0])
        version, marker = db.execute("SELECT version,value FROM marker").fetchone()
        receipts = db.execute("SELECT generation,marker FROM receipts ORDER BY rowid").fetchall()
        return {"generation": stored["assignment"]["generation"], "held": stored["held"],
                "version": version, "marker": marker, "receipts": receipts}


def b_trial(root):
    wire = subprocess.check_output(
        ["git", "archive", B_PIN, "src", "tests/identity_lab"], cwd=ROOT,
    )
    exact = root / "source"
    exact.mkdir()
    with tarfile.open(fileobj=io.BytesIO(wire)) as archive:
        archive.extractall(exact, filter="data")
    sys.path[:0] = [str(exact / "src"), str(exact / "tests/identity_lab")]
    # The pinned fixture launches each role using paths relative to its own source.
    from conftest import Lab, running
    from test_fencing import claim, plan, recover
    from aegis.identity_lab.protocol import Denied, Fence, Unavailable
    from aegis.identity_lab.services import Target

    assert Path(sys.modules[Target.__module__].__file__).is_relative_to(exact)
    trial = {"source_commit": B_PIN, "trace": []}
    trace = trial["trace"]
    stores = root / "stores"
    stores.mkdir()
    with running(Lab(stores)) as lab:
        old = claim(lab)
        for target in lab.targets:
            lab.call("agent-a", "broker-a", "/write", plan(lab, old, target))
        prior_a, prior_b = (plan(lab, old, t) for t in lab.targets)
        healthy = timed(trace, "healthy_disk", lambda: {t: b_state(lab, t) for t in lab.targets})
        assert all(s["marker"] == "observing" and not s["held"] for s in healthy.values())
        timed(trace, "anchor_stopped", lambda: lab.stop("anchor"))
        sleep(0.5)
        silent = timed(trace, "before_any_serving_request", lambda: {t: b_state(lab, t) for t in lab.targets})
        assert silent == healthy
        first = timed(trace, "first_post_fault_read_a", lambda: lab.call("observer", "target-a", "/read"))
        assert first["effective"] == "quarantined"
        triggered = timed(trace, "after_first_read_a", lambda: {t: b_state(lab, t) for t in lab.targets})
        assert triggered["target-a"]["held"] and triggered["target-a"]["marker"] == "quarantined"
        assert triggered["target-a"]["receipts"] == healthy["target-a"]["receipts"]
        assert triggered["target-b"] == healthy["target-b"]
        timed(trace, "unchanged_anchor_restarted", lambda: lab.start("anchor"))
        denied(trace, "same_generation_latched_target_a", lambda: lab.call(
            "broker-a", "target-a", "/write", prior_a), Denied)
        denied(trace, "observer_attempts_fence", lambda: lab.call(
            "observer", "target-a", "/fence", Fence(assignment=old, target="target-a")), Denied)
        returned = timed(trace, "first_read_b_after_unchanged_anchor_return", lambda: lab.call(
            "observer", "target-b", "/read"))
        assert returned["effective"] == "observing" and b_state(lab, "target-b") == healthy["target-b"]

        timed(trace, "second_anchor_loss", lambda: lab.stop("anchor"))
        gate = Barrier(3)

        def contend(name, operation):
            gate.wait(timeout=2)
            started = monotonic_ns()
            try:
                result = operation()
                return {"name": name, "started_ns": started, "at_ns": monotonic_ns(), "value": result}
            except (Denied, Unavailable) as exc:
                return {"name": name, "started_ns": started, "at_ns": monotonic_ns(),
                        "error": str(exc), "outcome": type(exc).__name__}

        with ThreadPoolExecutor(max_workers=2) as pool:
            with closing(sqlite3.connect(lab.database("target-b"))) as lock:
                lock.execute("BEGIN IMMEDIATE")
                event(trace, "target_b_writer_lock_acquired")
                hold = pool.submit(contend, "hold_read", lambda: lab.call("observer", "target-b", "/read"))
                write = pool.submit(contend, "protected_write", lambda: lab.call(
                    "broker-a", "target-b", "/write", prior_b))
                gate.wait(timeout=2)
                sleep(0.1)
                assert not hold.done() and not write.done()
                assert timed(trace, "competing_requests_blocked_disk", lambda: b_state(lab, "target-b")) ==                     healthy["target-b"]
                lock.rollback()
                event(trace, "target_b_writer_lock_released")
            results = [hold.result(timeout=6), write.result(timeout=6)]
        event(trace, "racing_request_results", results=results)
        committed = timed(trace, "target_b_durable_after_race", lambda: b_state(lab, "target-b"))
        assert results[0]["value"]["effective"] == "quarantined" and "error" in results[1]
        assert committed["held"] and committed["marker"] == "quarantined"
        assert committed["receipts"] == healthy["target-b"]["receipts"]

        timed(trace, "anchor_restarted_after_race", lambda: lab.start("anchor"))
        timed(trace, "operator_retired", lambda: recover(lab))
        new = claim(lab, "agent-b", "broker-b")
        event(trace, "successor_activated", generation=new.generation)
        for target in lab.targets:
            prior = prior_a if target == "target-a" else prior_b
            fresh = plan(lab, new, target)
            denied(trace, f"stale_owner_{target}", lambda: lab.call(
                "broker-a", target, "/write", prior), Denied)
            denied(trace, f"old_approval_{target}", lambda: lab.call(
                "agent-b", "broker-b", "/write", fresh.model_copy(update={"approval": prior.approval})), Denied)
            assert b_state(lab, target)["marker"] == "quarantined"
            timed(trace, f"fresh_approval_{target}", lambda: lab.call("agent-b", "broker-b", "/write", fresh))
            assert b_state(lab, target)["receipts"] == [(old.generation, "observing"), (new.generation, "observing")]
    trial["pre_observation_gate"] = "FAIL"
    return trial


def native_state(path):
    with read_only(path) as db:
        targets = db.execute("SELECT id,fence,mode FROM target ORDER BY id").fetchall()
        rollout = db.execute("SELECT phase,changed_ns,deadline_ns FROM rollout").fetchone()
        audit = db.execute("SELECT seq,at_ns,event FROM audit ORDER BY seq").fetchall()
        generation, rollout_generation = db.execute(
            "SELECT generation,rollout_generation FROM ownership").fetchone()
        return {"targets": targets, "rollout": rollout, "audit": audit, "generation": generation,
                "rollout_generation": rollout_generation}


def native_writer_race(trace, lab, plan, approval, old, denied_type):
    path = lab.store.path
    baseline = timed(trace, "canary_before_race", lambda: native_state(path))
    assert baseline["rollout"][0] == "expanding"
    peer = plan.targets[1]
    proof = old.command("restrict", plan.digest, peer)
    gate = Barrier(3)

    def compete(operation):
        gate.wait(timeout=2)
        started = monotonic_ns()
        try:
            result = operation()
        except denied_type as exc:
            return {"started_ns": started, "at_ns": monotonic_ns(), "outcome": "denied", "reason": str(exc)}
        return {"started_ns": started, "at_ns": monotonic_ns(), "outcome": "committed", "result": result}

    with ThreadPoolExecutor(max_workers=2) as pool:
        with closing(sqlite3.connect(path)) as lock:
            lock.execute("BEGIN IMMEDIATE")
            event(trace, "native_writer_lock_acquired")
            hold = pool.submit(compete, lambda: lab.store.quarantine("independent writer serialization drill"))
            effect = pool.submit(compete, lambda: lab.controller.restrict(plan, approval, peer, command=proof))
            gate.wait(timeout=2)
            sleep(0.06)
            assert not hold.done() and not effect.done()
            assert timed(trace, "native_requests_blocked_disk", lambda: native_state(path)) == baseline
            lock.rollback()
            event(trace, "native_writer_lock_released")
        hold_result, effect_result = hold.result(timeout=3), effect.result(timeout=3)
    event(trace, "native_competition_results", hold=hold_result, effect=effect_result)
    after = timed(trace, "native_disk_after_competition", lambda: native_state(path))
    assert hold_result["outcome"] == "committed"
    assert after["rollout"][0] == "recovery_required"
    audit_delta = [entry[2] for entry in after["audit"][len(baseline["audit"]):]]
    assert audit_delta == (["restricted", "quarantined"] if effect_result["outcome"] == "committed"
                           else ["quarantined"])
    denied(trace, "peer_command_after_durable_quarantine",
           lambda: lab.controller.restrict(plan, approval, peer, command=proof), denied_type)
    verified = external_probe(trace, "read_only_gets_after_writer_race", lab.endpoints)
    assert all(item["status"] == 503 and item["body"] == "fixture quarantined" for item in verified)
    assert timed(trace, "disk_after_race_probe", lambda: native_state(path)) == after
    return {"source_commit": NATIVE_PIN, "scenario": "writer_lock", "trace": trace,
            "writer_serialization": "PASS", "pre_observation_gate": "NOT_ASSESSED"}


async def native_trial(root, scenario):
    from test_defensive_validation import Network, StatusFixture
    import httpx
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from aegis.core import InventoryItem, LocalAgent, LocalPolicy
    from aegis.evidence import Evidence
    from aegis.evidence.synthetic import create_lab
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
        assert agent.evaluate_event(finding).outcome == "allow_dry_run"
        status = StatusFixture(root, researcher, bundle, audit.agent_id)
        key = Ed25519PrivateKey.generate()
        path = root / "target.db"
        provision = TargetStore(path, LocalOperator())
        provision.create()
        home = provision.ownership
        principal = "spiffe://aegis.lab/observer-validation/holder"
        home.enroll(audit.agent_id, principal, key.public_key(), ("broker-a", "broker-b"))

        def claim_instance(broker):
            proof = lease_proof("claim", home.candidate(broker), key)
            return IdentitySession(home.accept(proof, peer_principal=principal, broker=broker), key)

        old = new = claim_instance("broker-a")

        def coordinator(_):
            raise AssertionError("the witnessed native fixture must not query the legacy coordinator")

        async with httpx.AsyncClient(transport=httpx.MockTransport(coordinator)) as remote:
            intake = MeshIntake(agent, None, remote, journal=network.client())
            intake.lease = SimpleNamespace(ensure=lambda: asyncio.sleep(0))
            gate = EvidenceGate(finding, bundle, verification, intake, collector, evidence,
                                independent_evidence=NativeEvidenceStatus(status.reader, status.fetch))
            writer = VerifiedLab(gate, path, identity=old)
            with writer.lab as lab:
                plan = await writer.prepare(4500)
                approval = lab.operator.approve(plan, plan.digest)
                if scenario == "writer_lock":
                    await writer.transition(lab.controller.start, plan, approval, action="begin")
                    await writer.transition(lab.controller.restrict, plan, approval, plan.targets[0],
                                            action="restrict", target=plan.targets[0])
                    await writer.transition(lab.controller.verify, plan, canary=True, action="verify-canary")
                    return native_writer_race(trace, lab, plan, approval, old, Denied)
                await writer.execute(plan, plan.digest)
                healthy = external_probe(trace, "healthy_http_control", lab.endpoints)
                assert [r["status"] for r in healthy] == [403, 200, 200] * 3
                baseline = timed(trace, "healthy_disk", lambda: native_state(path))
                assert baseline["rollout"][0] == "confirmed"

                # Capture committed state before the first internal GET after the fault.
                original_probe = lab.observer._probe
                first_internal_probe = True

                def record_probe(target, fence, route, expected_status, body):
                    nonlocal first_internal_probe
                    fields = {}
                    if first_internal_probe:
                        first_internal_probe = False
                        fields = {"snapshot_started_ns": monotonic_ns(), "disk": native_state(path)}
                    event(trace, "internal_probe_start", target=target, route=route,
                          expected_status=expected_status, **fields)
                    try:
                        original_probe(target, fence, route, expected_status, body)
                    except ObservationError as exc:
                        event(trace, "internal_probe_failed", target=target, route=route, reason=str(exc))
                        raise

                lab.observer._probe = record_probe
                if scenario != "ownership_idle":
                    monitor = asyncio.create_task(writer.monitor(plan))
                event(trace, "authority_cut_started")
                if scenario.startswith("ownership"):
                    home.fence(old.assignment.generation)
                    new = claim_instance("broker-b")
                else:
                    status.unavailable = True
                event(trace, "authority_cut_applied", generation=new.assignment.generation)

                if scenario == "ownership_idle":
                    await asyncio.sleep(0.5)
                    before = timed(trace, "pre_external_probe_disk", lambda: native_state(path))
                    denied_http = external_probe(trace, "first_post_fault_external_gets", lab.endpoints)
                    assert all(row["status"] == 503 and row["body"] == "fixture quarantined" for row in denied_http)
                    assert timed(trace, "post_external_probe_disk", lambda: native_state(path)) == before
                    assert before["targets"] == baseline["targets"] and before["audit"] == baseline["audit"]
                    monitor = asyncio.create_task(writer.monitor(plan))

                assert await asyncio.wait_for(monitor, timeout=4) == "safe_hold"
                before_internal = next(row["disk"] for row in trace if row["event"] == "internal_probe_start")
                pre_probe_hold = all(mode == "quarantined" for _, _, mode in before_internal["targets"])
                disk = timed(trace, "durable_after_monitor_before_external_gets", lambda: native_state(path))
                assert disk["rollout"][0] == "safe_hold" and all(mode == "quarantined" for _, _, mode in disk["targets"])
                assert sum(row[2] == "restricted" for row in disk["audit"]) == 3
                requests = external_probe(trace, "separate_read_only_gets_after_hold", lab.endpoints)
                assert all(row["status"] == 503 and row["body"] == "fixture quarantined" and row["fence"] == 2
                           and row["served_target"] == row["target"] for row in requests)
                assert timed(trace, "post_gets_disk", lambda: native_state(path)) == disk

                status.unavailable = False
                await gate.refresh()
                for session, label in ((old, "old_owner"), (new, "current_owner_old_approval")):
                    peer = plan.targets[1]
                    proof = session.command("restrict", plan.digest, peer)
                    denied(trace, label, lambda: lab.controller.restrict(plan, approval, peer, command=proof), Denied)
                assert timed(trace, "post_replay_disk", lambda: native_state(path)) == disk

            with Lab(path, authorize=gate.authorize, status_current=gate.status_current, require_identity=True) as reboot:
                restarted = timed(trace, "restart_disk", lambda: native_state(path))
                assert restarted["rollout"][0] == "safe_hold" and restarted["targets"] == disk["targets"]
                retest = external_probe(trace, "read_only_gets_after_restart", reboot.endpoints)
                assert all(row["status"] == 503 and row["body"] == "fixture quarantined" for row in retest)
    return {"source_commit": NATIVE_PIN, "scenario": scenario, "trace": trace,
            "pre_observation_gate": "PASS" if scenario != "ownership_idle" and pre_probe_hold else "FAIL"}


def main():
    if sys.argv[1:] == ["probe"]:
        probe_process()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("b", "native"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    environment = {"when_utc": datetime.now(timezone.utc).isoformat(), "host": platform.platform(),
                   "python": platform.python_version(), "monotonic_clock": "single host"}
    with TemporaryDirectory(prefix="phase4e-observer-") as directory:
        root = Path(directory)
        if args.mode == "b":
            trials = [b_trial(root)]
        else:
            pin = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
            if pin != NATIVE_PIN:
                subprocess.run(["git", "diff", "--exit-code", NATIVE_PIN, "HEAD", "--", "src", "tests"],
                               check=True, cwd=ROOT)
            subprocess.run(["git", "diff", "--exit-code", NATIVE_PIN, "--", "src", "tests"], check=True, cwd=ROOT)
            sys.path[:0] = [str(ROOT / path) for path in ("src", "tests/phase4e", "tests/phase4d")]
            trials = [asyncio.run(native_trial(root / name, name))
                      for name in ("ownership_idle", "ownership_monitor", "evidence_monitor", "writer_lock")]
    args.output.write_text(json.dumps({"environment": environment, "trials": trials}, indent=2) + "\n")


if __name__ == "__main__":
    main()
