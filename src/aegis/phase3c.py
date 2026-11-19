"""Evidence-bound, manually approved defense for disposable local HTTP fixtures."""

import asyncio
from contextlib import asynccontextmanager, contextmanager, suppress
import json
from pathlib import Path
import sqlite3
from threading import RLock
import time

from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy
from nats.js.errors import NotFoundError

from .agent_runtime import durable_name, process_message
from .api import STREAM
from .artifact import Evidence as EvidenceReference
from .artifact import SignedFinding, canonical_bytes, parse_event, sign
from .evidence._worker import materials
from .evidence.records import SignedAttestation, SignedManifest, decode, digest
from .identity import IdentityLease, renew_lease
from .mitigation.lab import Lab
from .mitigation.policy import Denied
from .recovery import reconcile

COHORT = "lab-blue"
PACKAGE = "pkg:generic/aegis-demo"
VERSION = "1.0.0"
MESH_TEMPLATE = "restrict-fixture-route.v1"
REFERENCE = "urn:aegis:evidence:"
STATUS_SECONDS = 1.0


def claim_bytes(finding) -> bytes:
    # The signed Mesh evidence reference would otherwise create a digest cycle.
    return json.dumps(finding.model_dump(mode="json", exclude={"evidence"}),
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def attestations_digest(assessment):
    return tuple(sorted(digest(wire) for wire in assessment.attestations))


def check_bundle(finding, bundle) -> None:
    manifest = decode(SignedManifest, bundle.manifest).body
    reference = EvidenceReference(uri=REFERENCE + bundle.sha256, sha256=bundle.sha256,
                                  method="lab-reproduction")
    if (finding.evidence != [reference] or manifest.claim_sha256 != digest(claim_bytes(finding))
            or manifest.cohort != COHORT or manifest.family != "route-toggle"
            or bundle.objects != materials("route-toggle", "marker-on", "observer-ready")
            or finding.mitigation_template != MESH_TEMPLATE or finding.software.purl != PACKAGE
            or finding.software.affected_versions != [VERSION]):
        raise Denied("evidence does not cover this exact enrolled finding and fixture")


def publishable_finding(finding, key, researcher, collector):
    """Verify the fixed fixture before signing its Mesh finding."""
    bundle = researcher.bundle(claim_bytes(finding).decode(), family="route-toggle", cohort=COHORT)
    result = collector.verify(bundle, cohort=COHORT)
    if result.outcome != "reproduced":
        raise Denied(f"evidence is not reproducible: {result.reason}")
    reference = EvidenceReference(uri=REFERENCE + bundle.sha256, sha256=bundle.sha256,
                                  method="lab-reproduction")
    scoped = finding.model_copy(update={"evidence": [reference]})
    check_bundle(scoped, bundle)
    return sign(scoped, key), bundle, result


class MeshIntake:
    """Phase 2 durable delivery plus current local appraisal of journal state."""

    def __init__(self, agent, js, client):
        self.agent = agent
        self.js = js
        self.client = client
        self.lease = None
        self.subscription = None

    @asynccontextmanager
    async def connect(self):
        agent_id = self.agent.audit.agent_id
        name = durable_name(agent_id)
        self.lease = await IdentityLease.claim(self.js, agent_id)
        renewal = asyncio.create_task(renew_lease(self.lease))
        try:
            self.subscription = await self.js.pull_subscribe(
                "aegis.>", durable=name, stream=STREAM,
                config=ConsumerConfig(max_deliver=-1, ack_wait=10,
                                      ack_policy=AckPolicy.EXPLICIT, deliver_policy=DeliverPolicy.NEW),
            )
            yield self
        finally:
            renewal.cancel()
            await asyncio.gather(renewal, return_exceptions=True)
            try:
                await self.lease.release()
            finally:
                # These are disposable subscriptions. The audit is retained.
                if self.subscription is not None:
                    with suppress(NotFoundError):
                        await self.js.delete_consumer(STREAM, name)

    async def receive(self, event_id: str):
        observation = None

        def observe(decision, received, lease_checked, committed, acked):
            nonlocal observation
            if decision.event_id == event_id:
                observation = decision, received, committed, acked

        async with asyncio.timeout(20):
            while observation is None:
                try:
                    messages = await self.subscription.fetch(1, timeout=1)
                except TimeoutError:
                    continue
                message = messages[0]
                await process_message(message, self.agent, self.js, self.lease, observe=observe)
                if observation is not None:
                    envelope = parse_event(message.data)
                    if not isinstance(envelope, SignedFinding):
                        raise Denied("the received event is not a finding")
                    return envelope, *observation

    async def fresh(self, envelope):
        started = time.monotonic_ns()
        async with asyncio.timeout(STATUS_SECONDS):
            await self.lease.ensure()
            await reconcile(self.agent, self.agent.audit, self.client, self.lease)
        prior = self.agent.audit.get(str(envelope.finding.artifact_id))
        exact_digest = digest(canonical_bytes(envelope.finding))
        if prior is None or prior.digest != exact_digest:
            raise Denied("the exact delivered finding has no local audit")
        decision = self.agent.evaluate(envelope)
        if decision.outcome != "allow_dry_run" or decision.digest != exact_digest:
            raise Denied(f"Rapid denied the finding: {decision.reason_code}")
        return started + int(STATUS_SECONDS * 1e9)


class EvidenceGate:
    """Join immutable evidence and per-deployment Rapid appraisal at the writer."""

    def __init__(self, envelope, bundle, assessment, receiver, collector, evidence):
        self.envelope = envelope
        self.bundle = bundle
        self.receiver = receiver
        self.collector = collector
        self.evidence = evidence
        self._lock = RLock()
        self._fresh_until = 0
        check_bundle(envelope.finding, bundle)
        if assessment.bundle_sha256 != bundle.sha256 or assessment.outcome != "reproduced":
            raise Denied("the finding has no qualifying evidence package")
        for wire in assessment.attestations:
            evidence.accept_attestation(bundle, wire, cohort=COHORT)
        local = evidence.assess(bundle, cohort=COHORT)
        if local.outcome != "reproduced":
            raise Denied(f"local evidence appraisal failed: {local.reason}")
        self.attestations = attestations_digest(local)
        self.binding_context = {
            "agent_id": receiver.agent.audit.agent_id,
            "finding_id": str(envelope.finding.artifact_id),
            "finding_sha256": digest(canonical_bytes(envelope.finding)),
            "bundle_sha256": bundle.sha256,
            "attestation_sha256": self.attestations,
        }
        self.binding = digest(json.dumps(self.binding_context, sort_keys=True).encode())
        publisher = receiver.agent.trust.grants[(envelope.finding.publisher_id, envelope.key_id)]
        expiry = min(envelope.finding.expires_at.timestamp(), publisher.expires_at.timestamp(),
                     *(decode(SignedAttestation, wire).body.expires_at for wire in local.attestations))
        if publisher.revoked_at is not None:
            expiry = min(expiry, publisher.revoked_at.timestamp())
        self.valid_until_ns = time.monotonic_ns() + int((expiry - time.time()) * 1e9)

    async def refresh(self):
        try:
            deadline = await self.receiver.fresh(self.envelope)
        except Exception:
            with self._lock:
                self._fresh_until = 0
            raise
        with self._lock:
            self._fresh_until = deadline

    def status_current(self):
        # Called by the proxy while it holds a target transaction. Do not
        # acquire a lock here because guarded writers take the opposite order.
        return time.monotonic_ns() < min(self._fresh_until, self.valid_until_ns)

    @contextmanager
    def authorize(self, plan):
        with self._lock, self.collector.current_assessment(self.bundle, cohort=COHORT) as current:
            with self.evidence.current_assessment(self.bundle, cohort=COHORT) as local:
                if (current.outcome != "reproduced" or local.outcome != "reproduced"
                        or attestations_digest(current) != self.attestations
                        or attestations_digest(local) != self.attestations):
                    self._fresh_until = 0
                    raise Denied(f"evidence or Mesh status is not current ({current.reason}, {local.reason})")
                if (plan.evidence_binding != self.binding or plan.expires_ns > self.valid_until_ns
                        or not self.status_current()):
                    raise Denied("exact plan binding or Mesh status is not current")
                yield self.binding_context.copy()


class VerifiedLab:
    """Drive explicit local stages. A control-plane event never invokes this class."""

    def __init__(self, gate: EvidenceGate, path: Path):
        self.gate = gate
        self.lab = Lab(path, authorize=gate.authorize, status_current=gate.status_current)

    async def prepare(self, lease_ms):
        await self.gate.refresh()
        return self.lab.controller.prepare(lease_ms, binding=self.gate.binding,
                                           valid_until_ns=self.gate.valid_until_ns)

    async def transition(self, operation, *args, **kwargs):
        await self.gate.refresh()
        worker = asyncio.create_task(asyncio.to_thread(operation, *args, **kwargs))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            # Finish the in-flight target transaction before recovery.
            while not worker.done():
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            if not worker.cancelled():
                worker.exception()
            raise

    async def execute(self, plan, reviewed_digest):
        approval = self.lab.operator.approve(plan, reviewed_digest)
        started = time.monotonic_ns()
        try:
            await self.transition(self.lab.controller.start, plan, approval)
            preflight = time.monotonic_ns()
            await self.transition(self.lab.controller.restrict, plan, approval, plan.targets[0])
            await self.transition(self.lab.controller.verify, plan, canary=True)
            canary = time.monotonic_ns()
            for target in plan.targets[1:]:
                await self.transition(self.lab.controller.restrict, plan, approval, target)
            expanded = time.monotonic_ns()
            await self.transition(self.lab.controller.verify, plan)
            confirmed = time.monotonic_ns()
        except BaseException:
            # A failed preflight or unapproved plan cannot mutate a ready fixture.
            try:
                ready = self.lab.store.status() == "ready"
            except sqlite3.Error:
                ready = False
            if not ready:
                await asyncio.to_thread(self.lab.controller.rollback, "verified rollout interrupted")
            raise
        return {"preflight": preflight - started, "canary": canary - preflight,
                "expansion": expanded - canary, "effectiveness": confirmed - expanded,
                "confirmed_ns": confirmed}

    async def monitor(self, plan):
        try:
            while True:
                await asyncio.sleep(.05)
                await self.transition(self.lab.controller.verify, plan)
        except Exception:
            return await asyncio.to_thread(self.lab.controller.rollback, "lease, evidence, or health lost")
