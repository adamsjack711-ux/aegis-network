"""Evidence-bound, manually approved defense for disposable local HTTP fixtures."""

import asyncio
from contextlib import asynccontextmanager, contextmanager, nullcontext, suppress
from dataclasses import replace
import json
import logging
from pathlib import Path
import sqlite3
from threading import RLock
import time

from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy
from nats.js.errors import BadRequestError, NotFoundError

from .agent_runtime import durable_name, process_message
from .api import STREAM
from .artifact import Evidence as EvidenceReference
from .artifact import SignedFinding, canonical_bytes, parse_event, sign
from .evidence._worker import materials
from .evidence.records import SignedAttestation, SignedManifest, decode, digest
from .identity import IdentityLease, IdentityLost, renew_lease
from .mitigation.lab import Lab
from .mitigation.policy import Denied
from .ownership import Action, IdentitySession
from .recovery import reconcile

COHORT = "lab-blue"
PACKAGE = "pkg:generic/aegis-demo"
VERSION = "1.0.0"
MESH_TEMPLATE = "restrict-fixture-route.v1"
REFERENCE = "urn:aegis:evidence:"
STATUS_SECONDS = 1.0
JS_WRONG_LAST_SEQUENCE = 10071
logger = logging.getLogger(__name__)


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

    def __init__(self, agent, js, client, *, journal=None):
        self.agent = agent
        self.js = js
        self.client = client
        if journal is not None and journal.policy.cohort != COHORT:
            raise Denied("witnessed Mesh history is outside the enrolled cohort")
        self.journal = journal
        self.journal_binding = None
        self.journal_deadline = None
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
                if self.subscription is not None:
                    # Don't remove a durable now controlled by another owner.
                    with suppress(NotFoundError, IdentityLost):
                        await self.lease.ensure()
                        await self.js.delete_consumer(STREAM, name)
            finally:
                try:
                    await self.lease.release()
                except BadRequestError as exc:
                    if exc.err_code != JS_WRONG_LAST_SEQUENCE:
                        raise
                    # A timed-out KV write can land on reconnect. Leave the
                    # unmatched revision to expire instead of deleting it.
                    logger.warning("lease revision changed during cleanup; awaiting expiration")

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
        deadline = time.monotonic_ns() + int(STATUS_SECONDS * 1e9)
        async with asyncio.timeout(STATUS_SECONDS):
            await self.lease.ensure()
            if self.journal is None:
                await reconcile(self.agent, self.agent.audit, self.client, self.lease)
            else:
                binding, fresh_until = await self.journal.refresh()
                if not self.journal.current(envelope, binding):
                    raise Denied("finding is absent from current witnessed history or withdrawn")
                self.journal_binding = binding
                self.journal_deadline = int(fresh_until * 1e9)
                deadline = min(deadline, int(fresh_until * 1e9))
                await self.lease.ensure()
        prior = self.agent.audit.get(str(envelope.finding.artifact_id))
        exact_digest = digest(canonical_bytes(envelope.finding))
        if ((prior is None and self.journal is None)
                or (prior is not None and prior.digest != exact_digest)):
            raise Denied("the exact delivered finding has no local audit")
        decision = self.agent.evaluate(envelope)
        if decision.outcome != "allow_dry_run" or decision.digest != exact_digest:
            raise Denied(f"Rapid denied the finding: {decision.reason_code}")
        return deadline


class EvidenceGate:
    """Join immutable evidence and per-deployment Rapid appraisal at the writer."""

    def __init__(self, envelope, bundle, assessment, receiver, collector, evidence):
        self.envelope = envelope
        self.bundle = bundle
        self.receiver = receiver
        self.journal = getattr(receiver, "journal", None)
        self._current_checkpoint = None
        self._plan_checkpoint = None
        self._journal_deadline = None
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
        self._binding_context = {
            "agent_id": receiver.agent.audit.agent_id,
            "finding_id": str(envelope.finding.artifact_id),
            "finding_sha256": digest(canonical_bytes(envelope.finding)),
            "bundle_sha256": bundle.sha256,
            "attestation_sha256": self.attestations,
        }
        publisher = receiver.agent.trust.grants[(envelope.finding.publisher_id, envelope.key_id)]
        expiry = min(envelope.finding.expires_at.timestamp(), publisher.expires_at.timestamp(),
                     *(decode(SignedAttestation, wire).body.expires_at for wire in local.attestations))
        if publisher.revoked_at is not None:
            expiry = min(expiry, publisher.revoked_at.timestamp())
        self.valid_until_ns = time.monotonic_ns() + int((expiry - time.time()) * 1e9)

    @property
    def binding_context(self):
        if self._plan_checkpoint is None:
            return self._binding_context.copy()
        return {**self._binding_context, "mesh_checkpoint_sha256": self._plan_checkpoint}

    @property
    def binding(self):
        return digest(json.dumps(self.binding_context, sort_keys=True).encode())

    def prepare(self, controller, lease_ms):
        with self._lock:
            if self.journal is not None:
                if (self._current_checkpoint is None or self._journal_deadline is None
                        or not self.journal.current(self.envelope, self._current_checkpoint)):
                    raise Denied("witnessed status unavailable for plan review")
                context = {**self._binding_context, "mesh_checkpoint_sha256": self._current_checkpoint}
                binding = digest(json.dumps(context, sort_keys=True).encode())
                plan = controller.prepare(lease_ms, binding=binding,
                                          valid_until_ns=min(self.valid_until_ns, self._journal_deadline))
                self._plan_checkpoint = self._current_checkpoint
                return plan
            return controller.prepare(lease_ms, binding=self.binding, valid_until_ns=self.valid_until_ns)

    async def refresh(self):
        try:
            deadline = await self.receiver.fresh(self.envelope)
        except (Exception, asyncio.CancelledError):
            with self._lock:
                self._fresh_until = 0
            raise
        with self._lock:
            if self.journal is not None:
                self._current_checkpoint = self.receiver.journal_binding
                self._journal_deadline = self.receiver.journal_deadline
            self._fresh_until = deadline

    def status_current(self):
        # Called by the proxy while it holds a target transaction. Do not
        # acquire a lock here because guarded writers take the opposite order.
        return (time.monotonic_ns() < min(self._fresh_until, self.valid_until_ns)
                and (self.journal is None or (self._plan_checkpoint == self._current_checkpoint
                     and self.journal.current(self.envelope, self._plan_checkpoint))))

    @contextmanager
    def authorize(self, plan):
        with self._lock:
            guard = (self.journal.authorize(self.envelope, self._plan_checkpoint)
                     if self.journal is not None else nullcontext())
            with (guard, self.collector.current_assessment(self.bundle, cohort=COHORT) as current,
                  self.evidence.current_assessment(self.bundle, cohort=COHORT) as local):
                if (current.outcome != "reproduced" or local.outcome != "reproduced"
                        or attestations_digest(current) != self.attestations
                        or attestations_digest(local) != self.attestations):
                    self._fresh_until = 0
                    raise Denied(f"evidence or Mesh status is not current ({current.reason}, {local.reason})")
                deadline = self.valid_until_ns
                if self._journal_deadline is not None:
                    deadline = min(deadline, self._journal_deadline)
                if (plan.evidence_binding != self.binding or plan.expires_ns > deadline
                        or not self.status_current()):
                    raise Denied("exact plan binding or Mesh status is not current")
                yield self.binding_context


class VerifiedLab:
    """Drive explicit local stages. A control-plane event never invokes this class."""

    def __init__(self, gate: EvidenceGate, path: Path, *, identity: IdentitySession | None = None):
        self.gate = gate
        self.identity = identity
        if identity is not None and identity.assignment.deployment != gate.binding_context["agent_id"]:
            raise Denied("enrolled deployment does not match the Rapid audit owner")
        self.lab = Lab(path, authorize=gate.authorize, status_current=gate.status_current,
                       require_identity=identity is not None)

    async def prepare(self, lease_ms):
        await self.gate.refresh()
        plan = self.gate.prepare(self.lab.controller, lease_ms)
        if self.identity is None:
            return plan
        assignment = self.identity.assignment
        deadline = self.lab.store.ownership.check(assignment)
        return replace(plan, ownership_binding=assignment.binding, expires_ns=min(plan.expires_ns, deadline))

    async def transition(self, operation, plan, *args, action: Action | None = None,
                         target: str | None = None, **kwargs):
        await self.gate.refresh()
        if self.identity is not None:
            if action is None:
                raise Denied("identity-fenced transition requires an explicit action")
            kwargs["command"] = self.identity.command(action, plan.digest, target)
        worker = asyncio.create_task(asyncio.to_thread(operation, plan, *args, **kwargs))
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
            await self.transition(self.lab.controller.start, plan, approval, action="begin")
            preflight = time.monotonic_ns()
            await self.transition(self.lab.controller.restrict, plan, approval, plan.targets[0],
                                  action="restrict", target=plan.targets[0])
            await self.transition(self.lab.controller.verify, plan, canary=True, action="verify-canary")
            canary = time.monotonic_ns()
            for target in plan.targets[1:]:
                await self.transition(self.lab.controller.restrict, plan, approval, target,
                                      action="restrict", target=target)
            expanded = time.monotonic_ns()
            await self.transition(self.lab.controller.verify, plan, action="verify-health")
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
                await self.transition(self.lab.controller.verify, plan, action="verify-health")
        except Exception:
            return await asyncio.to_thread(self.lab.controller.rollback, "lease, evidence, or health lost")
