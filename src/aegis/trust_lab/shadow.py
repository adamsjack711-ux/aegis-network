"""Compare native lab appraisal and the restricted prototype without handing off authority."""

from dataclasses import dataclass

from aegis.mitigation.policy import Denied

from .history import Subject


@dataclass(frozen=True)
class ShadowAgreement:
    """A comparison record, deliberately carrying neither plan nor capability."""

    deployment: str
    native_binding: str
    finding: str
    evidence: str
    checkpoint: str
    status: str


async def compare(gate, native_plan, evaluator, holder_proof, cut, signed_status, chain):
    """Reconcile both ledgers against one exact subject without requesting a target write."""
    try:
        await gate.refresh()
        with gate.authorize(native_plan) as native:
            subject = Subject(finding=native["finding_sha256"], evidence=native["bundle_sha256"])
            deployment = native["agent_id"]
        if evaluator.target.deployment != deployment:
            raise Denied("shadow deployment differs from the native local audit")
        modeled = evaluator.reconcile(holder_proof, cut, signed_status, chain, subject, "restrict")
        return ShadowAgreement(deployment, native_plan.evidence_binding, subject.finding,
                               subject.evidence, modeled.checkpoint, modeled.status)
    finally:
        # The prototype can prepare a challenge only inside the synthetic lab.
        # Do not leave a potentially consumable operation behind after comparison.
        evaluator.disconnect()
