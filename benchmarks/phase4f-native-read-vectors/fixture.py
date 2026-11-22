"""Synthetic-only key material and source records adapted from the 4F preclaim fixture."""

from datetime import datetime, timezone
from types import MappingProxyType
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.artifact import Evidence, Finding, Revocation, Software, canonical_bytes, sign, sign_revocation
from aegis.evidence import Bundle, Grant, Trust
from aegis.evidence._worker import materials
from aegis.evidence.records import Manifest, Materials, ObjectPin, Withdrawal, digest, sign_record
from aegis.evidence.runner import CHECK_SHA256, ENVIRONMENT_SHA256, ORACLE_SHA256
from aegis.evidence.status_protocol import StatusPolicy, WitnessGrant, material_scope
from aegis.journal.protocol import Policy, canonical
from aegis.phase3c import COHORT, MESH_TEMPLATE, PACKAGE, REFERENCE, VERSION, claim_bytes
from aegis.trust import PublisherGrant, TrustStore


NOW = 1_800_000_000
ADMISSION = (NOW - 30, NOW - 29)
T4 = ("mesh-a", "mesh-b", "mesh-c", "mesh-d")
T5 = ("status-a", "status-b")
ROUTE = ("route-toggle", "marker-on", "observer-ready")
TARGET_ID = UUID("00000000-0000-4000-8000-000000000040")
EVENT_ID = UUID("00000000-0000-4000-8000-000000000041")


def timestamp(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc)


def fixture_key(name):
    # Public, deterministic test material. These keys have no runtime authority.
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(digest(b"4F-fixture-only\0" + name.encode())))



class FrozenAuthority:
    def __init__(self):
        finder, revoker = fixture_key("fixture-finder"), fixture_key("fixture-revoker")
        self.t4 = Policy(
            "fixture-history", COHORT, fixture_key("mesh-coordinator").public_key(),
            {name: fixture_key(name).public_key() for name in T4}, 3, 1, 60, 3, 60,
            TrustStore([
                PublisherGrant("finder", "fixture", finder.public_key(), frozenset({"finding"}),
                               timestamp(NOW - 300), timestamp(NOW + 60)),
                # This key has ordinarily expired by appraisal. Historical scope is checked at admission.
                PublisherGrant("revoker", "fixture", revoker.public_key(), frozenset({"revocation"}),
                               timestamp(NOW - 100), timestamp(NOW - 10),
                               revocation_publishers=frozenset({"finder"})),
            ]),
        )
        cohort = frozenset({COHORT})
        trust = Trust([
            Grant(name, "fixture", name + "-operator", role, fixture_key(name).public_key(), cohort, NOW - 60,
                  NOW + 60, frozenset({"research"}) if role == "revoker" else frozenset(),
                  frozenset({"bundle"}) if role == "revoker" else frozenset())
            for name, role in (("research", "submitter"), ("review", "revoker"),
                               ("verify-a", "verifier"), ("verify-b", "verifier"))
        ])
        self.t5 = StatusPolicy("fixture-status", COHORT, "mesh-coordinator-org", "agent-local-org", trust, tuple(
            WitnessGrant(name, name + "-operator", fixture_key(name).public_key()) for name in T5
        ))
        self.anchor = MappingProxyType({"independent-anchor": fixture_key("independent-anchor").public_key()})
        self.evidence_roster = MappingProxyType({w.witness_id: w.public_key for w in self.t5.witnesses})
        finding = Finding(
            schema_version="1.0", artifact_id=TARGET_ID, publisher_id="finder", sequence=1,
            issued_at=timestamp(NOW - 55), expires_at=timestamp(NOW + 60), vulnerability_id="FIXTURE-4F",
            software=Software(purl=PACKAGE, affected_versions=[VERSION]), applicability="authorized-lab",
            mitigation_template=MESH_TEMPLATE, evidence=[Evidence(uri="urn:fixture:unbound", sha256="0" * 64,
                                                                  method="lab-reproduction")],
        )
        self.objects = MappingProxyType(materials(*ROUTE))
        manifest = Manifest(
            kind="aegis.evidence.bundle.v1", record_id="10" * 16, issuer="research", key_id="fixture",
            cohort=COHORT, issued_at=NOW - 50, expires_at=NOW + 50, claim_sha256=digest(claim_bytes(finding)),
            family=ROUTE[0], materials=Materials(**{
                label: ObjectPin(sha256=digest(raw), size=len(raw)) for label, raw in self.objects.items()
            }), environment_sha256=ENVIRONMENT_SHA256, check_sha256=CHECK_SHA256, oracle_sha256=ORACLE_SHA256,
        )
        self.manifest_wire = sign_record(manifest, fixture_key("research"))
        bundle_pin = digest(self.manifest_wire)
        self.bundle = Bundle(bundle_pin, self.manifest_wire, dict(self.objects))
        finding = finding.model_copy(update={"evidence": [
            Evidence(uri=REFERENCE + bundle_pin, sha256=bundle_pin, method="lab-reproduction")
        ]})
        self.finding_wire = canonical(sign(finding, finder, "fixture"))
        self.target = ("finder", str(TARGET_ID), digest(canonical_bytes(finding)))
        withdrawal = Revocation(
            schema_version="1.1", revocation_id=EVENT_ID, publisher_id="revoker", sequence=1,
            target_publisher_id=self.target[0], target_artifact_id=TARGET_ID, target_sha256=self.target[2],
            issued_at=timestamp(NOW - 35), expires_at=timestamp(NOW + 60), reason="withdrawn",
        )
        self.mesh_wire = canonical(sign_revocation(withdrawal, revoker, "fixture"))
        self.conflicting_wire = canonical(sign_revocation(
            withdrawal.model_copy(update={"reason": "superseded"}), revoker, "fixture",
        ))
        self.evidence_withdrawal = sign_record(Withdrawal(
            kind="aegis.evidence.withdrawal.v1", record_id="20" * 16, issuer="review", key_id="fixture",
            cohort=COHORT, issued_at=NOW - 3, expires_at=NOW + 20, target_kind="bundle", target_sha256=bundle_pin,
            target_issuer="research", reason="withdrawn",
        ), fixture_key("review"))
        grant = self.t4.trust.grants[("revoker", "fixture")]
        grant_pin = digest(canonical([grant.publisher_id, grant.key_id, grant.public_key.public_bytes_raw().hex(),
                                      sorted(grant.roles), sorted(grant.revocation_publishers),
                                      grant.not_before.isoformat(), grant.expires_at.isoformat(), grant.revoked_at]))
        self.scope = MappingProxyType({
            "finding_body_sha256": self.target[2], "manifest_wire_sha256": bundle_pin,
            "claim_sha256": digest(claim_bytes(finding)), "material_scope_sha256": material_scope(manifest),
            "environment_sha256": manifest.environment_sha256, "withdrawal_wire_sha256": digest(self.mesh_wire),
            "withdrawal_body_sha256": digest(canonical_bytes(withdrawal)),
        })
        self.admission = MappingProxyType({
            "context": self.t4.context, "wire_sha256": self.scope["withdrawal_wire_sha256"],
            "grant_sha256": grant_pin, "interval": ADMISSION, "target": self.target,
        })
