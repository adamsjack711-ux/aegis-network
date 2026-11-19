"""Ephemeral enrolled lab fixtures for the offline tests and benchmark."""

import time
from dataclasses import dataclass
from uuid import NAMESPACE_OID, uuid5

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import Bundle, Grant, Trust, Verifier
from ._worker import materials
from .records import Manifest, Materials, ObjectPin, digest, sign_record
from .runner import CHECK_SHA256, ENVIRONMENT_SHA256, ORACLE_SHA256


@dataclass(frozen=True)
class Lab:
    trust: Trust
    submitter: Ed25519PrivateKey
    revoker: Ed25519PrivateKey
    verifiers: tuple[Verifier, ...]
    now: int

    def bundle(self, claim: str, *, family="feature-gate", marker=True, observer=True, cohort="lab-blue") -> Bundle:
        objects = materials(family, "marker-on" if marker else "marker-off",
                            "observer-ready" if observer else "observer-offline")
        claim_digest = digest(claim.encode("utf-8"))
        manifest = Manifest(
            kind="aegis.evidence.bundle.v1", record_id=uuid5(NAMESPACE_OID, repr((
                claim_digest, family, marker, observer, cohort, self.now,
            ))).hex,
            issuer="research", key_id="lab-v1", cohort=cohort, issued_at=self.now, expires_at=self.now + 3600,
            claim_sha256=claim_digest, family=family, materials=Materials(**{
                role: ObjectPin(sha256=digest(data), size=len(data)) for role, data in objects.items()
            }),
            environment_sha256=ENVIRONMENT_SHA256, check_sha256=CHECK_SHA256, oracle_sha256=ORACLE_SHA256,
        )
        signed = sign_record(manifest, self.submitter)
        return Bundle(digest(signed), signed, objects)


def create_lab(now: int | None = None) -> Lab:
    now = int(time.time()) if now is None else now
    submitter = Ed25519PrivateKey.generate()
    revoker = Ed25519PrivateKey.generate()
    verifiers = tuple(Verifier(f"verifier-{name}", "lab-v1", Ed25519PrivateKey.generate()) for name in ("a", "b"))
    cohorts = frozenset({"lab-blue", "lab-green"})
    grants = [
        Grant("research", "lab-v1", "research-org", "submitter", submitter.public_key(), cohorts, now, now + 7200),
        Grant("review", "lab-v1", "review-org", "revoker", revoker.public_key(), cohorts, now, now + 7200,
              frozenset({"research", "verifier-a", "verifier-b"}), frozenset({"bundle", "attestation", "verifier-key"})),
        *(Grant(v.issuer, v.key_id, v.issuer, "verifier", v.private_key.public_key(), cohorts, now, now + 7200)
          for v in verifiers),
    ]
    return Lab(Trust(grants), submitter, revoker, verifiers, now)
