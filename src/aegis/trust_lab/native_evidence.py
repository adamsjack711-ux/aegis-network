"""Native Evidence status appraisal for separately enrolled disposable fixtures."""

from collections.abc import Callable
from dataclasses import dataclass
import time

from aegis.evidence.records import digest
from aegis.evidence.runner import ENVIRONMENT_SHA256
from aegis.evidence.status import RelyingStatus, StatusProof
from aegis.mitigation.policy import Denied
from aegis.phase3c import claim_bytes, check_bundle


@dataclass(frozen=True)
class TimedStatus:
    binding: str
    expires_ns: int
    expires_at: int

    def current(self) -> bool:
        return time.monotonic_ns() < self.expires_ns and time.time() < self.expires_at


@dataclass(frozen=True)
class NativeEvidenceStatus:
    """Appraise the locally enrolled native fixture and require an exact audience."""

    reader: RelyingStatus
    fetch: Callable[[bytes], StatusProof]

    def require(self, finding, bundle, audience: str) -> TimedStatus:
        check_bundle(finding, bundle)
        status = self.reader.evaluate(bundle, expected_bundle_sha256=finding.evidence[0].sha256,
                                      expected_claim_sha256=digest(claim_bytes(finding)),
                                      expected_environment_sha256=ENVIRONMENT_SHA256, fetch=self.fetch)
        if status.outcome != "reproduced" or status.binding is None or status.valid_until is None:
            raise Denied(f"independent Evidence status denied ({status.reason})")
        if status.binding.audience != audience:
            raise Denied("independent Evidence status audience differs from the local deployment")
        sampled_ns = time.monotonic_ns()
        remaining_ns = int((status.valid_until - time.time()) * 1e9)
        if remaining_ns <= 0:
            raise Denied("independent Evidence status expired")
        return TimedStatus(status.binding_sha256, sampled_ns + remaining_ns, status.valid_until)
