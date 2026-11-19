"""Closed template, inventory, and process-local operator authority."""

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import secrets
import time


TEMPLATE = "restrict-fixture-route/v1"
TARGETS = ("canary", "replica-a", "replica-b")
MARKER_PATH = "/fixture-marker"
BENIGN_PATHS = ("/health", "/ok")
PATHS = (MARKER_PATH, *BENIGN_PATHS)
OBSERVATION_WINDOW_NS = 20_000_000
EVIDENCE_MAX_AGE_NS = 750_000_000
APPROVAL_WINDOW_NS = 30_000_000_000
MAX_LEASE_MS = 30_000
MIN_LEASE_MS = 250


class Denied(RuntimeError):
    """The requested transition failed a local safety gate."""


@dataclass(frozen=True)
class Plan:
    lab_id: str
    nonce: str
    template: str
    path: str
    targets: tuple[str, ...]
    expected_fences: tuple[int, ...]
    lease_ms: int
    expires_ns: int

    @property
    def digest(self) -> str:
        encoded = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode()).hexdigest()

    def validate(self, lab_id: str, now: int) -> None:
        if (
            self.lab_id != lab_id
            or self.template != TEMPLATE
            or self.path != MARKER_PATH
            or self.targets != TARGETS
            or len(self.expected_fences) != len(TARGETS)
            or any(type(fence) is not int or fence < 0 for fence in self.expected_fences)
            or type(self.lease_ms) is not int
            or not MIN_LEASE_MS <= self.lease_ms <= MAX_LEASE_MS
            or not now < self.expires_ns <= now + APPROVAL_WINDOW_NS
        ):
            raise Denied("plan outside the enrolled template or validity window")


@dataclass(frozen=True)
class Approval:
    plan_digest: str
    expires_ns: int
    token: str


class LocalOperator:
    """Mint and verify domain-separated capabilities within one lab process."""

    def __init__(self) -> None:
        self._key = secrets.token_bytes(32)

    def _token(self, plan: Plan, expiry: int, purpose: str, target: str = "") -> str:
        message = json.dumps([purpose, plan.digest, expiry, target]).encode()
        return hmac.digest(self._key, message, "sha256").hex()

    def approve(self, plan: Plan, reviewed_digest: str) -> Approval:
        now = time.monotonic_ns()
        plan.validate(plan.lab_id, now)
        if reviewed_digest != plan.digest:
            raise Denied("operator must approve the exact reviewed plan")
        return Approval(plan.digest, plan.expires_ns, self._token(plan, plan.expires_ns, "start"))

    def check(self, plan: Plan, approval: Approval, now: int) -> None:
        if (
            approval.plan_digest != plan.digest
            or not now < approval.expires_ns <= plan.expires_ns
            or not hmac.compare_digest(approval.token, self._token(plan, approval.expires_ns, "start"))
        ):
            raise Denied("invalid or expired local approval")

    def grant(self, plan: Plan, approval: Approval, target: str) -> str:
        self.check(plan, approval, time.monotonic_ns())
        if target not in plan.targets:
            raise Denied("target outside approved plan")
        return self._token(plan, approval.expires_ns, "restrict", target)

    def check_grant(self, plan: Plan, approval: Approval, target: str, grant: str, now: int) -> None:
        self.check(plan, approval, now)
        if target not in plan.targets or not hmac.compare_digest(
            grant, self._token(plan, approval.expires_ns, "restrict", target)
        ):
            raise Denied("capability does not cover this target")
