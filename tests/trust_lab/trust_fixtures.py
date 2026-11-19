"""Ephemeral keys, independent witness stores, and controlled clocks."""

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.evidence.records import digest
from aegis.trust_lab.evaluator import Evaluator, LabTarget
from aegis.trust_lab.history import (
    Coverage, Cut, EvidenceAuthority, Event, Leaf, SignedEvent, SignedStatus, Subject, Witness, checkpoint, status_for,
)
from aegis.trust_lab.identity import Delegations, Grant, Hold, Root, SignedDelegations, commitment, sign

DEPLOYMENT = "fd67458b-2c49-4cf8-a6a2-3e34d4c8629b"
SCOPE = "synthetic-blue"
WITNESSES = ("w0", "w1", "w2", "w3")


class Clock:
    def __init__(self):
        self.tick = 100
        self.ns = 0

    def wall(self):
        return self.tick

    def monotonic(self):
        return self.ns

    def advance(self, seconds=1):
        self.tick += seconds
        self.ns += seconds * 1_000_000_000


class Scenario:
    def __init__(self, path: Path):
        self.path = path
        self.clock = Clock()
        self.keys = {}
        self.grants = []
        self.chain = ()
        self.leaves = ()
        self.subject = Subject(finding=digest(b"fixture-finding"), evidence=digest(b"fixture-evidence"))
        self.root_keys = ("root0", "root1", "root2")
        for root in self.root_keys:
            self.keys[root] = Ed25519PrivateKey.generate()
        self.root = Root(SCOPE, {key: self.keys[key].public_key() for key in self.root_keys})
        roles = {
            "publisher": "publisher", "verifier1": "verifier", "verifier2": "verifier",
            "revoker": "revoker", "agent-a": "agent", "agent-b": "agent",
            "status": "status", "operator": "operator",
            **dict.fromkeys(WITNESSES, "witness"),
        }
        for key, role in roles.items():
            self.add_key(key, role)
        self.rotate(starts=90)
        self.witnesses = {
            name: Witness.provision(path / f"{name}.sqlite", name, self.keys[name], self.root, self.clock)
            for name in WITNESSES
        }
        self.target = LabTarget.provision(
            path / "target.sqlite", path / "external-anchor.sqlite", self.root,
            DEPLOYMENT, {"agent-a": ("east", "west"), "agent-b": ("west",)}, clock=self.clock,
        )
        self.target.transfer(expected=0, holder="agent-a", broker="east", chain=self.chain)
        self.evaluator = Evaluator(self.target, "operator")
        self.status_authority = EvidenceAuthority("status", self.keys["status"], self.root, self.clock)

    def add_key(self, key, role, *, organization=None, starts=90, ends=200):
        self.keys[key] = private = Ed25519PrivateKey.generate()
        self.grants.append(Grant(key=key, public_key=private.public_key().public_bytes_raw().hex(),
                                 role=role, organization=organization or key, scope=SCOPE,
                                 starts=starts, ends=ends))

    def rotate(self, *, starts=None, compromises=(), signers=("root0", "root1")):
        previous = commitment(self.chain[-1].body) if self.chain else None
        body = Delegations(scope=SCOPE, version=len(self.chain) + 1, previous=previous,
                           starts=self.clock.wall() if starts is None else starts, ends=180,
                           grants=tuple(self.grants), compromises=compromises)
        metadata = SignedDelegations(body=body, signatures=tuple(self.sign(k, "delegations", body) for k in signers))
        self.chain += (metadata,)

    @property
    def trust(self):
        return self.root.appraise(self.chain, self.clock.wall())

    def sign(self, key, domain, body):
        return sign(key, self.keys[key], domain, body)

    def event(self, id_, kind, key, *, subject=None, expires=150, issued=None):
        body = Event(scope=SCOPE, id=id_, kind=kind, subject=subject or self.subject,
                     issued=self.clock.wall() if issued is None else issued, expires=expires)
        return SignedEvent(body=body, signature=self.sign(key, "event", body))

    def admit(self, event, signers=("w0", "w1", "w2"), *, remember=True):
        receipts = [self.witnesses[key].admit(event, self.chain) for key in signers]
        assert len({commitment(receipt) for receipt, _ in receipts}) == 1
        leaf = Leaf(body=receipts[0][0], event=event, signatures=tuple(signature for _, signature in receipts))
        if remember:
            self.leaves += (leaf,)
        return leaf

    def seed(self, *, expires=150):
        self.admit(self.event("finding", "finding", "publisher", expires=expires))
        for verifier in ("verifier1", "verifier2"):
            self.admit(self.event(verifier, "corroboration", verifier, expires=expires))
        self.clock.advance()

    def cut(self, challenge, *, leaves=None, signers=WITNESSES):
        leaves = self.leaves if leaves is None else leaves
        head = checkpoint(self.trust, self.clock.wall() - 1, leaves)
        body = Coverage(checkpoint=head, nonce=challenge.nonce)
        signatures = []
        for key in signers:
            try:
                signatures.append(self.witnesses[key].endorse(body, leaves, self.chain))
            except Hold:
                continue
        return Cut(body=body, signatures=tuple(signatures), leaves=leaves)

    def status(self, cut, *, subject=None, key="status"):
        if key == "status":
            return self.status_authority.issue(cut, self.chain, subject or self.subject)
        body = status_for(cut.body.checkpoint, cut.leaves, subject or self.subject,
                          self.trust, self.clock.wall(), cut.body.nonce)
        return SignedStatus(body=body, signature=self.sign(key, "status", body))

    def begin(self, evaluator=None, *, holder="agent-a", broker="east"):
        return (evaluator or self.evaluator).begin(holder=holder, broker=broker)

    def reconcile(self, challenge, cut, *, status=None, evaluator=None, operation="restrict", chain=None):
        return (evaluator or self.evaluator).reconcile(
            self.sign(challenge.holder, "agent-proof", challenge), cut, status,
            self.chain if chain is None else chain, self.subject, operation,
        )

    def prepare(self, evaluator=None, *, holder="agent-a", broker="east", operation="restrict"):
        challenge = self.begin(evaluator, holder=holder, broker=broker)
        cut = self.cut(challenge)
        return self.reconcile(challenge, cut, status=self.status(cut), evaluator=evaluator, operation=operation)

    def approve(self, plan):
        return self.sign("operator", "approval", plan)

    def apply(self, plan, evaluator=None):
        return (evaluator or self.evaluator).apply(plan, self.approve(plan))
