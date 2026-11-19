"""Scoped Ed25519 credentials and a pinned, versioned delegation chain."""

from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field

from aegis.evidence.records import canonical, digest


class Hold(ValueError):
    """A required condition could not be established."""


Name = Annotated[str, Field(pattern=r"^[a-zA-Z0-9._-]{1,80}$")]
Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Tick = Annotated[int, Field(ge=0)]
Role = Literal["publisher", "verifier", "revoker", "agent", "witness", "status", "operator"]


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Signature(Record):
    key: Name
    value: Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]


def commitment(record):
    return digest(canonical(record))


def signing_bytes(domain, record):
    return b"AEGIS-TRUST-LAB/v1\x00" + domain.encode("ascii") + b"\x00" + canonical(record)


def sign(key_id, key, domain, record):
    return Signature(key=key_id, value=key.sign(signing_bytes(domain, record)).hex())


def verify(key, signature, domain, record):
    try:
        key.verify(bytes.fromhex(signature.value), signing_bytes(domain, record))
    except InvalidSignature as exc:
        raise Hold("invalid signature") from exc


def quorum(signatures, domain, record, keys, threshold):
    if not threshold <= len(signatures) <= len(keys):
        raise Hold("missing quorum")
    seen = set()
    for signature in signatures:
        if signature.key in seen or signature.key not in keys:
            raise Hold("duplicate or unauthorized quorum signer")
        verify(keys[signature.key], signature, domain, record)
        seen.add(signature.key)


class Grant(Record):
    key: Name
    public_key: Hash
    role: Role
    organization: Name
    scope: Name
    starts: Tick
    ends: Tick


class Compromise(Record):
    key: Name
    cutoff: Tick


class Delegations(Record):
    scope: Name
    version: Annotated[int, Field(ge=1)]
    previous: Hash | None
    starts: Tick
    ends: Tick
    grants: tuple[Grant, ...]
    compromises: tuple[Compromise, ...] = ()


class SignedDelegations(Record):
    body: Delegations
    signatures: tuple[Signature, ...]


class Root:
    """Out-of-band pins for one cohort. Membership changes need a new protocol."""

    def __init__(self, scope, keys):
        self.scope = scope
        self.keys = dict(keys)
        if len(self.keys) != 3 or len({k.public_bytes_raw() for k in keys.values()}) != 3:
            raise ValueError("three distinct pinned root keys required")

    def appraise(self, chain, now):
        versions = {}
        predecessor = None
        first_witnesses = None
        known_grants = {}
        cuts = {}
        key_roles = {}
        for signed in chain:
            body = signed.body
            quorum(signed.signatures, "delegations", body, self.keys, 2)
            if (body.scope != self.scope or body.version != len(versions) + 1
                    or body.previous != (commitment(predecessor) if predecessor else None)
                    or not body.starts <= now or body.ends <= body.starts
                    or (predecessor and body.starts <= predecessor.starts)):
                raise Hold("invalid delegation chain")
            grants = {g.key: g for g in body.grants}
            if len(grants) != len(body.grants):
                raise Hold("duplicate delegation")
            for grant in body.grants:
                if (grant.scope != self.scope or grant.starts >= grant.ends
                        or bytes.fromhex(grant.public_key) in {k.public_bytes_raw() for k in self.keys.values()}
                        or key_roles.setdefault(grant.public_key, grant.key) != grant.key
                        or known_grants.setdefault(grant.key, grant) != grant):
                    raise Hold("invalid or rebound delegation")
            witnesses = tuple(sorted(g.key for g in body.grants if g.role == "witness"))
            if first_witnesses is None:
                first_witnesses = witnesses
            if (witnesses != first_witnesses or len(witnesses) != 4
                    or len({grants[k].organization for k in witnesses}) != 4):
                raise Hold("four fixed independent witness identities required")
            new_cuts = {cut.key: cut.cutoff for cut in body.compromises}
            if (len(new_cuts) != len(body.compromises) or any(k in witnesses or k not in known_grants for k in new_cuts)
                    or any(new_cuts.get(k, at + 1) > at for k, at in cuts.items())):
                raise Hold("invalid compromise lifecycle")
            cuts = new_cuts
            versions[commitment(body)] = (body, grants)
            predecessor = body
        if predecessor is None or not now < predecessor.ends:
            raise Hold("delegated trust metadata is missing or expired")
        return Trust(versions, predecessor, cuts)


class Trust:
    def __init__(self, versions, current, cuts):
        self.versions = versions
        self.current = current
        self.cuts = cuts
        self.head = commitment(current)

    def grant(self, key, role, at, version=None):
        body, grants = self.versions.get(version or self.head, (None, {}))
        grant = grants.get(key)
        if (grant is None or grant.role != role or not body.starts <= at < body.ends
                or not grant.starts <= at < grant.ends):
            raise Hold("key lacks current scoped role")
        return grant

    def authenticate(self, signature, domain, record, role, at, version=None):
        grant = self.grant(signature.key, role, at, version)
        if version is None and at >= self.cuts.get(grant.key, grant.ends):
            raise Hold("key is compromised")
        verify(Ed25519PublicKey.from_public_bytes(bytes.fromhex(grant.public_key)), signature, domain, record)
        return grant

    def witnesses(self, at, version=None):
        body, grants = self.versions.get(version or self.head, (None, {}))
        if body is None:
            raise Hold("unknown witness metadata")
        return {
            g.key: Ed25519PublicKey.from_public_bytes(bytes.fromhex(g.public_key))
            for g in grants.values()
            if g.role == "witness" and g.starts <= at < g.ends and body.starts <= at < body.ends
        }
