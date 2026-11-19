"""Locally pinned publisher grants; an event cannot update these grants."""

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@dataclass(frozen=True)
class PublisherGrant:
    publisher_id: str
    key_id: str
    public_key: Ed25519PublicKey
    roles: frozenset[Literal["finding", "revocation"]]
    not_before: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    revocation_publishers: frozenset[str] | None = None

    def __post_init__(self):
        if self.not_before.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("grant timestamps require timezone")
        if self.expires_at <= self.not_before:
            raise ValueError("invalid grant interval")
        if self.revoked_at is not None and self.revoked_at.tzinfo is None:
            raise ValueError("revocation timestamp requires timezone")
        if not self.roles or not self.roles <= {"finding", "revocation"}:
            raise ValueError("invalid grant roles")
        if self.revocation_publishers is None:
            object.__setattr__(self, "revocation_publishers",
                           frozenset({self.publisher_id}) if "revocation" in self.roles else frozenset())
        if any(not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", publisher)
               for publisher in self.revocation_publishers):
            raise ValueError("invalid revocation publisher scope")
        if "revocation" not in self.roles and self.revocation_publishers:
            raise ValueError("revocation scope requires revocation role")


class TrustStore:
    def __init__(self, grants: list[PublisherGrant]):
        self.grants = {(g.publisher_id, g.key_id): g for g in grants}
        if len(self.grants) != len(grants):
            raise ValueError("duplicate publisher key ID")

    @classmethod
    def from_legacy(cls, keys: dict[str, Ed25519PublicKey]):
        return cls([
            PublisherGrant(publisher, "default", key, frozenset({"finding"}),
                           datetime(1970, 1, 1, tzinfo=timezone.utc),
                           datetime(9999, 1, 1, tzinfo=timezone.utc))
            for publisher, key in keys.items()
        ])

    def authorize(self, publisher_id: str, key_id: str, role: str, now: datetime | None = None) -> Ed25519PublicKey:
        now = now or datetime.now(timezone.utc)
        grant = self.grants.get((publisher_id, key_id))
        if grant is None:
            raise ValueError("unknown publisher key")
        if role not in grant.roles:
            raise ValueError("publisher key lacks role")
        if now < grant.not_before or now >= grant.expires_at:
            raise ValueError("publisher key outside validity interval")
        if grant.revoked_at is not None and now >= grant.revoked_at:
            raise ValueError("publisher key revoked")
        return grant.public_key

    def authorize_revocation(self, publisher_id: str, key_id: str,
                             target_publisher_id: str, now: datetime | None = None) -> Ed25519PublicKey:
        key = self.authorize(publisher_id, key_id, "revocation", now)
        if target_publisher_id not in self.grants[(publisher_id, key_id)].revocation_publishers:
            raise ValueError("revocation target publisher outside grant scope")
        return key
