"""Local publisher grants for the observation CLI without Rapid imports.

This is a private reader of the existing publisher-grant file. The security
checks remain in TrustStore; this module does not create or change grants.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .local_observer import _read_bounded
from .trust import PublisherGrant, TrustStore


def load_observer_publishers(path: Path) -> TrustStore:
    """Read the existing config.load_publishers format without importing core."""
    raw = json.loads(_read_bounded(path, 1024 * 1024))
    if not isinstance(raw, dict):
        raise ValueError("publisher grants must be an object")
    if "grants" not in raw:
        return TrustStore.from_legacy({
            publisher_id: Ed25519PublicKey.from_public_bytes(base64.b64decode(value, validate=True))
            for publisher_id, value in raw.items()
        })
    if not isinstance(raw["grants"], list):
        raise ValueError("publisher grants must be a list")
    grants = []
    for entry in raw["grants"]:
        if not isinstance(entry, dict):
            raise ValueError("publisher grant must be an object")
        required = {"publisher_id", "key_id", "public_key", "roles", "not_before", "expires_at", "revoked_at"}
        if not required <= set(entry) or set(entry) - required - {"revocation_publishers"}:
            raise ValueError("invalid publisher grant fields")
        grants.append(PublisherGrant(
            publisher_id=entry["publisher_id"],
            key_id=entry["key_id"],
            public_key=Ed25519PublicKey.from_public_bytes(base64.b64decode(entry["public_key"], validate=True)),
            roles=frozenset(entry["roles"]),
            not_before=datetime.fromisoformat(entry["not_before"]),
            expires_at=datetime.fromisoformat(entry["expires_at"]),
            revoked_at=datetime.fromisoformat(entry["revoked_at"]) if entry["revoked_at"] else None,
            revocation_publishers=frozenset(entry["revocation_publishers"])
            if "revocation_publishers" in entry else None,
        ))
    return TrustStore(grants)
