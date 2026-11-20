"""Local trust configuration. Public keys never arrive in event payloads."""

import base64
import json
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .core import InventoryItem, LocalPolicy
from .trust import PublisherGrant, TrustStore


def load_publishers(path: str) -> TrustStore:
    raw = json.loads(Path(path).read_text())
    return _parse_publishers(raw)


def load_publishers_bytes(data: bytes) -> TrustStore:
    """Parse a bounded descriptor snapshot without reopening its pathname."""
    return _parse_publishers(json.loads(data.decode("utf-8")))


def _parse_publishers(raw: object) -> TrustStore:
    if "grants" not in raw:
        return TrustStore.from_legacy({
            publisher_id: Ed25519PublicKey.from_public_bytes(base64.b64decode(value, validate=True))
            for publisher_id, value in raw.items()
        })
    grants = []
    for entry in raw["grants"]:
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


def load_local(path: str) -> tuple[LocalPolicy, list[InventoryItem]]:
    raw = json.loads(Path(path).read_text())
    policy = LocalPolicy(
        trusted_publishers=load_publishers(raw["publishers_file"]),
        allowed_templates=frozenset(raw["allowed_templates"]),
        lab_authorized=raw["lab_authorized"] is True,
    )
    inventory = [InventoryItem(**item) for item in raw["inventory"]]
    return policy, inventory
