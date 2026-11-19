"""Local trust configuration. Public keys never arrive in event payloads."""

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .core import InventoryItem, LocalPolicy


def load_publishers(path: str) -> dict[str, Ed25519PublicKey]:
    raw = json.loads(Path(path).read_text())
    return {
        publisher_id: Ed25519PublicKey.from_public_bytes(base64.b64decode(value, validate=True))
        for publisher_id, value in raw.items()
    }


def load_local(path: str) -> tuple[LocalPolicy, list[InventoryItem]]:
    raw = json.loads(Path(path).read_text())
    policy = LocalPolicy(
        trusted_publishers=load_publishers(raw["publishers_file"]),
        allowed_templates=frozenset(raw["allowed_templates"]),
        lab_authorized=raw["lab_authorized"] is True,
    )
    inventory = [InventoryItem(**item) for item in raw["inventory"]]
    return policy, inventory
