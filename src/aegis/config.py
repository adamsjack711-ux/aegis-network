"""Local trust configuration. Public keys never arrive in event payloads."""

import json
from pathlib import Path

from .core import InventoryItem, LocalPolicy
from .publisher_config import load_publishers


def load_local(path: str) -> tuple[LocalPolicy, list[InventoryItem]]:
    raw = json.loads(Path(path).read_text())
    policy = LocalPolicy(
        trusted_publishers=load_publishers(raw["publishers_file"]),
        allowed_templates=frozenset(raw["allowed_templates"]),
        lab_authorized=raw["lab_authorized"] is True,
    )
    inventory = [InventoryItem(**item) for item in raw["inventory"]]
    return policy, inventory
