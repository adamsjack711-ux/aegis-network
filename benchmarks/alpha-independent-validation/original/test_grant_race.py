"""Retained failing reproduction; shared grant-loader change requires review."""

import json
from pathlib import Path

import pytest

import aegis.intelligence_adapter as adapter
from aegis.local_observer import ObservationError


@pytest.mark.xfail(strict=True, reason="trust stat/read race awaits shared grant parser compatibility review")
def test_grant_replacement_cannot_bypass_one_megabyte_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    feed = tmp_path / "mesh.json"
    feed.write_text(json.dumps({"adapter_version": "mesh-events-v1", "events": []}))
    trust = tmp_path / "trust.json"
    trust.write_text('{"grants":[]}')
    original = adapter.load_publishers

    def replace_after_stat(path: str):
        trust.write_text(json.dumps({"grants": [], "padding": "x" * (1024 * 1024)}))
        return original(path)

    monkeypatch.setattr(adapter, "load_publishers", replace_after_stat)
    with pytest.raises(ObservationError, match="limit"):
        adapter.load_intelligence(feed, trust_path=trust)
