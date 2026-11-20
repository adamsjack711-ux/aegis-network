"""Mock research must remain inert even when it fabricates a cited positive."""

import json
from pathlib import Path
import socket
import subprocess

from aegis.intelligence.alpha_eval import OfflineBudget
from aegis.intelligence.phase5a1_eval import _load_v, _one_v, evaluate_phase5a1


ROOT = Path(__file__).resolve().parents[2]


class FabricatedPositive:
    def __init__(self, source_id: str):
        self.source_id = source_id

    def complete_json(self, _payload: bytes, *, budget: OfflineBudget) -> bytes:
        raw = json.dumps({
            "candidate_outcome": "affected",
            "point": "fabricated positive impact",
            "citations": [self.source_id],
            "support": "unchecked",
        }).encode()
        assert len(raw) <= budget.max_output_bytes
        return raw


def test_fabricated_positive_with_valid_source_id_is_not_reportable():
    case = next(case for case in _load_v(ROOT) if case["id"] == "V10-withdrawn")
    row = _one_v(ROOT, case, FabricatedPositive(case["sources"][0]["id"]),
                 OfflineBudget(), order="fixed", repeat=1)
    assert row["observed"] == "unknown"
    assert row["scripted_raw"] == "affected"
    assert row["scripted_checked"] == "unknown"
    assert row["point_attempted"] == 1 and row["point_emitted"] == 0
    assert row["raw_point"]["support"] == "unchecked"
    assert row["raw_point"]["reportable"] is False


def test_offline_evaluator_never_calls_socket_or_subprocess(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("offline evaluation attempted a network/process API")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    report = evaluate_phase5a1(ROOT)
    assert report["v_total"]["attempted"] == 72
    assert report["real_model"]["attempted_units"] == 0
