"""Private CLI serialization regression controls; no authority-bearing code."""

import io
import json
import sys
import time

import pytest

from aegis import cli
from aegis.local_observer import ObservationError


def test_streamed_json_matches_previous_stdout_exactly(monkeypatch):
    data = {"schema_version": "inventory-v2", "asset_id": None,
            "packages": [{"purl": "pkg:deb/debian/café", "version": "1:2-3",
                          "uncertainty": "unknown\nno proof"}],
            "independent_status": "unknown"}
    expected = json.dumps(data, sort_keys=True, indent=2) + "\n"
    sink = io.StringIO()
    with monkeypatch.context() as patch:
        patch.setattr(sys, "stdout", sink)
        cli._emit(data, True, "inventory")
    assert sink.getvalue() == expected


@pytest.mark.parametrize("command,argument", [
    ("status", []), ("inventory", []), ("findings", []),
    ("explain", ["fixed-finding-id"]), ("doctor", []),
])
def test_fixed_command_stdout_matches_previous_serializer(monkeypatch, capsys, command, argument):
    fixed = {"schema_version": "observation-results-v2", "asset_id": None,
             "captured_at": "2026-11-19T00:00:00Z", "identity_scope": "none",
             "findings": [{"publisher_authenticity": "verified",
                           "software_match": "matched", "local_claim_status": "current-in-supplied-file",
                           "independent_status": "unknown", "overall_assessment": "unknown"}]}
    monkeypatch.setattr(cli, "run", lambda _args: (fixed, 0))
    assert cli.main([command, *argument, "--json"]) == 0
    assert capsys.readouterr().out == json.dumps(fixed, sort_keys=True, indent=2) + "\n"


def test_streamed_json_uses_bounded_write_chunks_with_slow_consumer(monkeypatch):
    class SlowSink(io.StringIO):
        largest_write = 0

        def write(self, value):
            self.largest_write = max(self.largest_write, len(value))
            time.sleep(0.00001)
            return super().write(value)

    data = {"schema_version": "inventory-v2", "packages": [
        {"purl": f"pkg:deb/debian/package{i:04d}", "version": "1:2-3"}
        for i in range(100)
    ]}
    sink = SlowSink()
    with monkeypatch.context() as patch:
        patch.setattr(sys, "stdout", sink)
        cli._emit(data, True, "inventory")
    assert sink.getvalue() == json.dumps(data, sort_keys=True, indent=2) + "\n"
    assert sink.largest_write < 1024


def test_closed_stdout_has_bounded_exit_and_no_traceback(monkeypatch):
    class ClosedSink:
        closed = False

        def write(self, _value):
            raise BrokenPipeError("consumer closed")

        def close(self):
            self.closed = True

    sink = ClosedSink()
    with monkeypatch.context() as patch:
        patch.setattr(cli, "run", lambda _args: ({"schema_version": "inventory-v2", "packages": []}, 0))
        patch.setattr(sys, "stdout", sink)
        assert cli.main(["inventory", "--json"]) == 2
    assert sink.closed


def test_malformed_input_error_bytes_unchanged(monkeypatch, capsys):
    def fail(_args):
        raise ObservationError("malformed local input")

    monkeypatch.setattr(cli, "run", fail)
    assert cli.main(["inventory", "--json"]) == 2
    expected = json.dumps({"schema_version": "observation-error-v2", "status": "unknown",
                           "independent_status": "unknown", "error": "malformed local input"}) + "\n"
    captured = capsys.readouterr()
    assert captured.out == expected and captured.err == ""
