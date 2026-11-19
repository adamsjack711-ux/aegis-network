"""Check retained Phase 4E-D observations using public records only."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
from xml.etree import ElementTree

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def verify_public_signature(key, signature, domain, body):
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
        bytes.fromhex(signature), domain + b"\0" + canonical(body),
    )


def inspect_status(report):
    pins = report["record_digests"]
    assert pins == sorted(set(pins))
    archive = b"AEGIS-EVIDENCE-STATUS/v1\0archive\0" + b"".join(bytes.fromhex(pin) for pin in pins)
    head = {"revision": len(pins), "root_sha256": sha256(archive).hexdigest()}
    endorsements = report["endorsements"]
    assert len(endorsements) == len({item["public_key"] for item in endorsements}) == 2
    assert len({item["wire"]["body"]["witness_id"] for item in endorsements}) == 2
    for item in endorsements:
        wire = item["wire"]
        verify_public_signature(item["public_key"], wire["signature"],
                                b"AEGIS-EVIDENCE-STATUS/v1\0endorsement", wire["body"])
        assert wire["body"]["head"] == head
        assert wire["body"]["challenge_sha256"] == sha256(canonical(report["challenge"])).hexdigest()
        assert report["challenge"]["issued_at"] <= wire["body"]["issued_at"] < wire["body"]["expires_at"]


def inspect_dispatch(properties):
    backlog = properties["queued_before_restart"]
    publication = properties["broker_publication"]
    denial = properties["durable_denial"]
    withdrawal = denial["row"][2]
    pending = [row[1] for row in backlog if row[2] is False]
    delivered = [row[1] for row in publication]
    assert len(delivered) == len(set(pending)) == len(set(delivered)) == 5
    assert set(delivered) == set(pending)
    assert pending[-1] == withdrawal
    assert denial["row"] == ["revoked_dry_run", 1, withdrawal]
    return {"withdrawal_rank": delivered.index(withdrawal) + 1, "pending_count": len(delivered),
            "recovery_upper_ms": round(denial["recovery_upper_ms"], 3)}


def inspect_priority(properties):
    before = properties["priority_before_release"]
    after = properties["ordinary_after_release"]
    denial = properties["durable_denial"]
    withdrawal = before["critical_event_id"]
    ordinary = set(before["ordinary_pending_ids"])
    assert denial["row"] == ["revoked_dry_run", 1, withdrawal]
    assert before["ordinary_before"] == before["ordinary_held"] and before["ordinary_max_bytes"] > 0
    assert 0 < denial["recovery_upper_ms"] <= before["observed_ms_from_restart"] <= after["release_ms_from_restart"]
    assert {row[1] for row in properties["queued_before_restart"] if not row[2]} == ordinary | {withdrawal}
    assert {row[1] for row in properties["broker_publication"]} == ordinary
    assert ordinary <= {row[0] for row in after["decisions"]}
    return {"ordinary_held": len(ordinary), "recovery_upper_ms": round(denial["recovery_upper_ms"], 3),
            "ordinary_drain_ms": round(after["drain_ms_from_release"], 3)}


def inspect_held_barrier(report):
    generation = report["durable"]["home"]["generation"]
    assert report["durable"]["home"]["phase"] == "preparing"
    assert report["durable"]["anchor"]["generation"] == report["reachable"]["generation"] == generation
    assert report["reachable"]["effective"] == "quarantined"
    assert sorted(target["fence"] for target in report["durable"]["targets"].values()) == [1, generation]
    return generation


def inspect_unified_status(report):
    for status in report["statuses"]:
        wire = status["wire"]
        verify_public_signature(status["key"], wire["signature"], b"aegis-phase4e-v1/status", wire["body"])
        assert wire["body"]["challenge"] == sha256(canonical(status["challenge"])).hexdigest()
    assert report["statuses"][0]["wire"]["body"]["outcome"] == "reproduced"
    assert report["statuses"][-1]["wire"]["body"]["reason"] == "revoked"
    assert [row[0] for row in report["restrictions"]] == ["canary"]
    assert report["floor"]["pending"] is None
    return len(report["statuses"])


def inspect_crash(properties):
    before, after = properties["crash_before_recovery"], properties["crash_recovery"]
    assert before["pre_intake_agent"] == {"decision": None, "broker_ack_floor": 0}
    assert before["after_audit_agent"]["broker_ack_floor"] == 0
    assert before["after_audit_agent"]["decision"] == ["revoked_dry_run", 1, before["withdrawal_id"]]
    for row in after.values():
        assert row["durable_decision_rows"] == row["broker_ack_floor"] == 1
        assert row["first_durable_observation_upper_ms"] <= row["independent_ack_observation_upper_ms"]
    return after


def inspect_file(path):
    suite = ElementTree.parse(path).getroot().find("testsuite")
    summary = {key: int(suite.attrib[key]) for key in ("tests", "failures", "errors", "skipped")}
    summary["signed_status_samples"] = 0
    summary["signed_ownership_requests"] = 0
    for case in suite.findall("testcase"):
        dispatch = {}
        for item in case.findall("properties/property"):
            name, value = item.attrib["name"], item.attrib["value"]
            if name in {"appraised_status", "healthy_signed_status", "withdrawn_signed_status"}:
                inspect_status(json.loads(value))
                summary["signed_status_samples"] += 1
            elif name.startswith("signed_request_"):
                request = json.loads(value)
                verify_public_signature(request["public_key"], request["signature"], b"AEGIS-OWNERSHIP/v1\0lease",
                                        request["body"])
                assert request["body"]["assignment"]["holder_key"] == request["public_key"]
                summary["signed_ownership_requests"] += 1
            elif name in {"queued_before_restart", "broker_publication", "durable_denial",
                          "priority_before_release", "ordinary_after_release", "crash_before_recovery",
                          "crash_recovery"}:
                dispatch[name] = value
            elif name == "held_barrier":
                summary["held_writer_barrier_generation"] = inspect_held_barrier(json.loads(value))
            elif name == "verified_trust":
                summary["signed_unified_status_samples"] = inspect_unified_status(json.loads(value))
            elif name == "single_witness_admission":
                observation = json.loads(value)
                assert len(observation["direct_durable_receipt"]["votes"]) == 1
                assert observation["target_write_attempted"] is False
                summary["single_witness_appraisal"] = observation["outcome"]
            elif name in {"partition_held", "partition_reconnected"}:
                dispatch[name] = value
        if {"queued_before_restart", "broker_publication", "durable_denial"} <= dispatch.keys():
            data = {key: json.loads(value) for key, value in dispatch.items()}
            if {"priority_before_release", "ordinary_after_release"} <= data.keys():
                summary["priority"] = inspect_priority(data)
            elif "priority_before_release" not in data:
                summary["dispatch"] = inspect_dispatch(data)
        if {"crash_before_recovery", "crash_recovery"} <= dispatch.keys():
            summary["agent_crash_recovery"] = inspect_crash({key: json.loads(value) for key, value in dispatch.items()})
        if {"partition_held", "partition_reconnected"} <= dispatch.keys():
            held = json.loads(dispatch["partition_held"])
            recovered = json.loads(dispatch["partition_reconnected"])
            assert held["decision"] is None and held["broker_ack_floor"] == 0
            assert recovered["decision"] == ["revoked_dry_run", 1, held["published_withdrawal"]]
            assert recovered["observer_denial_upper_ms"] <= recovered["independent_ack_upper_ms"]
            summary["partition_recovery"] = recovered
    assert summary["tests"] == len(suite.findall("testcase"))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", type=Path, nargs="+")
    args = parser.parse_args()
    print(json.dumps({path.name: inspect_file(path) for path in args.reports}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
