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
                          "priority_before_release", "ordinary_after_release"}:
                dispatch[name] = value
        if {"queued_before_restart", "broker_publication", "durable_denial"} <= dispatch.keys():
            data = {key: json.loads(value) for key, value in dispatch.items()}
            if {"priority_before_release", "ordinary_after_release"} <= data.keys():
                summary["priority"] = inspect_priority(data)
            elif "priority_before_release" not in data:
                summary["dispatch"] = inspect_dispatch(data)
    assert summary["tests"] == len(suite.findall("testcase"))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", type=Path, nargs="+")
    args = parser.parse_args()
    print(json.dumps({path.name: inspect_file(path) for path in args.reports}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
