"""Independent installed-entry-point probe for disposable Linux containers."""

import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
from uuid import uuid4


ROOT = Path("/tmp/alpha-probe")
ROOT.mkdir()
ENV = os.environ | {
    "HOME": str(ROOT / "home"),
    "XDG_CONFIG_HOME": str(ROOT / "config"),
    "XDG_DATA_HOME": str(ROOT / "data"),
    "XDG_STATE_HOME": str(ROOT / "state"),
    "XDG_CACHE_HOME": str(ROOT / "cache"),
}
(ROOT / "home").mkdir()
PYTHON = "/tmp/alpha/bin/python"
ENTRY = "/tmp/alpha/bin/aegis"


def tree(root):
    if not root.exists():
        return []
    result = []
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            result.append((relative, "link", os.readlink(path)))
        elif path.is_file():
            result.append((relative, path.stat().st_mtime_ns,
                           hashlib.sha256(path.read_bytes()).hexdigest()))
        else:
            result.append((relative, "directory", path.stat().st_mtime_ns))
    return result


def call(*args, expected):
    before = (tree(ROOT), tree(Path("/tmp/alpha/lib/python3.12/site-packages")))
    process = subprocess.run([PYTHON, ENTRY, *args], env=ENV, capture_output=True, text=True)
    after = (tree(ROOT), tree(Path("/tmp/alpha/lib/python3.12/site-packages")))
    assert process.returncode == expected, (args, process.returncode, process.stderr, process.stdout)
    assert before == after, (args, "unrequested persistent write")
    return json.loads(process.stdout)


if "--malformed" in sys.argv:
    result = call("inventory", "--json", expected=2)
    assert result["schema_version"] == "inventory-v2" and not result["inventory_complete"]
    assert not result["packages"] and result["identity_scope"] == "none"
    print(json.dumps({"malformed_inventory": "unknown", "writes": 0}))
    raise SystemExit(0)

inventory = call("inventory", "--json", expected=0)
assert inventory["schema_version"] == "inventory-v2"
assert inventory["asset_id"] is None and inventory["identity_scope"] == "none"
assert inventory["inventory_complete"] and inventory["package_count"] > 0
distribution = inventory["distribution"]
assert distribution == sys.argv[1], (distribution, sys.argv)
imports = subprocess.run(
    [PYTHON, "-c", "import aegis.cli,json,sys; print(json.dumps(sorted(k for k in sys.modules if k.startswith('aegis.'))))"],
    env=ENV, capture_output=True, text=True,
)
assert imports.returncode == 0, imports.stderr
loaded = set(json.loads(imports.stdout))
assert "aegis.core" not in loaded and "aegis.config" not in loaded
assert "aegis.agent_runtime" not in loaded and not any(k.startswith("aegis.mitigation") for k in loaded)
status = call("status", "--json", expected=2)
assert status["independent_status"] == "unknown" and status["overall_assessment"] == "unknown"
assert call("findings", "--json", expected=2)["independent_status"] == "unknown"
assert call("explain", "absent", "--json", expected=2)["independent_status"] == "unknown"
assert call("doctor", "--json", expected=0)["independent_status"] == "unknown"

# Build a signed local claim from an actual installed binary package. The
# claim and trust grant are test inputs, not independent T4/T5 proof.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from aegis.artifact import Evidence, Finding, Revocation, Software, canonical_bytes, sign, sign_revocation

package = inventory["packages"][0]
now = datetime.now(timezone.utc)
key = Ed25519PrivateKey.generate()
revoker = Ed25519PrivateKey.generate()
finding = Finding(
    schema_version="1.0", artifact_id=uuid4(), publisher_id="probe-publisher", sequence=1,
    issued_at=now - timedelta(hours=1), expires_at=now + timedelta(hours=1),
    vulnerability_id="CVE-2026-0001",
    software=Software(purl=package["purl"], affected_versions=[package["version"]]),
    evidence=[Evidence(uri="urn:local:alpha-probe", sha256="a" * 64, method="advisory")],
    applicability="authorized-lab", mitigation_template="observe-only",
)
grant = {"grants": []}
for key_id, private, roles in (("default", key, ["finding"]), ("revoker", revoker, ["revocation"])):
    grant["grants"].append({
        "publisher_id": "probe-publisher", "key_id": key_id,
        "public_key": base64.b64encode(private.public_key().public_bytes_raw()).decode(),
        "roles": roles, "not_before": (now - timedelta(days=1)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(), "revoked_at": None,
    })
trust = ROOT / "trust.json"
feed = ROOT / "feed.json"
trust.write_text(json.dumps(grant))
events = [sign(finding, key).model_dump(mode="json")]
feed.write_text(json.dumps({"adapter_version": "mesh-events-v1", "events": events}))
rows = call("findings", "--feed", str(feed), "--trust", str(trust), "--json", expected=0)
assert rows["current_exact_package_match_count"] == 1
row = rows["findings"][0]
assert row["software_match"] == "matched" and row["publisher_authenticity"] == "verified"
assert row["independent_status"] == "unknown" and row["overall_assessment"] == "unknown"
assert call("explain", row["finding_id"], "--feed", str(feed), "--trust", str(trust),
            "--json", expected=0)["independent_status"] == "unknown"
assert call("status", "--feed", str(feed), "--trust", str(trust),
            "--json", expected=0)["independent_status"] == "unknown"
human = subprocess.run([PYTHON, ENTRY, "findings", "--feed", str(feed), "--trust", str(trust)],
                       env=ENV, capture_output=True, text=True)
assert human.returncode == 0 and "independent Evidence status unknown" in human.stdout
assert "protected" not in human.stdout.lower() and "safe" not in human.stdout.lower()

for version, expected_match, expected_exit in (
    (package["version"] + ".different", "unmatched", 0),
    (">=" + package["version"], "unknown", 2),
):
    variant = finding.model_copy(update={
        "artifact_id": uuid4(), "software": Software(purl=package["purl"], affected_versions=[version]),
    })
    feed.write_text(json.dumps({"adapter_version": "mesh-events-v1",
                                "events": [sign(variant, key).model_dump(mode="json")]}))
    variant_output = call("findings", "--feed", str(feed), "--trust", str(trust),
                          "--json", expected=expected_exit)
    assert variant_output["findings"][0]["software_match"] == expected_match

feed.write_text(json.dumps({"adapter_version": "mesh-events-v1", "events": events}))

tampered = json.loads(feed.read_text())
tampered["events"][0]["finding"]["vulnerability_id"] = "CVE-2026-9999"
feed.write_text(json.dumps(tampered))
assert call("findings", "--feed", str(feed), "--trust", str(trust),
            "--json", expected=2)["schema_version"] == "observation-error-v2"

withdrawal = Revocation(
    schema_version="1.1", revocation_id=uuid4(), publisher_id="probe-publisher", sequence=2,
    issued_at=now, expires_at=now + timedelta(hours=1),
    target_artifact_id=finding.artifact_id,
    target_sha256=hashlib.sha256(canonical_bytes(finding)).hexdigest(),
    target_publisher_id="probe-publisher", reason="withdrawn",
)
events.append(sign_revocation(withdrawal, revoker, "revoker").model_dump(mode="json"))
feed.write_text(json.dumps({"adapter_version": "mesh-events-v1", "events": events}))
withdrawn = call("findings", "--feed", str(feed), "--trust", str(trust), "--json", expected=2)
assert withdrawn["findings"][0]["local_claim_status"] == "withdrawn-in-supplied-file"

state = ROOT / "chosen"
process = subprocess.run([PYTHON, ENTRY, "--state-dir", str(state), "inventory", "--json"],
                         env=ENV, capture_output=True, text=True)
assert process.returncode == 0, process.stderr
assert json.loads(process.stdout)["identity_scope"] == "explicit-local"
assert sorted(str(path.relative_to(ROOT)) for path in ROOT.rglob("*") if path == state or state in path.parents) == [
    "chosen", "chosen/identity.json"]
assert state.stat().st_mode & 0o077 == 0
assert (state / "identity.json").stat().st_mode & 0o077 == 0

print(json.dumps({
    "distribution": distribution, "package_count": inventory["package_count"],
    "signed_exact_match": "unknown-independent-status", "invalid_signature": "rejected",
    "withdrawn": "unknown", "implicit_writes": 0, "explicit_state": "identity-only",
    "runtime_enforcement_imports": 0, "exact_version_mismatch": "unmatched",
    "range_version": "unknown",
}, sort_keys=True))
