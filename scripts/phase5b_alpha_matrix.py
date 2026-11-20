"""Owner-side offline installed-console matrix for disposable Linux containers.

Run only with /tmp and /var/lib/dpkg mounted as disposable tmpfs. This is a
filesystem observation, not a syscall trace or an independent validation.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.artifact import Evidence, Finding, Revocation, Software, canonical_bytes, sign, sign_revocation
from aegis.local_observer import distribution

ROOT = Path("/tmp/aegis-5b-alpha-matrix")
STATUS = Path("/var/lib/dpkg/status")
NOW = datetime.now(timezone.utc)


def tree(root: Path) -> dict[str, tuple]:
    result = {}
    for path in root.rglob("*"):
        metadata = path.lstat()
        name = str(path.relative_to(root))
        if stat.S_ISREG(metadata.st_mode):
            digest = sha256(path.read_bytes()).hexdigest()
        elif stat.S_ISLNK(metadata.st_mode):
            digest = os.readlink(path)
        else:
            digest = None
        result[name] = (metadata.st_mode, metadata.st_size, metadata.st_mtime_ns, digest)
    return result


def diff_trees(before: dict, after: dict) -> list[str]:
    return sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))


def make_fixture(distro: str) -> dict[str, Path]:
    fixture = ROOT / "fixtures"
    fixture.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    wrong = Ed25519PrivateKey.generate()
    finding = Finding(
        schema_version="1.0", artifact_id=uuid4(), publisher_id="alpha-fixture", sequence=1,
        issued_at=NOW - timedelta(days=2), expires_at=NOW + timedelta(days=2),
        vulnerability_id="AEGIS-ALPHA-001",
        software=Software(purl=f"pkg:deb/{distro}/curl", affected_versions=["1:8.0-1"]),
        evidence=[Evidence(uri="urn:local:alpha", sha256="a" * 64, method="advisory")],
        applicability="authorized-lab", mitigation_template="observe-only",
    )
    signed = sign(finding, key).model_dump(mode="json")
    revocation = Revocation(
        schema_version="1.1", revocation_id=uuid4(), publisher_id="alpha-fixture", sequence=2,
        issued_at=NOW - timedelta(hours=1), expires_at=NOW + timedelta(days=1),
        target_artifact_id=finding.artifact_id,
        target_sha256=sha256(canonical_bytes(finding)).hexdigest(),
        target_publisher_id="alpha-fixture", reason="withdrawn",
    )

    def write(name: str, value: object) -> Path:
        path = fixture / name
        path.write_text(json.dumps(value, sort_keys=True) + "\n")
        return path

    trust = {"grants": [{
        "publisher_id": "alpha-fixture", "key_id": "default",
        "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "roles": ["finding", "revocation"],
        "not_before": (NOW - timedelta(days=3)).isoformat(),
        "expires_at": (NOW + timedelta(days=3)).isoformat(), "revoked_at": None,
    }]}
    paths = {"trust": write("trust.json", trust)}
    paths["current"] = write("current.json", {"adapter_version": "mesh-events-v1", "events": [signed]})
    expired = finding.model_copy(update={"expires_at": NOW - timedelta(days=1)})
    paths["expired"] = write("expired.json", {"adapter_version": "mesh-events-v1",
                                                "events": [sign(expired, key).model_dump(mode="json")]})
    paths["withdrawn"] = write("withdrawn.json", {"adapter_version": "mesh-events-v1",
                                                    "events": [signed, sign_revocation(revocation, key, "default").model_dump(mode="json")]})
    ranged = finding.model_copy(update={"software": Software(
        purl=f"pkg:deb/{distro}/curl", affected_versions=[">=1:8.0-1"])})
    paths["unsupported"] = write("unsupported.json", {"adapter_version": "mesh-events-v1",
                                                        "events": [sign(ranged, key).model_dump(mode="json")]})
    paths["malformed"] = fixture / "malformed.json"
    paths["malformed"].write_text("{broken")
    tampered = json.loads(json.dumps(signed))
    tampered["finding"]["vulnerability_id"] = "AEGIS-TAMPERED"
    paths["tampered"] = write("tampered.json", {"adapter_version": "mesh-events-v1", "events": [tampered]})
    future = finding.model_copy(update={"issued_at": NOW + timedelta(days=1),
                                        "expires_at": NOW + timedelta(days=3)})
    paths["future"] = write("future.json", {"adapter_version": "mesh-events-v1",
                                              "events": [sign(future, key).model_dump(mode="json")]})
    revoked = json.loads(json.dumps(trust))
    revoked["grants"][0]["revoked_at"] = (NOW - timedelta(hours=1)).isoformat()
    paths["revoked_trust"] = write("revoked-trust.json", revoked)
    invalid = json.loads(json.dumps(trust))
    invalid["grants"][0]["public_key"] = base64.b64encode(wrong.public_key().public_bytes_raw()).decode()
    paths["invalid_trust"] = write("invalid-trust.json", invalid)
    conflict = sign(finding.model_copy(update={"artifact_id": uuid4()}), key).model_dump(mode="json")
    paths["conflict"] = write("conflict.json", {"adapter_version": "mesh-events-v1",
                                                  "events": [signed, conflict]})
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--console", type=Path, required=True)
    parser.add_argument("--distro", choices=("debian", "ubuntu"), required=True)
    args = parser.parse_args()
    if distribution() != args.distro:
        raise SystemExit("real container distribution differs from declared matrix row")
    ROOT.mkdir(mode=0o700, exist_ok=True)
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    valid_status = "Package: curl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:8.0-1\n\n"
    STATUS.write_text(valid_status)
    fixture = make_fixture(args.distro)
    home = ROOT / "home"
    home.mkdir(exist_ok=True)
    env = os.environ | {"HOME": str(home), "XDG_STATE_HOME": str(ROOT / "implicit-state"),
                        "TMPDIR": str(ROOT / "tmp"), "PYTHONDONTWRITEBYTECODE": "1"}
    (ROOT / "tmp").mkdir(exist_ok=True)
    results = []

    def invoke(name: str, argv: list[str], expected_exit: int, *, explicit: bool = False) -> dict:
        before_tmp, before_dpkg = tree(Path("/tmp")), tree(STATUS.parent)
        try:
            completed = subprocess.run([str(args.console), *argv], env=env, capture_output=True,
                                       text=True, check=False, timeout=10)
            code, stdout, stderr, censored = completed.returncode, completed.stdout, completed.stderr, False
        except subprocess.TimeoutExpired as exc:
            code, stdout, stderr, censored = None, str(exc.stdout or ""), str(exc.stderr or ""), True
        changed_tmp = diff_trees(before_tmp, tree(Path("/tmp")))
        changed_dpkg = diff_trees(before_dpkg, tree(STATUS.parent))
        okay = code == expected_exit and not censored
        if not explicit:
            okay = okay and not changed_tmp and not changed_dpkg
        result = {"name": name, "argv": argv, "exit": code, "expected_exit": expected_exit,
                  "stdout": stdout, "stderr": stderr, "changed_tmp": changed_tmp,
                  "changed_dpkg": changed_dpkg, "censored": censored,
                  "status": "pass" if okay else "fail"}
        results.append(result)
        return result

    cases = [
        ("status_no_feed", ["status"], 2),
        ("inventory", ["inventory"], 0),
        ("findings_no_feed", ["findings"], 2),
        ("findings_missing", ["findings", "--feed", str(ROOT / "missing.json")], 2),
        ("doctor", ["doctor"], 0),
        ("explain_no_feed", ["explain", "absent"], 2),
        ("signed_current", ["findings", "--feed", str(fixture["current"]), "--trust", str(fixture["trust"])], 0),
        ("signed_expired", ["findings", "--feed", str(fixture["expired"]), "--trust", str(fixture["trust"])], 2),
        ("signed_withdrawn", ["findings", "--feed", str(fixture["withdrawn"]), "--trust", str(fixture["trust"])], 2),
        ("unsupported_range", ["findings", "--feed", str(fixture["unsupported"]), "--trust", str(fixture["trust"])], 2),
        ("malformed", ["findings", "--feed", str(fixture["malformed"]), "--trust", str(fixture["trust"])], 2),
        ("duplicate_inventory", ["findings", "--feed", str(fixture["current"]), "--trust", str(fixture["trust"])], 2),
    ]
    for name, argv, expected in cases:
        STATUS.write_text(valid_status * 2 if name == "duplicate_inventory" else valid_status)
        for output_kind, extra in (("json", ["--json"]), ("human", [])):
            result = invoke(f"{name}_{output_kind}", [*argv, *extra], expected)
            if name == "signed_current" and output_kind == "json" and result["status"] == "pass":
                body = json.loads(result["stdout"])
                row = body["findings"][0]
                if not (row["publisher_authenticity"] == "verified" and
                        row["software_match"] == "matched" and
                        row["local_claim_status"] == "current-in-supplied-file" and
                        row["independent_status"] == row["overall_assessment"] == "unknown"):
                    result["status"] = "fail"
            if name == "signed_current" and output_kind == "human" and result["status"] == "pass":
                if "possible exposure" not in result["stdout"] or "independent Evidence status unknown" not in result["stdout"]:
                    result["status"] = "fail"
    # Additional signed negatives, outside the frozen twelve-case minimum.
    STATUS.write_text(valid_status)
    for name, feed, trust in (
        ("tampered", fixture["tampered"], fixture["trust"]),
        ("invalid_grant", fixture["current"], fixture["invalid_trust"]),
        ("future", fixture["future"], fixture["trust"]),
        ("revoked", fixture["current"], fixture["revoked_trust"]),
        ("conflict", fixture["conflict"], fixture["trust"]),
    ):
        invoke(name, ["findings", "--feed", str(feed), "--trust", str(trust), "--json"], 2)
    # Four explicit-state controls per distribution.
    chosen = ROOT / "chosen"
    first = invoke("explicit_first", ["--state-dir", str(chosen), "inventory", "--json"], 0, explicit=True)
    first_changes = first["changed_tmp"]
    if not chosen.is_dir() or not (chosen / "identity.json").is_file() or not all(
        name.startswith("aegis-5b-alpha-matrix/chosen") or name == "aegis-5b-alpha-matrix"
        for name in first_changes
    ):
        first["status"] = "fail"
    elif stat.S_IMODE(chosen.stat().st_mode) != 0o700 or stat.S_IMODE((chosen / "identity.json").stat().st_mode) != 0o600:
        first["status"] = "fail"
    repeat = invoke("explicit_repeat", ["--state-dir", str(chosen), "inventory", "--json"], 0, explicit=True)
    if repeat["changed_tmp"] or repeat["changed_dpkg"]:
        repeat["status"] = "fail"
    outside = ROOT / "outside"
    outside.mkdir()
    alias = ROOT / "alias"
    alias.symlink_to(outside, target_is_directory=True)
    ancestor = invoke("explicit_ancestor_symlink", ["--state-dir", str(alias / "aegis"), "inventory", "--json"], 2, explicit=True)
    final = invoke("explicit_final_symlink", ["--state-dir", str(alias), "inventory", "--json"], 2, explicit=True)
    if (outside / "aegis").exists() or (outside / "identity.json").exists() or ancestor["changed_tmp"] or final["changed_tmp"]:
        ancestor["status"] = final["status"] = "fail"
    summary = {key: sum(row["status"] == key for row in results) for key in ("pass", "fail")}
    print(json.dumps({"distro": args.distro, "python": os.sys.version.split()[0],
                      "logical_default_cases": len(cases), "default_invocations": len(cases) * 2,
                      "additional_negative_controls": 5, "explicit_controls": 4,
                      "summary": summary, "cases": results}, sort_keys=True))
    if summary["fail"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
