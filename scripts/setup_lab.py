"""Create disposable, ignored demo credentials and a synthetic finding."""

import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.artifact import Evidence, Finding, Software, sign


def main() -> None:
    directory = Path("lab-config")
    directory.mkdir(exist_ok=True)
    private_path = directory / "publisher.key"
    if private_path.exists():
        key = Ed25519PrivateKey.from_private_bytes(private_path.read_bytes())
    else:
        key = Ed25519PrivateKey.generate()
        private = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        private_path.write_bytes(private)
        os.chmod(private_path, 0o600)
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    (directory / "publishers.json").write_text(json.dumps({"lab-publisher": base64.b64encode(public).decode()}))
    (directory / "agent.json").write_text(json.dumps({
        "publishers_file": "/config/publishers.json",
        "lab_authorized": True,
        "allowed_templates": ["observe-only"],
        "inventory": [{"purl": "pkg:generic/aegis-demo", "version": "1.0.0"}],
    }, indent=2))
    evidence = b"synthetic lab finding; no exploit or scan\n"
    (directory / "evidence.txt").write_bytes(evidence)
    now = datetime.now(timezone.utc)
    finding = Finding(
        schema_version="1.0",
        artifact_id=uuid4(),
        publisher_id="lab-publisher",
        sequence=int(now.timestamp() * 1_000_000),
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(hours=1),
        vulnerability_id="AEGIS-LAB-0001",
        software=Software(purl="pkg:generic/aegis-demo", affected_versions=["1.0.0"]),
        evidence=[Evidence(uri="urn:aegis:lab:evidence", sha256=hashlib.sha256(evidence).hexdigest(), method="lab-reproduction")],
        applicability="authorized-lab",
        mitigation_template="observe-only",
    )
    (directory / "finding.json").write_text(sign(finding, key).model_dump_json(indent=2))
    print("Created lab-config with synthetic finding and disposable publisher key")


if __name__ == "__main__":
    main()
