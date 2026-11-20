"""Generate reproducible throwaway SignedFinding 1.0 CLI challenge fixtures."""

import base64
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.artifact import Evidence, Finding, Revocation, Software, canonical_bytes, sign, sign_revocation


ROOT = Path(__file__).resolve().parents[1] / "fixtures/phase-next-cli"
KEY = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)  # Public, fixture-only test seed.


def write(name, value):
    path = ROOT / name
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def finding(*, expiry, versions=("1:8.0-1",)):
    return Finding(schema_version="1.0", artifact_id=UUID("00000000-0000-4000-8000-000000000501"),
                   publisher_id="validator-fixture", sequence=1,
                   issued_at=datetime(2026, 11, 1, tzinfo=timezone.utc), expires_at=expiry,
                   vulnerability_id="AEGIS-CLI-501",
                   software=Software(purl="pkg:deb/debian/curl", affected_versions=list(versions)),
                   evidence=[Evidence(uri="urn:aegis:independent-cli-fixture",
                                      sha256="a" * 64, method="advisory")],
                   applicability="authorized-lab", mitigation_template="observe-only")


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / "os-release").write_text("ID=debian\n")
    (ROOT / "dpkg-status").write_text(
        "Package: curl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:8.0-1\n\n"
        "Package: removed\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 1\n\n"
    )
    (ROOT / "dpkg-truncated").write_text("Package: curl\nStatus: install ok installed\nVersion: 1:8.0-1\n\n")
    write("trust.json", {"grants": [{"publisher_id": "validator-fixture", "key_id": "validator",
                                  "public_key": base64.b64encode(KEY.public_key().public_bytes_raw()).decode(),
                                  "roles": ["finding", "revocation"],
                                  "not_before": "2026-01-01T00:00:00+00:00",
                                  "expires_at": "2031-01-01T00:00:00+00:00", "revoked_at": None}]})
    current = finding(expiry=datetime(2030, 1, 1, tzinfo=timezone.utc))
    signed = sign(current, KEY, "validator").model_dump(mode="json")
    write("signed-current.json", {"adapter_version": "mesh-events-v1", "events": [signed]})
    expired = finding(expiry=datetime(2026, 11, 19, tzinfo=timezone.utc))
    write("signed-expired.json", {"adapter_version": "mesh-events-v1",
                                  "events": [sign(expired, KEY, "validator").model_dump(mode="json")]})
    revocation = Revocation(schema_version="1.1",
                            revocation_id=UUID("00000000-0000-4000-8000-000000000502"),
                            publisher_id="validator-fixture", sequence=2,
                            issued_at=datetime(2026, 11, 19, tzinfo=timezone.utc),
                            expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
                            target_artifact_id=current.artifact_id,
                            target_sha256=sha256(canonical_bytes(current)).hexdigest(),
                            target_publisher_id=current.publisher_id, reason="withdrawn")
    write("signed-withdrawn.json", {"adapter_version": "mesh-events-v1",
                                    "events": [signed, sign_revocation(revocation, KEY, "validator").model_dump(mode="json")]})
    ranged = finding(expiry=datetime(2030, 1, 1, tzinfo=timezone.utc), versions=(">=1:8.0-1",))
    write("signed-unsupported-range.json", {"adapter_version": "mesh-events-v1",
                                             "events": [sign(ranged, KEY, "validator").model_dump(mode="json")]})
    write("unsigned-observation.json", {"schema_version": "observation-v1", "advisories": [
        {"vulnerability_id": "AEGIS-CLI-501", "purl": "pkg:deb/debian/curl", "affected_versions": ["1:8.0-1"]}]})


if __name__ == "__main__":
    main()
