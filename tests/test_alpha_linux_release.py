"""Local-only checks for the release gate; no Docker or package download."""

import hashlib
import json
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import alpha_linux_release as release  # noqa: E402


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        review_probe = mock.patch.object(release.subprocess, "run",
                                         return_value=subprocess.CompletedProcess([], 0))
        review_probe.start()
        self.addCleanup(review_probe.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.wheels = self.root / "wheels"
        self.wheels.mkdir()
        self.filename = release.builder.BACKEND_WHEEL
        self.wheel = self.wheels / self.filename
        with zipfile.ZipFile(self.wheel, "w") as archive:
            archive.writestr("hatchling-1.33.0.dist-info/METADATA",
                             "Name: hatchling\nVersion: 1.33.0\n")
            archive.writestr("hatchling-1.33.0.dist-info/WHEEL",
                             "Wheel-Version: 1.0\nTag: py3-none-any\n")
        self.sha = hashlib.sha256(self.wheel.read_bytes()).hexdigest()
        self.manifest_entry = {"file": self.filename, "sha256": self.sha,
                               "source": "reviewed local fixture", "license": "MIT"}
        self.provenance_entry = {**self.manifest_entry, "distribution": "hatchling",
                                 "version": "1.33.0", "tags": ["py3-none-any"], "role": "build"}
        self.write_records()

    def write_records(self):
        (self.wheels / "manifest.json").write_text(json.dumps({
            "schema": "aegis-offline-wheelhouse-v1", "wheels": [self.manifest_entry]}))
        (self.wheels / "provenance.json").write_text(json.dumps({
            "schema": "aegis-release-provenance-v1", "review_commit": "a" * 40,
            "wheels": [self.provenance_entry]}))

    def test_wheel_archive_identity_and_hash_are_checked(self):
        approved = release.validate_provenance(self.wheels)
        self.assertEqual(approved["wheels"][0]["sha256"], self.sha)
        self.provenance_entry["tags"] = ["cp313-cp313-macosx_15_0_arm64"]
        self.write_records()
        with self.assertRaisesRegex(release.builder.OfflineBuildError, "identity"):
            release.validate_provenance(self.wheels)

    def test_review_commit_must_resolve_locally(self):
        with mock.patch.object(release.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 1)):
            with self.assertRaisesRegex(release.builder.OfflineBuildError, "not present"):
                release.validate_provenance(self.wheels)

    def test_missing_review_record_stops_before_build(self):
        (self.wheels / "provenance.json").unlink()
        report = release.release("b" * 40, self.wheels.resolve(), self.root / "out")
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["builds"], [])
        self.assertEqual(report["cells"], [])
        self.assertIn("reviewed provenance", report["reason"])

    def test_pip_archive_report_must_match_original_hash(self):
        approved = release.validate_provenance(self.wheels)
        aegis = self.root / "aegis_network-0.1.0-py3-none-any.whl"
        aegis.write_bytes(b"synthetic fixture")
        expected = hashlib.sha256(aegis.read_bytes()).hexdigest()
        pip_report = {"install": [{"metadata": {"name": "aegis-network", "version": "0.1.0"},
                                   "download_info": {"url": f"file:///dist/{aegis.name}",
                                                     "archive_info": {"hashes": {"sha256": expected}}}}]}
        self.assertEqual(release.verify_pip_report(pip_report, approved, aegis)[0]["sha256"], expected)
        pip_report["install"][0]["download_info"]["archive_info"]["hashes"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(release.builder.OfflineBuildError, "wrong-hash"):
            release.verify_pip_report(pip_report, approved, aegis)


if __name__ == "__main__":
    unittest.main()
