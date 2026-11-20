"""Bounded, offline, observation-only Linux package matching.

This module is deliberately independent of the lab's authority-bearing Rapid
agent. An inventory match is a lead for a human, never a mitigation decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4


MAX_STATUS_BYTES = 64 * 1024 * 1024
MAX_FEED_BYTES = 8 * 1024 * 1024
MAX_PACKAGES = 100_000
MAX_ADVISORIES = 10_000
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,127}$")
PURL_RE = re.compile(r"^pkg:deb/(debian|ubuntu)/([a-z0-9][a-z0-9+.-]{0,127})$")


class ObservationError(ValueError):
    """A local input cannot be safely collected or interpreted."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_bounded(path: Path, limit: int) -> bytes:
    if not stat.S_ISREG(path.stat().st_mode):
        raise ObservationError(f"{path.name} must be a regular file")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ObservationError(f"{path.name} exceeds {limit} byte limit")
    return data


def distribution(path: Path = Path("/etc/os-release")) -> str:
    try:
        data = _read_bounded(path, 64 * 1024).decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise ObservationError("cannot read Linux os-release") from exc
    values: dict[str, str] = {}
    for line in data.splitlines():
        if line.startswith("ID="):
            values["ID"] = line[3:].strip().strip('"').lower()
    distro = values.get("ID", "")
    if distro not in {"debian", "ubuntu"}:
        raise ObservationError(f"unsupported distribution: {distro or 'unknown'} (Debian and Ubuntu only)")
    return distro


@dataclass(frozen=True)
class Package:
    name: str
    ecosystem: str
    version: str
    architecture: str
    purl: str
    asset_id: str | None
    source: str
    collected_at: str
    confidence: str = "installed-binary-package"
    limitation: str = "Binary package identity only; source-package and reachability mapping unavailable"

    def as_dict(self) -> dict[str, str | None]:
        return vars(self).copy()


@dataclass(frozen=True)
class InventorySnapshot:
    asset_id: str | None
    packages: tuple[Package, ...]
    complete: bool
    reason: str
    captured_at: str
    snapshot_id: str


def collect_snapshot(asset_id: str | None, *, os_release: Path = Path("/etc/os-release"),
                     dpkg_status: Path = Path("/var/lib/dpkg/status"),
                     now: datetime | None = None) -> InventorySnapshot:
    captured_at = iso(now or utc_now())
    try:
        packages = tuple(collect_inventory(asset_id, os_release=os_release,
                                           dpkg_status=dpkg_status, now=now))
        complete, reason = True, "complete"
    except ObservationError as exc:
        # Absence cannot be inferred from a failed source. No partial package
        # rows are promoted to an authoritative inventory snapshot.
        packages, complete, reason = (), False, str(exc)
    identity = [(p.purl, p.version, p.architecture) for p in packages]
    digest = hashlib.sha256(json.dumps([asset_id, complete, reason, identity], sort_keys=True,
                                       separators=(",", ":")).encode("utf-8")).hexdigest()
    return InventorySnapshot(asset_id, packages, complete, reason, captured_at, digest)


def _package_from_stanza(stanza: dict[str, str], distro: str, asset_id: str | None, collected_at: str) -> Package | None:
    if stanza.get("Status") != "install ok installed":
        return None
    name = stanza.get("Package", "")
    version = stanza.get("Version", "")
    architecture = stanza.get("Architecture", "")
    if not PACKAGE_RE.fullmatch(name) or not version or len(version) > 128 or not version.isprintable():
        raise ObservationError("malformed installed package metadata")
    if not architecture or len(architecture) > 64 or not re.fullmatch(r"[A-Za-z0-9_-]+", architecture):
        raise ObservationError("malformed installed package architecture")
    return Package(name, "deb", version, architecture, f"pkg:deb/{distro}/{name}",
                   asset_id, "dpkg-status", collected_at)


def collect_inventory(asset_id: str | None, *, os_release: Path = Path("/etc/os-release"),
                      dpkg_status: Path = Path("/var/lib/dpkg/status"),
                      now: datetime | None = None) -> list[Package]:
    distro = distribution(os_release)
    collected_at = iso(now or utc_now())
    packages: list[Package] = []
    identities: set[tuple[str, str]] = set()
    stanza: dict[str, str] = {}
    total = 0
    try:
        if not stat.S_ISREG(dpkg_status.lstat().st_mode):
            raise ObservationError("dpkg status must be a regular file, not a symlink or device")
        with dpkg_status.open("rb") as stream:
            while raw := stream.readline(16_385):
                total += len(raw)
                if total > MAX_STATUS_BYTES or len(raw) > 16_384 or not raw.endswith(b"\n") and len(raw) == 16_385:
                    raise ObservationError("dpkg status exceeds input limit")
                line = raw.decode("utf-8").rstrip("\r\n")
                if not line:
                    package = _package_from_stanza(stanza, distro, asset_id, collected_at)
                    if package is not None:
                        identity = (package.name, package.architecture)
                        if identity in identities:
                            raise ObservationError("duplicate installed package identity")
                        identities.add(identity)
                        packages.append(package)
                        if len(packages) > MAX_PACKAGES:
                            raise ObservationError("too many installed packages")
                    stanza = {}
                elif not line[0].isspace() and ": " in line:
                    key, value = line.split(": ", 1)
                    if key in {"Package", "Version", "Status", "Architecture"}:
                        stanza[key] = value
            if stanza:
                package = _package_from_stanza(stanza, distro, asset_id, collected_at)
                if package is not None:
                    if (package.name, package.architecture) in identities:
                        raise ObservationError("duplicate installed package identity")
                    packages.append(package)
                    if len(packages) > MAX_PACKAGES:
                        raise ObservationError("too many installed packages")
    except (OSError, UnicodeError) as exc:
        raise ObservationError("cannot read dpkg status") from exc
    if not packages:
        raise ObservationError("no installed packages found in dpkg status")
    return sorted(packages, key=lambda item: (item.name, item.architecture, item.version))


def state_directory(path: Path) -> Path:
    # Do not create implicit parent directories or follow an operator-supplied
    # symlink out of the explicitly selected state location.
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ObservationError("state directory path must not contain a symlink")
    try:
        path.mkdir(mode=0o700, parents=False, exist_ok=True)
    except OSError as exc:
        raise ObservationError("state directory parent must exist and be writable") from exc
    if not stat.S_ISDIR(path.stat().st_mode):
        raise ObservationError("state directory must be a directory")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise ObservationError("state directory must be private (mode 0700)")
    return path


def asset_identity(path: Path) -> str:
    directory = state_directory(path)
    identity = directory / "identity.json"
    if not identity.exists():
        value = str(uuid4())
        try:
            fd = os.open(identity, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"asset_id": value}, stream)
                stream.write("\n")
    if identity.is_symlink() or stat.S_IMODE(identity.stat().st_mode) & 0o077:
        raise ObservationError("identity file must be private (mode 0600) and not a symlink")
    try:
        data = json.loads(_read_bounded(identity, 4096))
        value = data["asset_id"]
        if set(data) != {"asset_id"} or UUID(value).version != 4:
            raise ValueError("invalid asset identity")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ObservationError("invalid local asset identity") from exc
    return value


@dataclass(frozen=True)
class Advisory:
    vulnerability_id: str
    purl: str
    affected_versions: tuple[str, ...]
    summary: str
    source: str
    expires_at: datetime
    withdrawn_at: datetime | None
    verification: str = "signed-mesh-v1-lab-scope"
    artifact_id: str = ""
    claim_digest: str = ""
    claim_status: str = "current"
    publisher_authenticity: str = "unverified"


def match_findings(packages: list[Package] | tuple[Package, ...], advisories: list[Advisory], *,
                   now: datetime | None = None, inventory_complete: bool = True,
                   asset_id: str | None = None) -> list[dict[str, object]]:
    now = now or utc_now()
    by_identity: dict[tuple[str, str], list[Package]] = {}
    for package in packages:
        by_identity.setdefault((package.purl, package.version), []).append(package)
    findings: list[dict[str, object]] = []
    seen: set[str] = set()
    for advisory in advisories:
        unsupported = not PURL_RE.fullmatch(advisory.purl) or any(
            any(character in version for character in "<>=*^|,") for version in advisory.affected_versions
        )
        matches = [] if unsupported else [
            package for version in advisory.affected_versions
            for package in by_identity.get((advisory.purl, version), [])
        ]
        for package in matches or [None]:
            version = package.version if package is not None else ""
            architecture = package.architecture if package is not None else ""
            key = f"{advisory.artifact_id or advisory.vulnerability_id}\0{advisory.purl}\0{version}\0{architecture}"
            finding_id = hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]
            if finding_id in seen:
                continue
            seen.add(finding_id)
            claim_status = advisory.claim_status
            if advisory.withdrawn_at is not None and advisory.withdrawn_at <= now:
                claim_status = "withdrawn"
            elif advisory.expires_at <= now and claim_status != "withdrawn":
                claim_status = "expired"
            if unsupported:
                software_match, reason = "unknown", "UNSUPPORTED_IDENTITY_OR_COMPARATOR"
            elif package is None and not inventory_complete:
                software_match, reason = "unknown", "INVENTORY_INCOMPLETE"
            elif package is None:
                software_match, reason = "unmatched", "NO_EXACT_PACKAGE_VERSION"
            else:
                software_match, reason = "matched", "EXACT_PACKAGE_VERSION"
            local_claim_status = {
                "current": "current-in-supplied-file",
                "withdrawn": "withdrawn-in-supplied-file",
                "expired": "expired",
                "future": "future",
            }.get(claim_status, "unknown-in-supplied-file")
            findings.append({
                    "finding_id": finding_id,
                    "vulnerability_id": advisory.vulnerability_id,
                    "artifact_id": advisory.artifact_id,
                    "claim_digest": advisory.claim_digest,
                    "asset_id": package.asset_id if package is not None else packages[0].asset_id if packages else asset_id,
                    "purl": advisory.purl,
                    "package_name": package.name if package is not None else advisory.purl.rsplit("/", 1)[-1],
                    "installed_version": version,
                    "architecture": architecture,
                    "publisher_authenticity": advisory.publisher_authenticity,
                    "local_claim_status": local_claim_status,
                    "software_match": software_match,
                    "match_reason": reason,
                    "independent_status": "unknown",
                    "independent_status_reason": "NO_VERIFIABLE_T4_T5_PROOF",
                    "overall_assessment": "unknown",
                    "comparator": "exact-string",
                    "inventory_complete": inventory_complete,
                    "confidence": "package-identity-only" if software_match == "matched" else "none",
                    "source": advisory.source,
                    "collected_at": package.collected_at if package is not None else packages[0].collected_at if packages else "unknown",
                    "intelligence_expires_at": iso(advisory.expires_at),
                    "summary": advisory.summary,
                    "verification": advisory.verification,
                    "uncertainty": "No current independent Evidence/T4/T5 status; binary/source package and reachability mapping unavailable",
            })
    return sorted(findings, key=lambda row: (str(row["vulnerability_id"]), str(row["package_name"]), str(row["architecture"])))
