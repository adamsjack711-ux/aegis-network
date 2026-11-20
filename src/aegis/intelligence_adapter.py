"""Versioned local intake adapters; no Mesh or enforcement contract changes."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Protocol

from .artifact import SignedFinding, SignedRevocation, canonical_bytes, parse_event, verify
from .config import load_publishers_bytes
from .local_observer import (
    Advisory, MAX_ADVISORIES, MAX_FEED_BYTES, ObservationError, _read_bounded,
    utc_now,
)
from .trust import TrustStore


class FindingAdapter(Protocol):
    version: str

    def advisories(self, raw: dict, *, now: datetime, trust: TrustStore | None) -> list[Advisory]: ...


class MeshV1Adapter:
    """Read existing signed lab findings as observation leads only."""

    version = "mesh-events-v1"

    def advisories(self, raw: dict, *, now: datetime, trust: TrustStore | None) -> list[Advisory]:
        if trust is None:
            raise ObservationError("signed Mesh feed requires --trust with locally pinned publisher grants")
        if set(raw) != {"adapter_version", "events"} or raw["adapter_version"] != self.version:
            raise ObservationError("unsupported Mesh adapter file")
        events = raw["events"]
        if not isinstance(events, list) or len(events) > MAX_ADVISORIES:
            raise ObservationError("invalid Mesh event count")
        findings: list[SignedFinding] = []
        withdrawals: set[tuple[str, str, str]] = set()
        seen_sequences: dict[tuple[str, int], tuple[str, str]] = {}
        seen_ids: dict[tuple[str, str], str] = {}
        for item in events:
            try:
                event = parse_event(json.dumps(item).encode("utf-8"))
                if isinstance(event, SignedFinding):
                    payload = event.finding
                    key = trust.authorize(payload.publisher_id, event.key_id, "finding", now)
                    # The original signature remains valid for historical
                    # display; currentness is assessed separately below.
                    verify(event, key, payload.issued_at)
                    event_id = str(payload.artifact_id)
                elif isinstance(event, SignedRevocation):
                    payload = event.revocation
                    if payload.target_publisher_id is None or payload.issued_at > now:
                        raise ObservationError("unscoped or future Mesh withdrawal")
                    key = trust.authorize_revocation(payload.publisher_id, event.key_id,
                                                      payload.target_publisher_id, now)
                    verify(event, key, payload.issued_at)
                    event_id = str(payload.revocation_id)
                    withdrawals.add((payload.target_publisher_id, str(payload.target_artifact_id),
                                     payload.target_sha256))
                digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
                sequence_key = (payload.publisher_id, payload.sequence)
                prior = seen_sequences.get(sequence_key)
                if prior is not None and prior != (event_id, digest):
                    raise ObservationError("publisher sequence conflict in local Mesh file")
                prior_digest = seen_ids.get((payload.publisher_id, event_id))
                if prior_digest is not None and prior_digest != digest:
                    raise ObservationError("event ID conflict in local Mesh file")
                if prior_digest is None:
                    seen_sequences[sequence_key] = (event_id, digest)
                    seen_ids[(payload.publisher_id, event_id)] = digest
                    if isinstance(event, SignedFinding):
                        findings.append(event)
            except ObservationError:
                raise
            except (ValueError, TypeError) as exc:
                raise ObservationError("invalid or untrusted signed Mesh event") from exc
        results: list[Advisory] = []
        for event in findings:
            finding = event.finding
            digest = hashlib.sha256(canonical_bytes(finding)).hexdigest()
            withdrawn = (finding.publisher_id, str(finding.artifact_id), digest) in withdrawals
            claim_status = ("withdrawn" if withdrawn else "future" if finding.issued_at > now
                            else "expired" if finding.expires_at <= now else "current")
            results.append(Advisory(
                finding.vulnerability_id, finding.software.purl,
                tuple(finding.software.affected_versions),
                "Signed Mesh lab finding; no host exploitability conclusion",
                f"aegis-mesh:{finding.publisher_id}:{finding.artifact_id}",
                finding.expires_at, None, "signed-mesh-v1-lab-scope",
                str(finding.artifact_id), digest, claim_status,
                publisher_authenticity="verified",
            ))
        return results


MAX_GRANT_BYTES = 1024 * 1024


def _read_grant_file(path: Path) -> bytes:
    """Read one regular grant inode through no-follow directory descriptors."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None or not hasattr(os, "O_NONBLOCK"):
        raise ObservationError("secure publisher grant reads are unavailable")
    parts = path.absolute().parts[1:]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ObservationError("invalid publisher grant path")
    # macOS's root-owned /var and /tmp aliases point to /private. Do not
    # permit arbitrary symlinks in either directory or the grant filename.
    if parts[0] in {"var", "tmp"}:
        alias = Path("/") / parts[0]
        target = Path("/private") / parts[0]
        if alias.is_symlink() and alias.lstat().st_uid == 0 and alias.resolve() == target:
            parts = ("private", parts[0], *parts[1:])
    directory = os.open("/", os.O_RDONLY | directory_flag | nofollow | getattr(os, "O_CLOEXEC", 0))
    try:
        for part in parts[:-1]:
            next_directory = os.open(part, os.O_RDONLY | directory_flag | nofollow |
                                     getattr(os, "O_CLOEXEC", 0), dir_fd=directory)
            os.close(directory)
            directory = next_directory
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | nofollow |
                     getattr(os, "O_CLOEXEC", 0), dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_GRANT_BYTES:
                raise ObservationError("publisher grant file exceeds input limit or is not regular")
            if before.st_uid not in {os.geteuid(), 0} or stat.S_IMODE(before.st_mode) & 0o022:
                raise ObservationError("publisher grant file has unsafe owner or write permissions")
            data = stream.read(MAX_GRANT_BYTES + 1)
            after = os.fstat(stream.fileno())
            if len(data) > MAX_GRANT_BYTES or after.st_size > MAX_GRANT_BYTES:
                raise ObservationError("publisher grant file exceeds input limit")
            identity = lambda meta: (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_nlink,
                                     meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)
            if identity(before) != identity(after) or len(data) != after.st_size:
                raise ObservationError("publisher grant file changed during read")
            selected = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
            if identity(selected) != identity(after):
                raise ObservationError("publisher grant path changed during read")
            return data
    finally:
        os.close(directory)


def load_intelligence(path: Path, *, trust_path: Path | None = None,
                      now: datetime | None = None) -> list[Advisory]:
    """Dispatch a temporary local file format to an explicitly versioned adapter."""
    now = now or utc_now()
    try:
        raw = json.loads(_read_bounded(path, MAX_FEED_BYTES))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ObservationError("cannot read local intelligence JSON") from exc
    if not isinstance(raw, dict):
        raise ObservationError("local intelligence must be an object")
    if raw.get("adapter_version") == MeshV1Adapter.version:
        if trust_path is None:
            raise ObservationError("signed Mesh feed requires --trust")
        try:
            trust = load_publishers_bytes(_read_grant_file(trust_path))
        except ObservationError:
            raise
        except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
            raise ObservationError("invalid local publisher grants") from exc
        return MeshV1Adapter().advisories(raw, now=now, trust=trust)
    raise ObservationError("unsupported local intelligence adapter version")
