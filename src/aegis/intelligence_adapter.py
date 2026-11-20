"""Versioned local intake adapters; no Mesh or enforcement contract changes."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import Protocol

from .artifact import SignedFinding, SignedRevocation, canonical_bytes, parse_event, verify
from .config import load_publishers, load_publishers_bytes
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


_MAX_GRANT_BYTES = 1024 * 1024


def _read_local_grants(path: Path) -> bytes:
    """Read one regular inode, once, with a bound before parsing publisher grants.

    Readable file modes remain accepted, as in the legacy path loader. Ownership,
    mode, and ACL policy require a separate reviewed compatibility decision.
    """
    parts = path.parts
    if not path.is_absolute():
        parts = (Path.cwd() / path).parts
    if not parts or parts[0] != "/" or any(part in ("", ".", "..") for part in parts[1:]):
        raise ObservationError("invalid local publisher grants")
    if sys.platform == "darwin" and len(parts) > 1 and parts[1] in ("var", "tmp"):
        alias = Path("/") / parts[1]
        alias_meta = alias.lstat()
        target = Path("/private") / parts[1]
        if (not stat.S_ISLNK(alias_meta.st_mode) or alias_meta.st_uid != 0
                or alias.resolve() != target or target.stat().st_uid != 0):
            raise ObservationError("invalid local publisher grants")
        parts = ("/", "private", *parts[1:])
    if len(parts) < 2:
        raise ObservationError("invalid local publisher grants")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    directory_fd = os.open("/", directory_flags)
    try:
        for component in parts[1:-1]:
            child_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
        file_fd = os.open(parts[-1], file_flags, dir_fd=directory_fd)
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                raise ObservationError("invalid local publisher grants")
            if before.st_size > _MAX_GRANT_BYTES:
                raise ObservationError("publisher grant file exceeds input limit")
            chunks: list[bytes] = []
            remaining = _MAX_GRANT_BYTES + 1
            while remaining:
                chunk = os.read(file_fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > _MAX_GRANT_BYTES:
                raise ObservationError("publisher grant file exceeds input limit")
            after = os.fstat(file_fd)
            fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
                      "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(before, field) != getattr(after, field) for field in fields) or len(data) != after.st_size:
                raise ObservationError("publisher grant file changed during read")
            return data
        finally:
            os.close(file_fd)
    finally:
        os.close(directory_fd)


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
            trust = load_publishers_bytes(_read_local_grants(trust_path))
        except ObservationError:
            raise
        except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
            raise ObservationError("invalid local publisher grants") from exc
        return MeshV1Adapter().advisories(raw, now=now, trust=trust)
    raise ObservationError("unsupported local intelligence adapter version")
