"""Bounded official read-only feed retrieval; fixtures use the same snapshot path."""

import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .models import SourceSnapshot

MAX_BYTES = 8 * 1024 * 1024
KEV_URI = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_GHSA = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.I)
_OSV = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}")
_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}")


def snapshot(kind: str, uri: str, content: bytes, *, retrieved_at: datetime | None = None,
             acquisition: str = "fixture") -> SourceSnapshot:
    if not isinstance(content, bytes) or len(content) > MAX_BYTES:
        raise ValueError("feed body exceeds limit")
    return SourceSnapshot(kind=kind, acquisition=acquisition, uri=uri, content=content,
                          retrieved_at=retrieved_at or datetime.now(timezone.utc),
                          sha256=hashlib.sha256(content).hexdigest())


def archive_snapshot(source: SourceSnapshot, directory: Path) -> Path:
    """Keep raw source bytes by content digest; an existing pin is never overwritten."""
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{source.sha256}.json"
    try:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if destination.read_bytes() != source.content:
            raise ValueError("archive digest collision or changed bytes")
        return destination
    with os.fdopen(fd, "wb") as handle:
        handle.write(source.content)
        handle.flush()
        os.fsync(handle.fileno())
    return destination


class FeedClient:
    """Source catalog only. Retrieval requires a later enrolled collector."""

    def __init__(self, *, vendor_repositories: frozenset[str] = frozenset()):
        self.vendor_repositories = vendor_repositories

    def canonical_uri(self, kind: str, identifier: str = "", *, repository: str = "") -> str:
        if kind == "nvd" and _CVE.fullmatch(identifier):
            return "https://services.nvd.nist.gov/rest/json/cves/2.0/?cveId=" + identifier
        elif kind == "osv" and _OSV.fullmatch(identifier):
            return "https://api.osv.dev/v1/vulns/" + identifier
        elif kind == "kev" and not identifier:
            return KEV_URI
        elif (kind == "vendor-ghsa" and _GHSA.fullmatch(identifier)
              and repository in self.vendor_repositories and len(repository.split("/")) == 2
              and all(_REPO.fullmatch(part) for part in repository.split("/"))):
            return f"https://api.github.com/repos/{repository}/security-advisories/{identifier}"
        else:
            raise ValueError("source or target is not allowlisted")

    def fetch(self, kind: str, identifier: str = "", *, repository: str = "") -> SourceSnapshot:
        raise ValueError("external feed retrieval is not enrolled")
