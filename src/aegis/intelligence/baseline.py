"""Deterministic normalization and conservative local relevance appraisal."""

import json
import re
from datetime import datetime, timezone, timedelta

from .models import Asset, Assessment, Claim, SourceRef, SourceSnapshot, VersionClaim

_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}", re.I)
_NUMERIC = re.compile(r"[0-9]+(?:\.[0-9]+)*")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _decode(source: SourceSnapshot) -> dict:
    data = json.loads(source.content, object_pairs_hook=_unique_pairs)
    if not isinstance(data, dict):
        raise ValueError("feed root must be an object")
    return data


def _ref(source: SourceSnapshot, pointer: str) -> SourceRef:
    return SourceRef(kind=source.kind, acquisition=source.acquisition, uri=source.uri, sha256=source.sha256,
                     retrieved_at=source.retrieved_at, pointer=pointer)


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ValueError("invalid vulnerability identifier")
    return value.upper() if _CVE.fullmatch(value) else value


def _purl(ecosystem: str, name: str) -> str | None:
    types = {"PyPI": "pypi", "npm": "npm", "Go": "golang", "Maven": "maven",
             "crates.io": "cargo", "RubyGems": "gem", "NuGet": "nuget"}
    if ecosystem not in types or not name or any(c in name for c in "@?#"):
        return None
    return f"pkg:{types[ecosystem]}/{name.lower() if ecosystem == 'PyPI' else name}"


def normalize(source: SourceSnapshot) -> tuple[Claim, ...]:
    data = _decode(source)
    claims: list[Claim] = []
    if source.kind == "osv":
        vid = _identifier(data["id"])
        if not source.uri.endswith("/" + vid):
            raise ValueError("OSV ID does not match source URI")
        aliases = tuple(_identifier(x) for x in data.get("aliases", []))
        severity = data.get("severity") or []
        score = severity[0].get("score") if severity else None
        severity_details = tuple((str(item.get("type", "")), str(item.get("score", "")), None)
                                 for item in severity)
        for i, affected in enumerate(data.get("affected", [])):
            package = affected.get("package") or {}
            ecosystem, name = package.get("ecosystem", ""), package.get("name", "")
            identity = package.get("purl") or _purl(ecosystem, name)
            kind = "purl" if identity else "ecosystem"
            identity = identity or f"{ecosystem}:{name}"
            versions = [VersionClaim(scheme="exact", value=v) for v in affected.get("versions", [])]
            for item in affected.get("ranges", []):
                raw_events = item.get("events", [])
                if any(not isinstance(event, dict) or len(event) != 1 or
                       next(iter(event)) not in {"introduced", "fixed", "last_affected", "limit"}
                       for event in raw_events):
                    raise ValueError("invalid OSV range event")
                events = tuple((k, str(v)) for event in raw_events for k, v in event.items())
                versions.append(VersionClaim(scheme="osv", value=item.get("type", ""), events=events,
                                             fixed=next((v for k, v in events if k == "fixed"), None)))
            claims.append(Claim(vulnerability_id=vid, aliases=aliases, identity_kind=kind,
                                identity=identity, versions=tuple(versions),
                                severity=str(score) if score else None, severity_details=severity_details,
                                exploited=None,
                                confidence="fixture" if source.acquisition == "fixture" else "aggregated",
                                missing=() if versions else ("affected-versions",),
                                summary=str(data.get("summary") or data.get("details") or "")[:4000],
                                published_at=data.get("published"), modified_at=data.get("modified"),
                                withdrawn_at=data.get("withdrawn"),
                                reference=_ref(source, f"/affected/{i}")))
    elif source.kind == "nvd":
        entries = data.get("vulnerabilities", [])
        if not isinstance(entries, list) or len(entries) != 1:
            raise ValueError("NVD lookup must contain exactly one CVE")
        cve = entries[0]["cve"]
        vid = _identifier(cve["id"])
        if not source.uri.endswith("cveId=" + vid):
            raise ValueError("NVD CVE does not match source URI")
        descriptions = cve.get("descriptions", [])
        summary = next((x.get("value", "") for x in descriptions if x.get("lang") == "en"), "")
        metrics = cve.get("metrics") or {}
        severity_details = tuple((k, str(item.get("cvssData", {}).get("vectorString", "")),
                                  float(item["cvssData"]["baseScore"]) if "baseScore" in item.get("cvssData", {}) else None)
                                 for k, values in metrics.items() if k.startswith("cvssMetric")
                                 for item in values)
        metric = next((v[0] for k, v in metrics.items() if k.startswith("cvssMetric") and v), {})
        cvss = metric.get("cvssData") or {}
        def walk(node, pointer):
            for j, match in enumerate(node.get("cpeMatch", [])):
                if match.get("vulnerable") is not True:
                    continue
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) < 6 or parts[:2] != ["cpe", "2.3"]:
                    continue
                identity = ":".join(parts[:5])
                bounds = tuple((k, str(match[k])) for k in ("versionStartIncluding", "versionStartExcluding",
                          "versionEndIncluding", "versionEndExcluding") if k in match)
                version = VersionClaim(scheme="cpe", value=parts[5], events=bounds)
                claims.append(Claim(vulnerability_id=vid, identity_kind="cpe", identity=identity,
                                    versions=(version,), severity=cvss.get("baseSeverity"),
                                    severity_score=float(cvss["baseScore"]) if "baseScore" in cvss else None,
                                    severity_details=severity_details, exploited=None,
                                    confidence="fixture" if source.acquisition == "fixture" else "official-record",
                                    missing=("configuration-context",),
                                    summary=summary[:4000], published_at=cve.get("published"),
                                    modified_at=cve.get("lastModified"),
                                    reference=_ref(source, f"{pointer}/cpeMatch/{j}")))
            for j, child in enumerate(node.get("nodes", [])):
                walk(child, f"{pointer}/nodes/{j}")
        for i, config in enumerate(cve.get("configurations", [])):
            walk(config, f"/vulnerabilities/0/cve/configurations/{i}")
        if not claims:
            claims.append(Claim(vulnerability_id=vid, identity_kind="unknown", identity="",
                                versions=(VersionClaim(scheme="none"),), severity=cvss.get("baseSeverity"),
                                severity_score=float(cvss["baseScore"]) if "baseScore" in cvss else None,
                                severity_details=severity_details, exploited=None,
                                confidence="fixture" if source.acquisition == "fixture" else "official-record",
                                missing=("affected-products", "affected-versions"),
                                summary=summary[:4000], published_at=cve.get("published"),
                                modified_at=cve.get("lastModified"),
                                reference=_ref(source, "/vulnerabilities/0/cve")))
    elif source.kind == "kev":
        if data.get("count") != len(data.get("vulnerabilities", [])):
            raise ValueError("KEV count mismatch")
        for i, item in enumerate(data.get("vulnerabilities", [])):
            claims.append(Claim(vulnerability_id=_identifier(item["cveID"]),
                                identity_kind="vendor-product",
                                identity=f"{item.get('vendorProject', '')}:{item.get('product', '')}",
                                versions=(VersionClaim(scheme="none"),), exploited=True,
                                confidence="fixture" if source.acquisition == "fixture" else "official-record",
                                missing=("affected-versions", "fixed-version"),
                                summary=str(item.get("shortDescription", ""))[:4000],
                                published_at=item.get("dateAdded"), modified_at=data.get("dateReleased"),
                                reference=_ref(source, f"/vulnerabilities/{i}")))
    elif source.kind == "vendor-ghsa":
        if not source.uri.endswith("/" + data["ghsa_id"]):
            raise ValueError("vendor GHSA ID does not match source URI")
        vid = _identifier(data.get("cve_id") or data["ghsa_id"])
        aliases = (_identifier(data["ghsa_id"]),) if vid != data["ghsa_id"] else ()
        for i, vuln in enumerate(data.get("vulnerabilities", [])):
            package = vuln.get("package") or {}
            ecosystem, name = package.get("ecosystem", ""), package.get("name", "")
            # GitHub uses lowercase ecosystem names, unlike OSV.
            mapping = {"pip": "PyPI", "rubygems": "RubyGems", "rust": "crates.io",
                       "go": "Go", "nuget": "NuGet", "maven": "Maven", "npm": "npm"}
            identity = _purl(mapping.get(ecosystem, ecosystem), name)
            version = VersionClaim(scheme="vendor-range", value=vuln.get("vulnerable_version_range") or "",
                                   fixed=vuln.get("first_patched_version"))
            claims.append(Claim(vulnerability_id=vid, aliases=aliases,
                                identity_kind="purl" if identity else "ecosystem",
                                identity=identity or f"{ecosystem}:{name}", versions=(version,),
                                severity=data.get("severity"),
                                severity_details=(("vendor-label", str(data.get("severity")), None),)
                                if data.get("severity") else (), exploited=None,
                                confidence="fixture" if source.acquisition == "fixture" else "vendor-published",
                                missing=() if version.value else ("affected-versions",),
                                summary=str(data.get("summary") or "")[:4000],
                                published_at=data.get("published_at"), modified_at=data.get("updated_at"),
                                withdrawn_at=data.get("withdrawn_at"),
                                reference=_ref(source, f"/vulnerabilities/{i}")))
    return tuple(claims)


def _parts(value: str) -> tuple[int, ...] | None:
    if not _NUMERIC.fullmatch(value):
        return None
    return tuple(int(x) for x in value.split("."))


def _compare(left: str, right: str) -> int | None:
    a, b = _parts(left), _parts(right)
    if a is None or b is None:
        return None
    count = max(len(a), len(b))
    a, b = a + (0,) * (count - len(a)), b + (0,) * (count - len(b))
    return (a > b) - (a < b)


def _version_status(version: str, claim: VersionClaim) -> bool | None:
    if claim.scheme == "exact":
        return version == claim.value
    if claim.scheme == "osv" and claim.value in {"ECOSYSTEM", "SEMVER"}:
        active = False
        for event, point in claim.events:
            order = _compare(version, point) if point != "0" else 1
            if order is None:
                return None
            if event == "introduced" and order >= 0:
                active = True
            elif event in {"fixed", "limit"} and order >= 0:
                active = False
            elif event == "last_affected" and order > 0:
                active = False
        return active if claim.events and claim.events[0][0] == "introduced" else None
    if claim.scheme == "vendor-range":
        clauses = re.split(r"\s*,\s*", claim.value)
        for clause in clauses:
            match = re.fullmatch(r"(<=|>=|<|>|=)\s*([0-9]+(?:\.[0-9]+)*)", clause)
            if not match:
                return None
            op, bound = match.groups()
            order = _compare(version, bound)
            if order is None:
                return None
            if not {"<": order < 0, "<=": order <= 0, ">": order > 0,
                    ">=": order >= 0, "=": order == 0}[op]:
                return False
        return bool(clauses)
    return None


def assess(asset: Asset, claims: tuple[Claim, ...] | list[Claim], vulnerability_id: str,
           *, now: datetime | None = None, max_source_age_days: int = 7) -> Assessment:
    vid = _identifier(vulnerability_id)
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or not 1 <= max_source_age_days <= 365:
        raise ValueError("invalid source freshness policy")
    relevant = [c for c in claims if vid in (c.vulnerability_id, *c.aliases)
                and c.identity_kind == asset.identity_kind and c.identity == asset.identity]
    statuses = []
    reasons = []
    for claim in relevant:
        if claim.withdrawn_at:
            statuses.append(None)
            reasons.append("source advisory is withdrawn")
            continue
        if claim.reference.retrieved_at > now or now - claim.reference.retrieved_at > timedelta(days=max_source_age_days):
            statuses.append(None)
            reasons.append("source snapshot is stale or from the future")
            continue
        if "configuration-context" in claim.missing:
            statuses.append(None)
            reasons.append("source configuration logic needs independent verification")
            continue
        results = [_version_status(asset.version, v) for v in claim.versions]
        statuses.append(True if True in results else None if None in results else False)
        if None in results:
            reasons.append("version syntax or affected range is unsupported")
    if True in statuses and False in statuses:
        outcome = "conflicting"
    elif not statuses or None in statuses:
        outcome = "unknown"
    else:
        outcome = "affected" if True in statuses else "unaffected"
    if not reasons:
        reasons = ["exact identity and supported source version claims" if statuses else "no exact source identity match"]
    return Assessment(asset_id=asset.asset_id, vulnerability_id=vid, outcome=outcome,
                      reasons=tuple(dict.fromkeys(reasons)), references=tuple(c.reference for c in relevant))
