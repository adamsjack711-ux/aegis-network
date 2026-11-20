"""Private, non-authoritative atomic observations over exact offline source bytes."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


_DIGEST = r"^[a-f0-9]{64}$"
_EFFECT = "availability degradation"
_SOURCE_IDENTITY = re.compile(r"\b(npm|pypi|debian|maven)(?:\s+package|\s+source\s+package)?\s+([a-z0-9_.:@-]+)", re.I)
_AFFIRMATIVE_EFFECT = re.compile(r"\b(?:can cause|causes|caused|results in|leads to)\s+availability degradation\b", re.I)


class AtomicSourceClaim(BaseModel):
    """A narrow fixture-text observation, never a verified defense artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    schema_version: Literal["phase5a-source-claim-v1"] = "phase5a-source-claim-v1"
    source_id: str = Field(min_length=1, max_length=128)
    source_sha256: str = Field(pattern=_DIGEST)
    source_locator: str = Field(min_length=1)
    byte_start: int = Field(ge=0)
    byte_end: int = Field(gt=0)
    quote: str = Field(min_length=1, max_length=512)
    acquisition: Literal["sealed-local-fixture", "pinned-inline-fixture"]
    source_role: str = Field(min_length=1, max_length=64)
    source_status: Literal["current-fixture"] = "current-fixture"
    product_ecosystem: str = Field(min_length=1, max_length=64)
    product_name: str = Field(min_length=1, max_length=256)
    source_product_ecosystem: str = Field(min_length=1, max_length=64)
    source_product_name: str = Field(min_length=1, max_length=256)
    asset_version: str = Field(min_length=1, max_length=128)
    claim_kind: Literal["version-applicability", "effect"]
    version_predicate: str = Field(min_length=1, max_length=128)
    polarity: Literal["affected", "unaffected"]
    effect_type: Literal["availability-degradation"] | None = None
    support: Literal["fixture-parser-consistent"] = "fixture-parser-consistent"
    independently_verified: Literal[False] = False

    @model_validator(mode="after")
    def coherent_fields(self):
        if self.byte_end <= self.byte_start:
            raise ValueError("empty source locator")
        if (self.claim_kind == "effect") != (self.effect_type is not None):
            raise ValueError("effect field mismatch")
        if self.claim_kind == "effect" and self.polarity != "affected":
            raise ValueError("effect requires affected source predicate")
        return self


def exact_source_bytes(root: Path, source: dict) -> tuple[bytes, str]:
    """Reopen the sealed source; inline legacy text is pinned by its corpus hash."""
    if "raw_path" not in source:
        return source["text"].encode("utf-8"), "pinned-inline-fixture"
    path = (root / source["raw_path"]).resolve()
    allowed = (root / "fixtures/phase-next-alpha-ai/sources").resolve()
    if not path.is_relative_to(allowed):
        raise ValueError("source locator escapes fixture root")
    raw = path.read_bytes()
    if (hashlib.sha256(raw).hexdigest() != source["sha256"] or
            len(raw) != source["bytes"] or raw.decode("utf-8").rstrip("\n") != source["text"]):
        raise ValueError("source bytes differ from sealed record")
    return raw, "sealed-local-fixture"


def _span(text: str, *, kind: str, predicate: str, asset_version: str) -> tuple[int, int, str]:
    """Select an exact phrase, never an inferred or generated summary."""
    if kind == "effect":
        affirmative = _AFFIRMATIVE_EFFECT.search(text)
        if affirmative is None:
            raise ValueError("no affirmative effect phrase")
        start_char, end_char = affirmative.end() - len(_EFFECT), affirmative.end()
        return (len(text[:start_char].encode()), len(text[:end_char].encode()),
                text[start_char:end_char])
    elif predicate == "explicit-numeric-range":
        match = re.search(r"(?:>=|<=|<|>)\s*[0-9]+(?:\.[0-9]+)*(?:\s+and\s+(?:>=|<=|<|>)\s*[0-9]+(?:\.[0-9]+)*)?", text)
    elif predicate == "explicit-inclusive-range":
        match = re.search(r"versions?\s+[0-9]+(?:\.[0-9]+)*\s+through\s+[0-9]+(?:\.[0-9]+)*", text, re.I)
    elif predicate == "explicit-inclusive-upper-bound":
        match = re.search(r"versions?\s+through\s+[0-9]+(?:\.[0-9]+)*", text, re.I)
    elif predicate == "explicit-before-range":
        match = re.search(r"before\s+[0-9]+(?:\.[0-9]+)*", text, re.I)
    elif predicate == "explicit-unrelated-product":
        match = re.search(r"\bunrelated\b|\bdistinct product\b", text, re.I)
    else:
        match = re.search(r"(?<![A-Za-z0-9.])" + re.escape(asset_version) + r"(?![A-Za-z0-9.])", text, re.I)
    if match is None:
        raise ValueError("no exact source phrase for claim")
    start, end = len(text[:match.start()].encode()), len(text[:match.end()].encode())
    return start, end, text[match.start():match.end()]


def affirmative_effect(text: str, asset: dict | None = None) -> bool:
    match = _AFFIRMATIVE_EFFECT.search(text)
    if match is None:
        return False
    prior_sentence = text.rfind(". ", 0, match.start())
    sentence_start = prior_sentence + 2 if prior_sentence >= 0 else 0
    sentence_end = text.find(". ", match.end())
    sentence = text[sentence_start:sentence_end if sentence_end >= 0 else len(text)]
    if re.search(r"\b(?:different|another|unrelated)\b", sentence, re.I):
        return False
    if asset is not None:
        identities = list(_SOURCE_IDENTITY.finditer(text))
        local = _SOURCE_IDENTITY.search(sentence)
        if local is None:
            subject = sentence[:match.start() - sentence_start].strip()
            if not re.fullmatch(r"(?:a|an) crafted (?:document|request|input|packet)", subject, re.I):
                return False
        if len(identities) > 1 and local is None:
            return False
        if local is not None:
            ecosystem = {"debian": "deb"}.get(local.group(1).lower(), local.group(1).lower())
            if ecosystem != asset["ecosystem"].lower() or local.group(2).lower() != asset["name"].lower():
                return False
    return True


def build_atomic_claim(root: Path, source: dict, asset: dict, *, polarity: str,
                       predicate: str, kind: Literal["version-applicability", "effect"] = "version-applicability") -> AtomicSourceClaim:
    if polarity not in {"affected", "unaffected"}:
        raise ValueError("inconclusive source cannot form positive atomic claim")
    raw, acquisition = exact_source_bytes(root, source)
    text = raw.decode("utf-8")
    identity = _SOURCE_IDENTITY.search(text)
    if identity is None:
        raise ValueError("source product identity missing")
    source_ecosystem = {"debian": "deb"}.get(identity.group(1).lower(), identity.group(1).lower())
    start, end, quote = _span(text, kind=kind, predicate=predicate, asset_version=asset["version"])
    claim = AtomicSourceClaim(source_id=source["id"], source_sha256=hashlib.sha256(raw).hexdigest(),
                              source_locator=f"utf8-byte:{start}:{end}", byte_start=start, byte_end=end,
                              quote=quote, acquisition=acquisition, source_role=source.get("role", "unknown"),
                              product_ecosystem=asset["ecosystem"], product_name=asset["name"],
                              source_product_ecosystem=source_ecosystem,
                              source_product_name=identity.group(2).lower(),
                              asset_version=asset["version"], claim_kind=kind,
                              version_predicate=predicate, polarity=polarity,
                              effect_type="availability-degradation" if kind == "effect" else None)
    verify_atomic_claim(claim, raw, source, asset, polarity=polarity, predicate=predicate)
    return claim


def verify_atomic_claim(claim: AtomicSourceClaim, raw: bytes, source: dict, asset: dict,
                        *, polarity: str, predicate: str) -> None:
    """Check byte binding and typed associations. Semantic truth remains unproven."""
    from .alpha_eval import _clean_text, _source_decision

    text = raw.decode("utf-8")
    identity = _SOURCE_IDENTITY.search(text)
    if identity is None:
        raise ValueError("source product identity missing")
    source_ecosystem = {"debian": "deb"}.get(identity.group(1).lower(), identity.group(1).lower())
    stamp = source.get("retrieved_at")
    if (source.get("role") not in {"vendor", "registry"} or
            stamp and datetime.fromisoformat(stamp.replace("Z", "+00:00")) <
            datetime(2026, 11, 13, tzinfo=timezone.utc) or
            "withdrawn" in text.lower()):
        raise ValueError("source status is not current fixture")
    decision, checked_predicate = _source_decision(text, asset)
    expected_acquisition = "sealed-local-fixture" if "raw_path" in source else "pinned-inline-fixture"
    expected_start, expected_end, expected_quote = _span(
        text, kind=claim.claim_kind, predicate=predicate, asset_version=asset["version"])
    if (claim.source_id != source["id"] or claim.source_sha256 != hashlib.sha256(raw).hexdigest() or
            ("sha256" in source and source["sha256"] != claim.source_sha256) or
            claim.source_role != source["role"] or claim.acquisition != expected_acquisition or
            claim.source_locator != f"utf8-byte:{claim.byte_start}:{claim.byte_end}" or
            (claim.byte_start, claim.byte_end, claim.quote) !=
            (expected_start, expected_end, expected_quote) or
            claim.byte_end > len(raw) or raw[claim.byte_start:claim.byte_end].decode("utf-8") != claim.quote or
            claim.product_ecosystem != asset["ecosystem"] or claim.product_name != asset["name"] or
            claim.source_product_ecosystem != source_ecosystem or
            claim.source_product_name != identity.group(2).lower() or
            claim.asset_version != asset["version"] or claim.polarity != polarity or
            claim.version_predicate != predicate or decision != polarity or checked_predicate != predicate):
        raise ValueError("atomic claim/source association mismatch")
    if claim.claim_kind == "effect" and (
        claim.quote.lower() != _EFFECT or not affirmative_effect(_clean_text(text), asset)
    ):
        raise ValueError("unsupported effect quote")
