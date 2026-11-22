"""Pure, synthetic Phase 4F byte framing. No transport, stores or authority output."""

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from datetime import timedelta

from cryptography.exceptions import InvalidSignature

from aegis.artifact import SignedFinding, SignedRevocation, canonical_bytes
from aegis.evidence.records import MAX_RECORD, SignedManifest, canonical as evidence_canonical, decode, digest
from aegis.evidence.status import EvidenceHistory
from aegis.evidence.status_protocol import (
    MAX_HISTORY, STATUS_TTL, Challenge, Scope, SignedEndorsement, archive_head, endorsement_bytes, material_scope,
)
from aegis.journal.merkle import EMPTY, MAX_SIZE, Tree, verify_consistency, verify_inclusion
from aegis.journal.protocol import Admission, JournalBlocked, Vote, canonical
from aegis.mitigation.policy import Denied
from aegis.phase3c import check_bundle, claim_bytes


V1 = "aegis.phase4f.read"
KINDS = {name: f"{V1}.{name}.v1" for name in (
    "challenge", "floor", "view", "view-request", "entry", "obligation", "leaf", "anchor",
    "page", "page-request", "error", "result", "t5-capture",
)}
DOMAINS = {name: f"aegis-native-t4-{name}/v1".encode() + b"\x00"
           for name in ("obligation", "anchor", "floor", "view")}
PAGE_MAX = 16
PAGES_MAX = 64
OBLIGATIONS_MAX = 1024
SOURCE_MAX = 256 * 1024
T4_MAX = 8 * 1024 * 1024
ALL_MAX = 16 * 1024 * 1024
MAX_TIME = 2000
MAX_ATTEMPTS = 74  # 72 primary slots and up to two transport retries.
ROLE_BOUNDS = {"floor": (2, 64 * 1024), "view": (4, 64 * 1024),
               "page": (PAGES_MAX, 512 * 1024), "t5": (2, 3 * 1024 * 1024)}
ZERO_HEAD = {"size": 0, "root": EMPTY.hex()}


class Stop(Exception):
    def __init__(self, code, stage, admission_ms=None):
        super().__init__(code, stage)
        self.code, self.stage, self.admission_ms = code, stage, admission_ms

    def wire(self):
        body = {"kind": KINDS["error"], "outcome": "unknown_hold", "code": self.code, "stage": self.stage}
        if self.admission_ms is not None:
            body["pending_admission_ms"] = self.admission_ms
        return canonical(body)


def need(condition, code, stage):
    if not condition:
        raise Stop(code, stage)


def number(value, minimum=0, maximum=MAX_SIZE):
    return type(value) is int and minimum <= value <= maximum


def hexed(value, length=64):
    return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{length}}}", value) is not None


def fields(value, names, stage):
    need(isinstance(value, dict) and set(value) == set(names.split()), "INVALID_WIRE", stage)


def object_wire(raw, stage):
    def unique(pairs):
        obj = dict(pairs)
        if len(obj) != len(pairs):
            raise ValueError("duplicate member")
        return obj

    def reject_constant(token):
        raise ValueError(f"non-JSON token {token}")

    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject_constant)
        need(canonical(obj) == raw and isinstance(obj, dict), "INVALID_WIRE", stage)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise Stop("INVALID_WIRE", stage) from error
    return obj


def frame(raw, name, names):
    body = object_wire(raw, name)
    fields(body, "kind " + names, name)
    need(body["kind"] == KINDS[name], "WRONG_SCOPE", name)
    return body


def signed_wire(name, body, key):
    if body["kind"] != KINDS[name]:
        raise ValueError("wrong fixture signing kind")
    return canonical({"body": body, "signature": key.sign(DOMAINS[name] + canonical(body)).hex()})


def authenticate(raw, name, names, key):
    wire = object_wire(raw, name)
    fields(wire, "body signature", name)
    body = wire["body"]
    fields(body, "kind " + names, name)
    need(body["kind"] == KINDS[name], "WRONG_SCOPE", name)
    need(hexed(wire["signature"], 128), "INVALID_WIRE", name)
    try:
        key.verify(bytes.fromhex(wire["signature"]), DOMAINS[name] + canonical(body))
    except InvalidSignature as error:
        raise Stop("INVALID_AUTHENTICATION", name) from error
    return body


def read_head(value, stage):
    fields(value, "size root", stage)
    need(number(value["size"]) and hexed(value["root"]), "INVALID_WIRE", stage)
    need(value["size"] or value["root"] == EMPTY.hex(), "INCOMPLETE_PROOF", stage)
    return value


def proof_nodes(value, stage):
    need(isinstance(value, list), "INVALID_WIRE", stage)
    need(len(value) <= 64, "LIMIT", stage)
    need(all(hexed(node) for node in value), "INVALID_WIRE", stage)
    return tuple(bytes.fromhex(node) for node in value)


def tree_head(tree):
    return {"size": tree.size, "root": tree.root(tree.size).hex()}


def timebox(body, clock, stage, lifetime=MAX_TIME, issued_after=None):
    issued, expires = body["issued_ms"], body["expires_ms"]
    need(number(issued) and number(expires) and 0 < expires - issued <= lifetime, "INVALID_WIRE", stage)
    need(issued_after is None or issued >= issued_after, "WRONG_SCOPE", stage)
    need(issued <= clock["lower_ms"] <= clock["upper_ms"] < expires, "EXPIRED", stage)


@dataclass
class Budget:
    """Count attempted reads before body availability; accumulate bounded identity bodies."""

    attempts: int = 0
    retries: int = 0
    total: int = 0
    t4: int = 0
    slots: dict = field(default_factory=dict)
    elapsed: int = 0

    def read(self, role, index, chunks, *, declared=None, encoding="identity", outcome="received", elapsed=0):
        need(number(elapsed) and self.elapsed <= elapsed < MAX_TIME, "DEADLINE", role)
        self.elapsed = elapsed
        count, cap = ROLE_BOUNDS[role]
        need(number(index, 0, count - 1), "LIMIT", role)
        need(self.attempts < MAX_ATTEMPTS, "ATTEMPT_LIMIT", role)
        slot = role, index
        need(outcome in ("received", "unavailable"), "INVALID_WIRE", role)
        if slot in self.slots:
            need(self.slots[slot] == "unavailable" and self.retries < 2, "ATTEMPT_LIMIT", role)
            self.retries += 1
            self.slots[slot] = "retried"
        else:
            self.slots[slot] = "started"
        self.attempts += 1

        need(encoding == "identity", "INVALID_ENCODING", role)
        need(declared is None or number(declared), "INVALID_WIRE", role)
        need(declared is None or declared <= cap, "RESPONSE_LIMIT", role)
        body = bytearray()
        for chunk in chunks:
            need(type(chunk) is bytes, "INVALID_WIRE", role)
            size = len(chunk)
            # Count actual identity-decoded bytes before accumulating or parsing.
            self.total += size
            if role != "t5":
                self.t4 += size
            need(len(body) + size <= cap, "RESPONSE_LIMIT", role)
            need(self.total <= ALL_MAX, "AGGREGATE_LIMIT", role)
            need(self.t4 <= T4_MAX, "T4_AGGREGATE_LIMIT", role)
            body.extend(chunk)
        need(declared is None or declared == len(body), "INCOMPLETE_PROOF", role)
        if outcome != "received":
            if self.slots[slot] == "started":
                self.slots[slot] = "unavailable"
            raise Stop("SOURCE_UNAVAILABLE", role)
        self.slots[slot] = "received"
        return bytes(body)


def challenge(raw, policy, prior, clock):
    body = frame(raw, "challenge", "audience context workload store nonce prior lower_ms upper_ms")
    need(all(body[key] == policy[key] for key in ("context", "audience", "workload", "store")),
         "WRONG_SCOPE", "challenge")
    need(hexed(body["nonce"]) and number(body["lower_ms"]) and number(body["upper_ms"])
         and body["lower_ms"] <= body["upper_ms"] <= clock["upper_ms"]
         and body["upper_ms"] - body["lower_ms"] <= 200, "CLOCK", "challenge")
    need(read_head(body["prior"], "challenge") == prior, "ROLLBACK", "challenge")
    return body


def floor(raw, query, query_body, prior, protected, policy, authority, clock):
    body = authenticate(raw, "floor", "anchor_id context challenge_sha256 head witnesses consistency issued_ms expires_ms",
                        authority.anchor["independent-anchor"])
    need(body["anchor_id"] == "independent-anchor" and body["context"] == policy["context"]
         and body["challenge_sha256"] == digest(query), "WRONG_SCOPE", "floor")
    timebox(body, clock, "floor", issued_after=query_body["lower_ms"])
    head = read_head(body["head"], "floor")
    need(head["size"] >= prior["size"] and head["size"] >= protected["size"], "ROLLBACK", "floor")
    for independently_seen in (prior, protected):
        if independently_seen["size"] == head["size"]:
            need(independently_seen["root"] == head["root"], "CONFLICTING_FLOOR", "floor")
    need(head == protected, "INCOMPLETE_PROOF", "floor")
    need(head["size"] <= OBLIGATIONS_MAX, "LIMIT", "floor")
    nodes = proof_nodes(body["consistency"], "floor")
    need(verify_consistency(prior["size"], head["size"], bytes.fromhex(prior["root"]),
                            bytes.fromhex(head["root"]), nodes), "INCOMPLETE_PROOF", "floor")
    need(isinstance(body["witnesses"], dict) and set(body["witnesses"]) == set(authority.t4.operators),
         "INCOMPLETE_PROOF", "floor")
    for value in body["witnesses"].values():
        read_head(value, "floor")
    return body


def view(raw, name, first, view_request, first_query, first_floor, policy, authority, clock):
    body = authenticate(raw, "view", "witness_id context challenge_sha256 floor_sha256 head"
                        " request_sha256 complete pending_admission_ms issued_ms expires_ms", authority.t4.operators[name])
    need(body["witness_id"] == name and body["context"] == policy["context"]
         and body["challenge_sha256"] == digest(first_query)
         and body["floor_sha256"] == digest(first_floor) and body["request_sha256"] == digest(view_request),
         "WRONG_SCOPE", "view")
    timebox(body, clock, "view", issued_after=first["issued_ms"])
    need(type(body["complete"]) is bool, "INVALID_WIRE", "view")
    head = read_head(body["head"], "view")
    if body["pending_admission_ms"] is not None:
        need(number(body["pending_admission_ms"], maximum=body["issued_ms"]), "INVALID_WIRE", "view")
        raise Stop("PENDING_INTAKE", "view", body["pending_admission_ms"])
    need(body["complete"] and head == first["witnesses"][name],
         "INCOMPLETE_PROOF", "view")
    return body["issued_ms"], body["expires_ms"]


@dataclass
class Projection:
    authority: object
    policy: dict
    first: dict
    anchors: Tree = field(default_factory=Tree)
    slots: dict = field(init=False)
    events: dict = field(default_factory=dict)
    sequences: dict = field(default_factory=dict)
    witnessed: set = field(default_factory=set)
    matches: dict = field(default_factory=dict)

    def __post_init__(self):
        self.slots = {name: Tree() for name in self.authority.t4.operators}

    def entry(self, value):
        fields(value, "leaf obligation acceptance inclusion", "entry")
        leaf = value["leaf"]
        fields(leaf, "kind context ordinal witness_id witness_ordinal source obligation_sha256", "entry")
        name = leaf["witness_id"]
        n = self.anchors.size
        need(leaf["kind"] == KINDS["leaf"] and leaf["context"] == self.policy["context"]
             and isinstance(name, str) and name in self.slots, "WRONG_SCOPE", "entry")
        need(number(leaf["ordinal"]) and number(leaf["witness_ordinal"])
             and leaf["ordinal"] == n and leaf["witness_ordinal"] == self.slots[name].size,
             "INCOMPLETE_PROOF", "entry")
        raw = bounded_source(canonical(leaf["source"]))
        try:
            envelope = SignedRevocation.model_validate_json(raw)
            revocation = envelope.revocation
            need(canonical(envelope) == raw and revocation.schema_version == "1.1", "INVALID_WIRE", "entry")
        except ValueError as error:
            raise Stop("INVALID_WIRE", "entry") from error

        obligation_raw = canonical(value["obligation"])
        obligation = authenticate(obligation_raw, "obligation", "entry witness_head", self.authority.t4.operators[name])
        need(leaf["obligation_sha256"] == digest(obligation_raw), "INCOMPLETE_PROOF", "entry")
        core = obligation["entry"]
        fields(core, "kind context witness_id ordinal event_id sequence revoker revoker_key"
               " source_sha256 body_sha256 admission vote admitted_ms grant_sha256 trust_cut_sha256 target", "entry")
        fields(core["target"], "publisher_id artifact_id finding_body_sha256", "entry")
        target = {"publisher_id": revocation.target_publisher_id, "artifact_id": str(revocation.target_artifact_id),
                  "finding_body_sha256": revocation.target_sha256}
        check = {"kind": KINDS["entry"], "witness_id": name, "context": self.policy["context"],
                 "ordinal": leaf["witness_ordinal"], "event_id": str(revocation.revocation_id),
                 "sequence": revocation.sequence, "revoker": revocation.publisher_id, "revoker_key": envelope.key_id,
                 "source_sha256": digest(raw), "body_sha256": digest(canonical_bytes(revocation)), "target": target,
                 "grant_sha256": self.policy["grant_sha256"], "trust_cut_sha256": self.policy["trust_cut_sha256"]}
        need(all(type(core[k]) is type(v) and core[k] == v for k, v in check.items()), "WRONG_SCOPE", "entry")

        admitted = core["admitted_ms"]
        need(isinstance(admitted, list) and len(admitted) == 2 and all(number(item) for item in admitted)
             and admitted[0] <= admitted[1] <= self.first["issued_ms"]
             and admitted[1] - admitted[0] <= 200, "CLOCK", "entry")
        try:
            admission = Admission.model_validate(core["admission"])
            vote = Vote.model_validate(core["vote"])
            epoch_ms = self.authority.t4.epoch_seconds * 1000
            need(admission.context == self.policy["context"] and admission.event == digest(raw)
                 and vote.operator == name and all(admission.epoch == moment // epoch_ms for moment in admitted),
                 "WRONG_SCOPE", "entry")
            self.authority.t4.check_vote(admission, vote)
            grant = self.authority.t4.trust.grants[(revocation.publisher_id, envelope.key_id)]
            epoch_cutoff = self.authority.t4.cutoff(admission.epoch)
            if grant.revoked_at is not None:
                need(epoch_cutoff <= grant.revoked_at.timestamp(), "WRONG_SCOPE", "entry")
            for at in admitted:
                self.authority.t4.validate_event(envelope, self.policy["timestamp"](at // 1000) + timedelta(milliseconds=at % 1000))
        except (ValueError, JournalBlocked, KeyError) as error:
            raise Stop("INVALID_AUTHENTICATION", "entry") from error

        leaf_wire = canonical(leaf)
        final = self.first["head"]
        need(verify_inclusion(leaf_wire, n, final["size"], bytes.fromhex(final["root"]),
                              proof_nodes(value["inclusion"], "entry")), "INCOMPLETE_PROOF", "entry")
        self.slots[name].append(canonical(core))
        need(read_head(obligation["witness_head"], "entry") == tree_head(self.slots[name]),
             "INCOMPLETE_PROOF", "entry")
        self.anchors.append(leaf_wire)
        acceptance = authenticate(canonical(value["acceptance"]), "anchor",
                                  "anchor_id context ordinal leaf_sha256 head", self.authority.anchor["independent-anchor"])
        need(number(acceptance["ordinal"]) and acceptance == {
            "kind": KINDS["anchor"], "anchor_id": "independent-anchor", "context": self.policy["context"],
            "ordinal": n, "leaf_sha256": digest(leaf_wire), "head": tree_head(self.anchors),
        }, "INCOMPLETE_PROOF", "entry")
        event_id = check["event_id"]
        sequence = revocation.publisher_id, revocation.sequence
        need(self.events.get(event_id, raw) == raw and self.sequences.get(sequence, event_id) == event_id,
             "SIGNED_CONFLICT", "entry")
        need((name, event_id) not in self.witnessed, "INCOMPLETE_PROOF", "entry")
        self.events[event_id] = raw
        self.sequences[sequence] = event_id
        self.witnessed.add((name, event_id))
        if target == self.policy["target"]:
            previous = self.matches.get(event_id)
            if previous is None or admitted[0] < previous["admission_ms"]:
                self.matches[event_id] = {
                    "admission_ms": admitted[0], "source_sha256": digest(raw), "body_sha256": check["body_sha256"],
                    "native_admission_sha256": digest(canonical(admission)),
                    "obligation_sha256": digest(obligation_raw), "anchor_acceptance_sha256": digest(canonical(value["acceptance"])),
                }


def request_scope(challenge_raw, floor_raw, policy):
    return {"context": policy["context"], "challenge_sha256": digest(challenge_raw),
            "floor_sha256": digest(floor_raw)}


def project(pages, requests, first_query, first_floor, first, policy, authority, request_size):
    need(number(request_size, 1, PAGE_MAX), "LIMIT", "page")
    need(len(pages) <= PAGES_MAX and len(requests) <= PAGES_MAX, "LIMIT", "page")
    need(len(pages) == len(requests), "INCOMPLETE_PROOF", "page")
    observed = Projection(authority, policy, first)
    scope = request_scope(first_query, first_floor, policy)
    for raw, request_raw in zip(pages, requests, strict=True):
        request = frame(request_raw, "page-request", "context challenge_sha256 floor_sha256 start requested")
        page = frame(raw, "page", "context challenge_sha256 floor_sha256 start requested next entries request_sha256")
        need(all(page[k] == request[k] == v for k, v in scope.items()), "WRONG_SCOPE", "page")
        requested, start = page["requested"], observed.anchors.size
        need(number(requested, 1, PAGE_MAX) and number(request["requested"], 1, PAGE_MAX)
             and isinstance(page["entries"], list) and len(page["entries"]) <= PAGE_MAX, "LIMIT", "page")
        need(requested == request["requested"] == request_size and page["request_sha256"] == digest(request_raw),
             "WRONG_SCOPE", "page")
        count = min(requested, first["head"]["size"] - start)
        need(count > 0 and number(page["start"]) and number(request["start"]) and number(page["next"])
             and page["start"] == request["start"] == start and len(page["entries"]) == count
             and page["next"] == start + count, "INCOMPLETE_PROOF", "page")
        for entry in page["entries"]:
            observed.entry(entry)
    need(tree_head(observed.anchors) == first["head"] and
         {name: tree_head(tree) for name, tree in observed.slots.items()} == first["witnesses"],
         "INCOMPLETE_PROOF", "page")
    need(len(observed.matches) <= 1, "AMBIGUOUS_SCOPE", "entry")
    return observed.matches


def bounded_source(raw):
    need(len(raw) <= SOURCE_MAX, "SOURCE_LIMIT", "entry")
    return raw


def unbase(value, maximum):
    need(isinstance(value, str), "INVALID_WIRE", "t5")
    need(len(value) <= 4 * ((maximum + 2) // 3), "LIMIT", "t5")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise Stop("INVALID_WIRE", "t5") from error
    need(base64.b64encode(raw).decode("ascii") == value, "INVALID_WIRE", "t5")
    need(len(raw) <= maximum, "LIMIT", "t5")
    return raw


def evidence_records(wires):
    need(isinstance(wires, list), "INVALID_WIRE", "t5")
    need(len(wires) <= MAX_HISTORY, "LIMIT", "t5")
    return [unbase(value, MAX_RECORD) for value in wires]


def evidence(capture, raw_query, prior_pins, policy, authority, clock):
    """Appraise captured native T5 frames with no stateful callback."""
    need(len(capture) == 2, "INCOMPLETE_PROOF", "t5")
    need(isinstance(prior_pins, list) and all(hexed(pin) for pin in prior_pins)
         and len(prior_pins) <= MAX_HISTORY and sorted(set(prior_pins)) == prior_pins,
         "PROTECTED_FLOOR_MISSING", "t5")
    lower, upper = clock["lower_ms"] // 1000, clock["upper_ms"] // 1000
    try:
        query = decode(Challenge, raw_query)
        finding_envelope = SignedFinding.model_validate_json(authority.finding_wire)
        finding = finding_envelope.finding
        need(canonical(finding_envelope) == authority.finding_wire
             and digest(canonical_bytes(finding)) == policy["target"]["finding_body_sha256"], "WRONG_SCOPE", "t5")
        authority.t4.validate_event(finding_envelope, policy["timestamp"](upper))
        manifest = decode(SignedManifest, authority.manifest_wire).body
        check_bundle(finding, authority.bundle)
        scope = Scope(cohort=authority.t5.cohort, claim_sha256=digest(claim_bytes(finding)),
                      bundle_sha256=digest(authority.manifest_wire), material_scope_sha256=material_scope(manifest))
        need(query.policy_sha256 == authority.t5.sha256 and query.audience == policy["audience"]
             and query.scope == scope and manifest.environment_sha256 == authority.scope["environment_sha256"],
             "WRONG_SCOPE", "t5")
        need(query.issued_at <= lower <= upper < query.issued_at + STATUS_TTL, "EXPIRED", "t5")
        archives, heads, expiries = [], [], []
        for name, raw in zip(authority.evidence_roster, capture, strict=True):
            carrier = frame(raw, "t5-capture", "endorsement_b64 records_b64")
            records = evidence_records(carrier["records_b64"])
            pins = tuple(digest(record) for record in records)
            need(tuple(sorted(set(pins))) == pins, "INCOMPLETE_PROOF", "t5")
            signed = decode(SignedEndorsement, unbase(carrier["endorsement_b64"], MAX_RECORD))
            body = signed.body
            need(body.witness_id == name and body.challenge_sha256 == digest(raw_query), "WRONG_SCOPE", "t5")
            authority.evidence_roster[name].verify(bytes.fromhex(signed.signature), endorsement_bytes(body))
            need(query.issued_at <= body.issued_at <= lower <= upper < body.expires_at
                 <= min(body.issued_at + STATUS_TTL, query.issued_at + STATUS_TTL), "EXPIRED", "t5")
            need(archive_head(pins) == body.head, "INCOMPLETE_PROOF", "t5")
            archives.append(list(zip(pins, records, strict=True)))
            heads.append(body.head)
            expiries.append(body.expires_at)
        need(heads[0] == heads[1] and archives[0] == archives[1], "INCOMPLETE_PROOF", "t5")
        current = {pin for pin, _ in archives[0]}
        retained = set(prior_pins)
        need(not current < retained, "ROLLBACK", "t5")
        need(retained <= current, "CONFLICTING_FLOOR", "t5")
        receipt = EvidenceHistory(authority.t5, archives[0], upper).assess(query, heads[0], upper, min(expiries))
        return receipt.outcome, receipt.reason, (receipt.valid_until or min(expiries)) * 1000
    except (ValueError, InvalidSignature, Denied, JournalBlocked) as error:
        raise Stop("INVALID_AUTHENTICATION", "t5") from error


def appraisal(inputs, policy, authority):
    """Consumes immutable in-memory wire bytes and independently selected pins."""
    clock = inputs["clock"]
    lower, upper, elapsed = (clock[key] for key in ("lower_ms", "upper_ms", "elapsed_ms"))
    need(number(lower) and number(upper) and 0 <= upper - lower <= 200, "CLOCK", "challenge")
    need(number(elapsed) and elapsed < MAX_TIME, "DEADLINE", "challenge")
    need(inputs["prior"] is not None and inputs["prior_after"] is not None
         and len(inputs["protected"]) == 2 and all(head is not None for head in inputs["protected"]),
         "PROTECTED_FLOOR_MISSING", "floor")
    prior = read_head(inputs["prior"], "floor")
    need(read_head(inputs["prior_after"], "floor") == prior, "CHANGED_FLOOR", "floor")
    first_query, second_query = inputs["queries"]
    query_a = challenge(first_query, policy, prior, clock)
    query_b = challenge(second_query, policy, prior, clock)
    need(query_a["nonce"] != query_b["nonce"], "REPLAY", "challenge")

    budget = Budget()
    first_raw, second_raw = inputs["floors"]
    first_raw = budget.read("floor", 0, [first_raw])
    first = floor(first_raw, first_query, query_a, prior, read_head(inputs["protected"][0], "floor"),
                  policy, authority, clock)
    need(len(inputs["views"]) == len(authority.t4.operators), "INCOMPLETE_PROOF", "view")
    view_request = inputs["view_request"]
    request = frame(view_request, "view-request", "context challenge_sha256 floor_sha256")
    need(all(request[k] == v for k, v in request_scope(first_query, first_raw, policy).items()), "WRONG_SCOPE", "view")
    view_times = []
    for index, (name, raw) in enumerate(zip(authority.t4.operators, inputs["views"], strict=True)):
        raw = budget.read("view", index, [raw])
        view_times.append(view(raw, name, first, view_request, first_query, first_raw, policy, authority, clock))
    need(len(inputs["pages"]) <= PAGES_MAX, "LIMIT", "page")
    pages = [budget.read("page", index, [raw]) for index, raw in enumerate(inputs["pages"])]
    matches = project(pages, inputs["page_requests"], first_query, first_raw, first, policy, authority, inputs["page_size"])
    capture = [budget.read("t5", index, [raw]) for index, raw in enumerate(inputs["t5"])]
    outcome, reason, t5_expiry = evidence(capture, inputs["t5_query"], inputs["t5_prior"], policy, authority, clock)

    need(query_b["lower_ms"] >= max(issued for issued, _ in view_times), "CLOCK", "challenge")
    second_raw = budget.read("floor", 1, [second_raw], elapsed=elapsed)
    second = floor(second_raw, second_query, query_b, prior, read_head(inputs["protected"][1], "floor"),
                   policy, authority, clock)
    need((second["head"], second["witnesses"]) == (first["head"], first["witnesses"]), "CHANGED_FLOOR", "floor")
    valid_until = min(first["expires_ms"], second["expires_ms"], t5_expiry,
                      *(expires for _, expires in view_times), lower + MAX_TIME - elapsed)
    need(upper < valid_until, "DEADLINE", "result")
    if outcome == "inconclusive" and reason == "revoked":
        result, event_id, proof = "evidence_hold", None, None
    else:
        need(outcome == "reproduced", "INCOMPLETE_PROOF", "t5")
        result = "scoped_proof" if matches else "no_matching_anchored_obligation"
        event_id, proof = next(iter(matches.items()), (None, None))
    if proof is not None:
        proof.update({"target": policy["target"], "grant_sha256": policy["grant_sha256"],
                      "trust_cut_sha256": policy["trust_cut_sha256"],
                      "first_floor_sha256": digest(first_raw), "confirmed_floor_sha256": digest(second_raw),
                      "witness_view_sha256": [digest(raw) for raw in inputs["views"]],
                      "t5_query_sha256": digest(inputs["t5_query"]),
                      "t5_capture_sha256": [digest(raw) for raw in capture]})
    return canonical({"kind": KINDS["result"], "outcome": result, "anchored_head": first["head"],
                      "event_id": event_id, "proof": proof, "valid_until_ms": valid_until,
                      "native_observations_added": 0})
