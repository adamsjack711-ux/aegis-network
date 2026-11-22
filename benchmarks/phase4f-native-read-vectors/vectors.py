"""Generate and verify the versioned offline wire vectors."""

import argparse
import base64
import copy
import json
from pathlib import Path
import sys
from uuid import UUID

from aegis.artifact import SignedRevocation, canonical_bytes, sign_revocation
from aegis.evidence.records import MAX_RECORD, Attestation, Observation, canonical as ec, digest, sign_record
from aegis.evidence.status_protocol import (
    MAX_HISTORY, Challenge, Endorsement, Scope, SignedEndorsement, archive_head, endorsement_bytes,
)
from aegis.journal.protocol import Admission, canonical, vote

from fixture import ADMISSION, NOW, FrozenAuthority, fixture_key, timestamp
from wire import (
    ALL_MAX, DOMAINS, KINDS, MAX_ATTEMPTS, MAX_TIME, OBLIGATIONS_MAX, PAGES_MAX, PAGE_MAX, ROLE_BOUNDS,
    SOURCE_MAX, T4_MAX, Budget, Stop, Tree, ZERO_HEAD, appraisal, bounded_source, evidence_records, proof_nodes,
    signed_wire, tree_head,
)

HERE = Path(__file__).resolve().parent
PREDECESSOR = "3f36c6ab39405bd1a10d5c905483abdab7204a0e"
NATIVE_REFERENCE = "b09afcf830e9ac7273beaa08ec6b64e73add7a53"
key = fixture_key
authority = FrozenAuthority()
now = NOW
base = now * 1000
admission_ms = ADMISSION[0] * 1000
pending_offset = -12
pending_base = base + pending_offset * 1000
pending_ms = pending_base + 10
anchor_id = "independent-anchor"
t4 = tuple(authority.t4.operators)
t5 = tuple(authority.evidence_roster)
policy = {
    "context": authority.t4.context, "audience": "enrolled-agent", "workload": "withdrawal-observation",
    "store": "synthetic-agent-audit", "timestamp": timestamp,
    "target": dict(zip(("publisher_id", "artifact_id", "finding_body_sha256"), authority.target, strict=True)),
    "grant_sha256": authority.admission["grant_sha256"],
    "trust_cut_sha256": digest(canonical(["synthetic-current-trust-cut", authority.admission["grant_sha256"]])),
}


def body(raw):
    return json.loads(raw)["body"]


def sign_frame(kind, name, **fields):
    return signed_wire(kind, {"kind": KINDS[kind], **fields}, key(name))


def update(raw, **changes):
    return canonical({**json.loads(raw), **changes})


def resign(raw, kind, name, **changes):
    return signed_wire(kind, {**body(raw), **changes}, key(name))


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def archive(withdrawn=False, first_expires=now + 20, appraisal_at=now):
    wires = [authority.manifest_wire]
    for index, name in enumerate(("verify-a", "verify-b")):
        wires.append(sign_record(Attestation(
            kind="aegis.evidence.attestation.v1", record_id=f"{30 + index:032x}",
            issuer=name, key_id="fixture", cohort=authority.t5.cohort, issued_at=appraisal_at - 2,
            expires_at=first_expires if index == 0 else now + 20, started_at=appraisal_at - 5, bundle_sha256=authority.bundle.sha256,
            observation=Observation(outcome="reproduced", reason="marker-observed",
                                    positive_control=True, negative_control=True),
        ), key(name)))
    if withdrawn:
        wires.append(authority.evidence_withdrawal)
    return sorted(wires, key=digest)


def status_query(at=now):
    return ec(Challenge(
        policy_sha256=authority.t5.sha256, audience=policy["audience"], nonce="33" * 32, issued_at=at - 1,
        scope=Scope(cohort=authority.t5.cohort, claim_sha256=authority.scope["claim_sha256"],
                    bundle_sha256=authority.bundle.sha256, material_scope_sha256=authority.scope["material_scope_sha256"]),
    ))


def status_wire(operator, query, records, expires=None, at=now):
    endorsement = Endorsement(
        witness_id=operator, challenge_sha256=digest(query), head=archive_head(tuple(map(digest, records))),
        issued_at=at, expires_at=at + 2 if expires is None else expires,
    )
    native = ec(SignedEndorsement(body=endorsement, signature=key(operator).sign(endorsement_bytes(endorsement)).hex()))
    return canonical({"kind": KINDS["t5-capture"], "endorsement_b64": b64(native),
                      "records_b64": list(map(b64, records))})


def unrelated():
    source = SignedRevocation.model_validate_json(authority.mesh_wire)
    return canonical(sign_revocation(source.revocation.model_copy(update={
        "revocation_id": UUID("00000000-0000-4000-8000-000000000042"),
        "sequence": 2, "target_sha256": "92" * 32,
    }), key("fixture-revoker"), "fixture"))


def challenge_wire(prior, nonce, lower):
    return canonical({"kind": KINDS["challenge"], **{
        k: policy[k] for k in ("context", "audience", "workload", "store")
    }, "prior": prior, "nonce": nonce * 32, "lower_ms": lower, "upper_ms": lower + 10})


def projection(rows):
    global_tree = Tree()
    slot_trees = {name: Tree() for name in t4}
    entries = []
    for ordinal, (name, source) in enumerate(rows):
        signed = SignedRevocation.model_validate_json(source)
        event = signed.revocation
        witness_ordinal = slot_trees[name].size
        admitted = [admission_ms, admission_ms + 100]
        admission = Admission(context=policy["context"], event=digest(source),
                              epoch=admitted[0] // (authority.t4.epoch_seconds * 1000))
        core = {
            "kind": KINDS["entry"], "context": policy["context"], "witness_id": name, "ordinal": witness_ordinal,
            "event_id": str(event.revocation_id), "sequence": event.sequence, "revoker": event.publisher_id,
            "revoker_key": signed.key_id, "source_sha256": digest(source), "body_sha256": digest(canonical_bytes(event)),
            "admission": admission.model_dump(mode="json"), "vote": vote(name, key(name), admission).model_dump(mode="json"),
            "admitted_ms": admitted, "grant_sha256": policy["grant_sha256"], "trust_cut_sha256": policy["trust_cut_sha256"],
            "target": {"publisher_id": event.target_publisher_id, "artifact_id": str(event.target_artifact_id),
                       "finding_body_sha256": event.target_sha256},
        }
        slot_trees[name].append(canonical(core))
        obligation = sign_frame("obligation", name, entry=core, witness_head=tree_head(slot_trees[name]))
        leaf = {
            "kind": KINDS["leaf"], "context": policy["context"], "ordinal": ordinal, "witness_id": name,
            "witness_ordinal": witness_ordinal, "source": json.loads(source), "obligation_sha256": digest(obligation),
        }
        leaf_raw = canonical(leaf)
        global_tree.append(leaf_raw)
        acceptance = sign_frame("anchor", anchor_id, anchor_id=anchor_id, context=policy["context"], ordinal=ordinal,
                                leaf_sha256=digest(leaf_raw), head=tree_head(global_tree))
        entries.append({"leaf": leaf, "obligation": json.loads(obligation), "acceptance": json.loads(acceptance)})
    for index, entry in enumerate(entries):
        entry["inclusion"] = [node.hex() for node in global_tree.inclusion(index, global_tree.size)]
    return global_tree, {name: tree_head(tree) for name, tree in slot_trees.items()}, entries


def floor_wire(tree, witnesses, prior, query, issued, expires):
    return sign_frame("floor", anchor_id, anchor_id=anchor_id, context=policy["context"],
                      challenge_sha256=digest(query), head=tree_head(tree), witnesses=witnesses,
                      consistency=[node.hex() for node in tree.consistency(prior["size"], tree.size)],
                      issued_ms=issued, expires_ms=expires)


def round_wires(rows=(), prior_size=0, page_size=1, withdrawn=False, at=now):
    start_ms = at * 1000
    tree, witnesses, entries = projection(rows)
    prior = {"size": prior_size, "root": tree.root(prior_size).hex()}
    queries = [challenge_wire(prior, "11", start_ms - 50), challenge_wire(prior, "22", start_ms + 30)]
    first = floor_wire(tree, witnesses, prior, queries[0], start_ms - 30, start_ms + 1800)
    final = floor_wire(tree, witnesses, prior, queries[1], start_ms + 50, start_ms + 1900)
    scope = {"context": policy["context"], "challenge_sha256": digest(queries[0]), "floor_sha256": digest(first)}
    view_request = canonical({"kind": KINDS["view-request"], **scope})
    views = [sign_frame("view", name, witness_id=name, **scope, request_sha256=digest(view_request),
                        head=head, complete=True, pending_admission_ms=None, issued_ms=start_ms - 20,
                        expires_ms=start_ms + 1750) for name, head in witnesses.items()]
    page_requests, pages = [], []
    for start in range(0, tree.size, page_size):
        fields = {**scope, "start": start, "requested": page_size}
        request = canonical({"kind": KINDS["page-request"], **fields})
        page_requests.append(request)
        pages.append(canonical({"kind": KINDS["page"], **fields, "request_sha256": digest(request),
                                "next": min(start + page_size, tree.size), "entries": entries[start:start + page_size]}))
    query = status_query(at)
    return {
        "prior": prior, "prior_after": copy.deepcopy(prior), "protected": [tree_head(tree), tree_head(tree)],
        "clock": {"lower_ms": start_ms + 70, "upper_ms": start_ms + 90, "elapsed_ms": 250},
        "queries": queries, "floors": [first, final], "view_request": view_request, "views": views,
        "page_requests": page_requests, "pages": pages, "page_size": page_size,
        "t5_query": query, "t5_prior": [digest(authority.manifest_wire)], "t5": [status_wire(name, query, archive(withdrawn, appraisal_at=at), at=at) for name in t5],
    }


def swap(values, index, value):
    result = list(values)
    result[index] = value
    return result


def result(classification, head, event_id=None, inputs=None):
    proof = None
    if event_id is not None:
        entries = [entry for page in inputs["pages"] for entry in json.loads(page)["entries"]]
        first = next(entry for entry in entries if entry["obligation"]["body"]["entry"]["event_id"] == event_id)
        core = first["obligation"]["body"]["entry"]
        proof = {
            "admission_ms": admission_ms, "source_sha256": authority.scope["withdrawal_wire_sha256"],
            "body_sha256": authority.scope["withdrawal_body_sha256"],
            "native_admission_sha256": digest(canonical(core["admission"])),
            "obligation_sha256": digest(canonical(first["obligation"])),
            "anchor_acceptance_sha256": digest(canonical(first["acceptance"])),
            "target": policy["target"], "grant_sha256": policy["grant_sha256"],
            "trust_cut_sha256": policy["trust_cut_sha256"],
            "first_floor_sha256": digest(inputs["floors"][0]), "confirmed_floor_sha256": digest(inputs["floors"][1]),
            "witness_view_sha256": list(map(digest, inputs["views"])),
            "t5_query_sha256": digest(inputs["t5_query"]), "t5_capture_sha256": list(map(digest, inputs["t5"])),
        }
    return {"kind": KINDS["result"], "outcome": classification, "anchored_head": head, "event_id": event_id,
            "proof": proof, "valid_until_ms": base + 1750, "native_observations_added": 0}


def error(code, stage, **more):
    return {"kind": KINDS["error"], "outcome": "unknown_hold", "code": code, "stage": stage, **more}


def rounds():
    rows = ((t4[0], unrelated()), (t4[1], authority.mesh_wire))
    full = round_wires(rows, prior_size=1)
    absent = round_wires(rows[:1])
    genesis = round_wires()
    event_id = str(SignedRevocation.model_validate_json(authority.mesh_wire).revocation.revocation_id)
    yield "anchored-complete", full, result("scoped_proof", full["protected"][0], event_id, full), {}
    yield "anchored-absence-nonempty", absent, result("no_matching_anchored_obligation", absent["protected"][0]), {}
    yield "protected-genesis-absence", genesis, result("no_matching_anchored_obligation", ZERO_HEAD), {}
    duplicate = round_wires(((t4[0], authority.mesh_wire), (t4[1], authority.mesh_wire)))
    yield "same-event-distinct-witnesses", duplicate, result(
        "scoped_proof", duplicate["protected"][0], event_id, duplicate), {}
    pending_round = round_wires(rows[:1], at=now + pending_offset)
    pending_event = SignedRevocation.model_validate_json(authority.mesh_wire)
    authority.t4.validate_event(pending_event, policy["timestamp"](pending_ms / 1000))
    pending_model = {
        "pending_event_source_sha256": digest(authority.mesh_wire), "pending_original_admission_ms": pending_ms,
        "signed_views_issued_ms": pending_base - 20, "confirmation_issued_ms": pending_base + 50,
    }
    yield "unseen-append-between-view-and-confirmation", pending_round, {
        **result("no_matching_anchored_obligation", pending_round["protected"][0]),
        "valid_until_ms": pending_base + 1750,
    }, pending_model

    only_evidence = round_wires(withdrawn=True)
    yield "evidence-only-withdrawal", only_evidence, result("evidence_hold", ZERO_HEAD), {}

    def refusal(label, code, stage, **changes):
        return label, {**full, **changes}, error(code, stage), {}

    later_pending_view = pending_base + 20
    pending = resign(pending_round["views"][0], "view", t4[0], complete=False,
                     pending_admission_ms=pending_ms, issued_ms=later_pending_view)
    yield "observed-pending-original-clock", {
        **pending_round, "views": swap(pending_round["views"], 0, pending),
    }, error(
        "PENDING_INTAKE", "view", pending_admission_ms=pending_ms), {**pending_model, "pending_seen_by_witness_ms": later_pending_view}
    yield refusal("missing-view", "INCOMPLETE_PROOF", "view", views=full["views"][:-1])
    yield refusal("signed-incomplete-view", "INCOMPLETE_PROOF", "view",
                  views=swap(full["views"], 0, resign(full["views"][0], "view", t4[0], complete=False)))
    yield refusal("other-witness-frame-in-slot", "WRONG_SCOPE", "view",
                  views=swap(full["views"], 0, resign(full["views"][0], "view", t4[0], witness_id=t4[1])))
    yield refusal("missing-protected-reader-floor", "PROTECTED_FLOOR_MISSING", "floor", prior=None)
    yield refusal("missing-independent-anchor-pin", "PROTECTED_FLOOR_MISSING", "floor", protected=[None, None])
    yield refusal("reader-floor-changes-during-round", "CHANGED_FLOOR", "floor", prior_after=full["protected"][0])
    yield refusal("fresh-signed-rollback", "ROLLBACK", "floor", protected=[full["protected"][0]] * 2,
                  floors=swap(full["floors"], 0, floor_wire(
                      *projection(rows[:1])[:2], full["prior"], full["queries"][0], base - 30, base + 1800)))
    yield refusal("same-size-anchor-fork", "CONFLICTING_FLOOR", "floor",
                  protected=[{"size": 2, "root": "aa" * 32}] * 2)
    yield refusal("wrong-anchor-scope", "WRONG_SCOPE", "floor",
                  floors=swap(full["floors"], 0, resign(full["floors"][0], "floor", anchor_id, context="12" * 32)))
    yield refusal("expiry-equals-conservative-upper", "EXPIRED", "floor",
                  floors=swap(full["floors"], 0, resign(full["floors"][0], "floor", anchor_id, expires_ms=base + 90)))
    yield refusal("missing-consistency-node", "INCOMPLETE_PROOF", "floor",
                  floors=swap(full["floors"], 0, resign(full["floors"][0], "floor", anchor_id, consistency=[])))
    advanced = projection((*rows, (t4[2], authority.mesh_wire)))
    yield refusal("new-anchor-head-at-confirmation", "CHANGED_FLOOR", "floor",
                  protected=[full["protected"][0], tree_head(advanced[0])],
                  floors=swap(full["floors"], 1, floor_wire(
                      *advanced[:2], full["prior"], full["queries"][1], base + 50, base + 1900)))
    yield refusal("reused-confirmation-nonce", "REPLAY", "challenge", queries=swap(
        full["queries"], 1, update(full["queries"][1], nonce="11" * 32)))
    yield refusal("bool-disguised-as-empty-prior", "INVALID_WIRE", "challenge", **{
        **genesis, "queries": swap(genesis["queries"], 0, update(genesis["queries"][0], prior={**ZERO_HEAD, "size": False})),
    })
    yield refusal("duplicate-json-member", "INVALID_WIRE", "challenge",
                  queries=swap(full["queries"], 0, b'{"kind":0,' + full["queries"][0][1:]))
    yield refusal("noncanonical-separators", "INVALID_WIRE", "challenge",
                  queries=swap(full["queries"], 0, json.dumps(json.loads(full["queries"][0])).encode()))
    yield refusal("deep-json", "INVALID_WIRE", "challenge",
                  queries=swap(full["queries"], 0, b'{"x":' + b"[" * 1200 + b"0" + b"]" * 1200 + b"}"))
    yield refusal("unknown-json-member", "INVALID_WIRE", "challenge",
                  queries=swap(full["queries"], 0, update(full["queries"][0], extension=True)))
    yield refusal("malformed-signature", "INVALID_WIRE", "floor",
                  floors=swap(full["floors"], 0, update(full["floors"][0], signature="DE" * 64)))
    yield refusal("changed-signed-bytes", "INVALID_AUTHENTICATION", "floor", floors=swap(
        full["floors"], 0, update(full["floors"][0], body={**body(full["floors"][0]), "expires_ms": base + 1799})))
    yield refusal("cross-domain-signature", "INVALID_AUTHENTICATION", "floor", floors=swap(
        full["floors"], 0, update(full["floors"][0], signature=key(anchor_id).sign(
            DOMAINS["anchor"] + canonical(body(full["floors"][0]))).hex())))
    yield refusal("missing-page", "INCOMPLETE_PROOF", "page", pages=full["pages"][:1])
    yield refusal("duplicate-ordinal-page", "INCOMPLETE_PROOF", "page", pages=[full["pages"][0]] * 2,
                  page_requests=[full["page_requests"][0]] * 2)
    switched_request = update(full["page_requests"][1], requested=2)
    yield refusal("mid-round-page-size-switch", "WRONG_SCOPE", "page",
                  page_requests=swap(full["page_requests"], 1, switched_request),
                  pages=swap(full["pages"], 1, update(full["pages"][1],
                                                     requested=2, request_sha256=digest(switched_request))))
    yield refusal("wrong-page-request-digest", "WRONG_SCOPE", "page",
                  pages=swap(full["pages"], 0, update(full["pages"][0], request_sha256="9f" * 32)))
    yield refusal("gapped-reordered-pages", "INCOMPLETE_PROOF", "page",
                  pages=list(reversed(full["pages"])), page_requests=list(reversed(full["page_requests"])))
    oversized = {"size": OBLIGATIONS_MAX + 1, "root": "81" * 32}
    yield refusal("signed-terminal-exceeds-obligation-cap", "LIMIT", "floor",
                  protected=[oversized] * 2,
                  floors=swap(full["floors"], 0, resign(full["floors"][0], "floor", anchor_id, head=oversized)))
    yield refusal("requested-page-over-cap", "LIMIT", "page", pages=swap(
        full["pages"], 0, update(full["pages"][0], requested=PAGE_MAX + 1)))
    yield refusal("page-count-over-cap", "LIMIT", "page", pages=[full["pages"][0]] * (PAGES_MAX + 1))
    corrupt = json.loads(full["pages"][0])
    corrupt["entries"][0]["leaf"]["witness_id"] = []
    yield refusal("list-valued-witness-id", "WRONG_SCOPE", "entry", pages=swap(full["pages"], 0, canonical(corrupt)))
    conflict = round_wires(((t4[0], authority.mesh_wire), (t4[1], authority.conflicting_wire)))
    yield refusal("authenticated-same-event-conflict", "SIGNED_CONFLICT", "entry", **conflict)
    yield refusal("missing-t5-view", "INCOMPLETE_PROOF", "t5", t5=full["t5"][:1])
    yield refusal("duplicate-t5-operator", "WRONG_SCOPE", "t5", t5=[full["t5"][0]] * 2)
    yield refusal("disagreeing-t5-native-archives", "INCOMPLETE_PROOF", "t5", t5=swap(
        full["t5"], 1, status_wire(t5[1], full["t5_query"], archive(True))))
    wrong_query = json.loads(full["t5_query"])
    wrong_query["scope"]["material_scope_sha256"] = "a9" * 32
    wrong_query = ec(Challenge.model_validate(wrong_query))
    yield refusal("t5-wrong-scope-with-matching-signatures", "WRONG_SCOPE", "t5", t5_query=wrong_query,
                  t5=[status_wire(name, wrong_query, archive()) for name in t5])
    yield refusal("expired-t5-native-endorsement", "EXPIRED", "t5",
                  t5=swap(full["t5"], 1, status_wire(t5[1], full["t5_query"], archive(), expires=now)))
    yield refusal("missing-t5-protected-floor", "PROTECTED_FLOOR_MISSING", "t5", t5_prior=None)
    yield refusal("fresh-signed-t5-strict-subset", "ROLLBACK", "t5", t5_prior=sorted(map(digest, archive(True))))
    old = sorted([digest(authority.manifest_wire), digest(authority.evidence_withdrawal)])
    yield refusal("fresh-signed-t5-replacement", "CONFLICTING_FLOOR", "t5", t5_prior=old)
    short = [status_wire(name, full["t5_query"], archive(first_expires=now + 1)) for name in t5]
    yield "earliest-t5-attestation-expiry", {**full, "t5": short}, {
        **result("scoped_proof", full["protected"][0], event_id, {**full, "t5": short}), "valid_until_ms": base + 1000,
    }, {}
    yield "shared-deadline-earliest", {**full, "clock": {**full["clock"], "elapsed_ms": 1979}}, {
        **result("scoped_proof", full["protected"][0], event_id, full), "valid_until_ms": base + 91,
    }, {}
    yield refusal("remaining-deadline-inside-utc-uncertainty", "DEADLINE", "result",
                  clock={**full["clock"], "elapsed_ms": 1999})
    yield refusal("elapsed-deadline", "DEADLINE", "challenge", clock={**full["clock"], "elapsed_ms": MAX_TIME})
    yield refusal("utc-uncertainty-over-cap", "CLOCK", "challenge",
                  clock={**full["clock"], "lower_ms": full["clock"]["upper_ms"] - 201})
    yield refusal("changed-per-witness-confirmation-root", "CHANGED_FLOOR", "floor",
                  floors=swap(full["floors"], 1, resign(full["floors"][1], "floor", anchor_id, witnesses={
                      **body(full["floors"][1])["witnesses"], t4[2]: {"size": 1, "root": "8e" * 32},
                  })))


def read(role, index, sizes=(), **options):
    return {"role": role, "index": index, "sizes": list(sizes), "options": options}


def budgets():
    page_cap = ROLE_BOUNDS["page"][1]
    t5_cap = ROLE_BOUNDS["t5"][1]
    fill_t4 = [read("page", index, [page_cap]) for index in range(T4_MAX // page_cap)]
    normal = [read("floor", 0, [7]), read("floor", 1, [9])]
    slots = [read(role, index) for role, (count, _) in ROLE_BOUNDS.items() for index in range(count)]
    all_slots = [read("floor", 0, outcome="unavailable"), read("floor", 0),
                 read("floor", 1, outcome="unavailable"), read("floor", 1), *slots[2:]]
    yield "exact-and-split-response", [read("page", 0, [page_cap - 1, 1], declared=page_cap)], (
        None, 1, 0, page_cap, page_cap)
    yield "response-cap-plus-one-actual", [read("page", 0, [page_cap, 1])], (
        "RESPONSE_LIMIT", 1, 0, page_cap + 1, page_cap + 1)
    yield "response-cap-plus-one-declared", [read("page", 0, declared=page_cap + 1)], (
        "RESPONSE_LIMIT", 1, 0, 0, 0)
    yield "floor-wire-exact", [read("floor", 0, [65536])], (None, 1, 0, 65536, 65536)
    yield "witness-wire-over-cap", [read("view", 0, [65537])], ("RESPONSE_LIMIT", 1, 0, 65537, 65537)
    yield "t5-wire-over-cap", [read("t5", 0, [t5_cap + 1])], ("RESPONSE_LIMIT", 1, 0, t5_cap + 1, 0)
    yield "declared-truncated-wire", [read("page", 0, [7], declared=8)], ("INCOMPLETE_PROOF", 1, 0, 7, 7)
    yield "gzip-declined", [read("page", 0, encoding="gzip")], ("INVALID_ENCODING", 1, 0, 0, 0)
    yield "t4-aggregate-exact", fill_t4, (None, 16, 0, T4_MAX, T4_MAX)
    yield "t4-aggregate-over-cap", [*fill_t4, read("page", 16, [1])], (
        "T4_AGGREGATE_LIMIT", 17, 0, T4_MAX + 1, T4_MAX + 1)
    for excess in (0, 1):
        tail = [read("t5", 0, [2 * 1024 * 1024 + excess], outcome="unavailable"),
                read("t5", 0, [t5_cap]), read("t5", 1, [t5_cap])]
        yield "all-role-aggregate-" + ("over" if excess else "exact"), [*fill_t4, *tail], (
            "AGGREGATE_LIMIT" if excess else None, 19, 1, ALL_MAX + excess, T4_MAX)
    yield "unavailable-zero-bytes", [read("floor", 0, outcome="unavailable")], ("SOURCE_UNAVAILABLE", 1, 0, 0, 0)
    yield "same-slot-third-empty-attempt-refused", [read("floor", 0, outcome="unavailable")] * 3, (
        "ATTEMPT_LIMIT", 2, 1, 0, 0)
    yield "total-retries-across-roles", [*all_slots[:4], read("view", 0, outcome="unavailable"), read("view", 0)], (
        "ATTEMPT_LIMIT", 5, 2, 0, 0)
    yield "zero-byte-total-attempts-exact", all_slots, (None, MAX_ATTEMPTS, 2, 0, 0)
    yield "zero-byte-attempts-over", [*all_slots, read("t5", 1)], ("ATTEMPT_LIMIT", MAX_ATTEMPTS, 2, 0, 0)
    yield "successful-slot-cannot-refetch", [normal[0], normal[0]], ("ATTEMPT_LIMIT", 1, 0, 7, 7)
    yield "failed-body-counts-before-retry", [read("floor", 0, [5], outcome="unavailable"), normal[0]], (
        None, 2, 1, 12, 12)
    yield "deadline-one-before", [read("floor", 0, elapsed=MAX_TIME - 1)], (None, 1, 0, 0, 0)
    yield "deadline-exact-no-read", [normal[0], read("floor", 1, elapsed=MAX_TIME)], ("DEADLINE", 1, 0, 7, 7)
    yield "cross-read-clock-regression", [read("floor", 0, elapsed=10), read("floor", 1, elapsed=9)], (
        "DEADLINE", 1, 0, 0, 0)


def verify_budget(label, actions, expected):
    budget = Budget()
    attempts = []
    failure = None
    for action in actions:
        role, index = action["role"], action["index"]
        chunks = [b"a" * size for size in action["sizes"]]
        attempt = {**action, "body_sha256": digest(b"".join(chunks))}
        try:
            budget.read(role, index, chunks, **action["options"])
        except Stop as exc:
            failure = exc.code
            attempt["error_sha256"] = digest(exc.wire())
            attempts.append(attempt)
            if failure != "SOURCE_UNAVAILABLE":
                break
        else:
            failure = None
            attempts.append(attempt)
    actual = failure, budget.attempts, budget.retries, budget.total, budget.t4
    if actual != expected:
        raise ValueError(f"{label}: expected {expected}, got {actual}")
    return {"id": label, "reads": attempts,
            "expected": dict(zip(("code", "attempts", "retries", "bytes_all", "bytes_t4"), expected, strict=True))}


def boundary_cases(pin):
    for size in (SOURCE_MAX, SOURCE_MAX + 1):
        source = b"a" * size
        expected = "SOURCE_LIMIT" if size > SOURCE_MAX else None
        yield primitive("source-cap", bounded_source, (source,), expected,
                        {"fill_hex": "61", "size": size, "sha256": digest(source)})
    for count in (MAX_HISTORY, MAX_HISTORY + 1):
        records = [b64(b"a")] * count
        yield primitive("t5-record-count", evidence_records, (records,),
                        "LIMIT" if count > MAX_HISTORY else None, pin(canonical(records)))
    for size in (MAX_RECORD, MAX_RECORD + 1):
        records = [b64(b"a" * size)]
        yield primitive("t5-record-bytes", evidence_records, (records,),
                        "LIMIT" if size > MAX_RECORD else None, pin(canonical(records)))
    for nodes, expected in ((["ad" * 32] * 64, None), (["ad" * 32] * 65, "LIMIT"),
                            (["ad" * 31], "INVALID_WIRE"), (["ad" * 33], "INVALID_WIRE")):
        yield primitive("proof-nodes", proof_nodes, (nodes, "entry"), expected, pin(canonical(nodes)))


def primitive(label, check, args, expected, source):
    try:
        check(*args)
    except Stop as exc:
        actual = exc.code
    else:
        actual = None
    if expected != actual:
        raise ValueError(f"{label}: expected {expected}, got {actual}")
    return {"id": label, "input": source, "expected_code": expected}


def golden():
    wires = {}

    def pin(raw):
        value = digest(raw)
        wires.setdefault(value, raw.hex())
        return value

    cases = []
    for label, values, expected, model in rounds():
        try:
            actual = appraisal(values, policy, authority)
        except Stop as exc:
            actual = exc.wire()
        if actual != canonical(expected):
            raise ValueError(f"{label}: expected {expected}, got {actual.decode()}")
        inputs = {**values}
        for field in ("queries", "floors", "views", "page_requests", "pages", "t5"):
            inputs[field] = list(map(pin, inputs[field]))
        for field in ("t5_query", "view_request"):
            inputs[field] = pin(inputs[field])
        cases.append({"id": label, "inputs": inputs, "result_sha256": pin(actual), "modeled_environment": model})

    original = SignedRevocation.model_validate_json(authority.mesh_wire)
    pretty = json.dumps(json.loads(authority.mesh_wire), indent=2).encode("utf-8")
    if canonical(SignedRevocation.model_validate_json(pretty)) != authority.mesh_wire:
        raise ValueError("native reference failed canonical envelope readback")
    budget_cases = [verify_budget(*case) for case in budgets()]
    boundary = list(boundary_cases(pin))
    return {
        "kind": "aegis.phase4f.read.golden-vectors.v1", "predecessor": PREDECESSOR, "native_reference": NATIVE_REFERENCE,
        "public_fixture_keys": {
            name: key(name).public_key().public_bytes_raw().hex() for name in (
                anchor_id, *t4, *t5, "fixture-finder", "fixture-revoker", "research", "review", "verify-a", "verify-b",
            )
        },
        "policy": {name: value for name, value in policy.items() if name != "timestamp"},
        "evidence_pins": dict(authority.scope),
        "signature_domains_hex": {name: value.hex() for name, value in DOMAINS.items()},
        "bounds": {"response_roles": ROLE_BOUNDS, "t4_bytes": T4_MAX, "all_bytes": ALL_MAX,
                   "source_bytes": SOURCE_MAX, "page_size": PAGE_MAX, "pages": PAGES_MAX,
                   "obligations": OBLIGATIONS_MAX, "deadline_ms": MAX_TIME, "attempts": MAX_ATTEMPTS, "retries": 2},
        "reference_wires": {
            "finding_envelope": pin(authority.finding_wire), "manifest_envelope": pin(authority.manifest_wire),
            "revocation_canonical_envelope": pin(authority.mesh_wire),
            "revocation_original_body": pin(canonical_bytes(original.revocation)),
            "alternate_native_http_formatting": pin(pretty),
            "fixture_material": {name: pin(raw) for name, raw in authority.objects.items()},
        },
        "rounds": cases, "byte_budget": budget_cases, "primitive_boundaries": boundary, "wire_hex_by_sha256": wires,
        "native_observations_added": 0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit", action="store_true", help="write the candidate vector catalog to stdout")
    args = parser.parse_args()
    catalog = golden()
    raw = (json.dumps(catalog, indent=2, sort_keys=True) + "\n").encode()
    if args.emit:
        sys.stdout.buffer.write(raw)
    else:
        if (HERE / "golden.json").read_bytes() != raw:
            raise SystemExit("FAIL golden vector bytes differ")
        print(f"PASS {len(catalog['rounds'])} appraisal rounds, {len(catalog['byte_budget'])} budget cases, "
              f"{len(catalog['primitive_boundaries'])} primitive boundaries, "
              f"{len(catalog['wire_hex_by_sha256'])} pinned frames; SHA-256 {digest(raw)}")


if __name__ == "__main__":
    main()
