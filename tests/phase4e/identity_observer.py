"""Standalone Phase 4E-B observer, run in the candidate's disposable identity lab."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from http.client import HTTPSConnection
import json
import sqlite3
import ssl
from threading import Barrier

import pytest
from cryptography import x509

from aegis.identity_lab.protocol import (
    Assignment, Denied, Mutation, Stamp, Unavailable, Write, approve, command, make_claim,
)


def read_db(path, query):
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as db:
        return db.execute(query).fetchall()


def read_target(lab, target):
    """Probe the actual TLS listener with the separately enrolled observer."""
    endpoint = lab.endpoints[target]
    assert endpoint.host == "127.0.0.1"
    credentials = lab.root / "observer"
    context = ssl.create_default_context(cafile=str(credentials / "ca.pem"))
    context.check_hostname = False
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(credentials / "cert.pem", credentials / "key.pem")
    with closing(HTTPSConnection(endpoint.host, endpoint.port, context=context, timeout=2)) as connection:
        connection.connect()
        leaf = x509.load_der_x509_certificate(connection.sock.getpeercert(binary_form=True))
        uris = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert uris.get_values_for_type(x509.UniformResourceIdentifier) == [f"spiffe://phase4e.test/{target}"]
        connection.request("POST", "/read", b"{}", {"Connection": "close", "Content-Type": "application/json"})
        response = connection.getresponse()
        assert response.status == 200
        return json.loads(response.read())


def readback(lab):
    home, = read_db(lab.database("home"), "SELECT body FROM record")
    anchor, = read_db(lab.database("anchor"), "SELECT body FROM record")
    targets = {}
    for target in lab.targets:
        record, = read_db(lab.database(target), "SELECT body FROM record")
        marker, = read_db(lab.database(target), "SELECT version, value FROM marker")
        targets[target] = {
            "fence": json.loads(record[0])["assignment"]["generation"],
            "marker": marker,
            "receipts": read_db(lab.database(target), "SELECT generation, marker FROM receipts ORDER BY rowid"),
        }
    return {"home": json.loads(home[0]), "anchor": json.loads(anchor[0]), "targets": targets}


def test_I01_I02_I03_barrier_with_one_authenticated_writer_unavailable(lab, record_property):
    ready = Barrier(2)

    def contend(agent, broker):
        proof = make_claim(lab.policy, agent, broker, 0, lab.instances[agent])
        ready.wait(timeout=2)
        try:
            return Assignment.model_validate(lab.call(agent, broker, "/claim", proof))
        except Denied:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = pool.map(contend, lab.agents, lab.brokers)
        former, = (assignment for assignment in results if assignment is not None)
    first = readback(lab)
    assert first["home"]["phase"] == "active" and first["home"]["generation"] == former.generation == 1
    assert first["anchor"]["generation"] == 1
    assert all(state["fence"] == 1 for state in first["targets"].values())

    def write_request(assignment, target):
        version = read_target(lab, target)["version"]
        mutation = Mutation(assignment=assignment, target=target, marker="observing", expected_version=version)
        return Write(command=command(mutation, lab.instances[assignment.agent]),
                     approval=approve(mutation, lab.approval), credential_until_ns=assignment.expires_ns)

    reachable, offline = lab.targets
    lab.call(former.agent, former.broker, "/write", write_request(former, reachable))
    assert read_target(lab, reachable)["effective"] == "observing"
    stale = write_request(former, reachable)
    retired = lab.call("operator", "home", "/recover",
                       Stamp.model_validate(lab.call("operator", "anchor", "/stamp")))
    successor_agent, = set(lab.agents) - {former.agent}
    successor_broker, = set(lab.brokers) - {former.broker}
    prior = retired["generation"]
    lab.stop(offline)
    claim = make_claim(lab.policy, successor_agent, successor_broker, prior, lab.instances[successor_agent])
    with pytest.raises(Unavailable):
        lab.call(successor_agent, successor_broker, "/claim", claim)
    pending = readback(lab)
    observed = read_target(lab, reachable)
    record_property("held_barrier", json.dumps({"durable": pending, "reachable": observed}, sort_keys=True))
    assert pending["home"]["phase"] == "preparing"
    successor_generation = pending["home"]["generation"]
    assert pending["anchor"]["generation"] == successor_generation > former.generation
    assert pending["targets"][reachable]["fence"] == observed["generation"] == successor_generation
    assert pending["targets"][offline]["fence"] == former.generation
    assert observed["effective"] == "quarantined"
    assert pending["targets"][reachable]["receipts"] == [(former.generation, "observing")]
    assert pending["targets"][offline]["receipts"] == []
    with pytest.raises(Denied):
        lab.call(former.agent, former.broker, "/write", stale)
    assert readback(lab) == pending

    lab.start(offline)
    retry = make_claim(lab.policy, successor_agent, successor_broker, prior, lab.instances[successor_agent])
    successor = Assignment.model_validate(lab.call(successor_agent, successor_broker, "/claim", retry))
    assert successor.generation == successor_generation
    for target in lab.targets:
        assert read_target(lab, target)["effective"] == "quarantined"
        lab.call(successor.agent, successor.broker, "/write", write_request(successor, target))
    recovered = readback(lab)
    observed = {target: read_target(lab, target) for target in lab.targets}
    record_property("committed_successor", json.dumps({"durable": recovered, "targets": observed}, sort_keys=True))
    assert recovered["home"]["phase"] == "active" and recovered["home"]["generation"] == successor_generation
    assert all(item["fence"] == successor_generation for item in recovered["targets"].values())
    assert recovered["targets"][reachable]["receipts"] == [
        (former.generation, "observing"), (successor_generation, "observing"),
    ]
    assert recovered["targets"][offline]["receipts"] == [(successor_generation, "observing")]
    assert all(item["effective"] == "observing" for item in observed.values())


def test_I05_restored_home_holds_against_current_anchor(lab, record_property):
    def claim(agent, broker, generation):
        proof = make_claim(lab.policy, agent, broker, generation, lab.instances[agent])
        return Assignment.model_validate(lab.call(agent, broker, "/claim", proof))

    def available_generation():
        expected = Stamp.model_validate(lab.call("operator", "anchor", "/stamp"))
        return lab.call("operator", "home", "/recover", expected)["generation"]

    prior = claim("agent-a", "broker-a", 0)
    snapshot = lab.root / "home-snapshot.sqlite"
    with (closing(sqlite3.connect(lab.database("home"))) as original,
          closing(sqlite3.connect(snapshot)) as backup):
        original.backup(backup)
    current = claim("agent-b", "broker-b", available_generation())
    target = lab.targets[0]

    def request(assignment):
        version = read_target(lab, target)["version"]
        mutation = Mutation(assignment=assignment, target=target, marker="observing", expected_version=version)
        return Write(command=command(mutation, lab.instances[assignment.agent]),
                     approval=approve(mutation, lab.approval), credential_until_ns=assignment.expires_ns)

    lab.call(current.agent, current.broker, "/write", request(current))
    assert read_target(lab, target)["effective"] == "observing"
    staged = request(current)
    lab.stop("home")
    with (closing(sqlite3.connect(snapshot)) as backup,
          closing(sqlite3.connect(lab.database("home"))) as restored):
        backup.backup(restored)
    lab.start("home")
    with pytest.raises((Denied, Unavailable)):
        lab.call(current.agent, current.broker, "/write", staged)
    stale = readback(lab)
    observed = read_target(lab, target)
    record_property("stale_home_restore", json.dumps({"durable": stale, "target": observed}, sort_keys=True))
    assert stale["home"]["generation"] == prior.generation
    assert stale["anchor"]["generation"] == current.generation > prior.generation
    assert stale["targets"][target]["marker"][1] == "quarantined"
    assert observed["effective"] == observed["marker"] == "quarantined"
    assert readback(lab) == stale
    assert stale["targets"][target]["receipts"] == [(current.generation, "observing")]

    new = claim("agent-a", "broker-a", available_generation())
    assert new.generation > current.generation
    assert read_target(lab, target)["effective"] == "quarantined"
    lab.call(new.agent, new.broker, "/write", request(new))
    final = readback(lab)
    observed = read_target(lab, target)
    record_property("restored_home_reconciled", json.dumps({"durable": final, "target": observed}, sort_keys=True))
    assert final["anchor"]["generation"] == final["home"]["generation"] == new.generation
    assert observed["effective"] == "observing"
    assert final["targets"][target]["receipts"] == [(current.generation, "observing"), (new.generation, "observing")]
