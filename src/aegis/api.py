"""Coordinator HTTP ingestion and durable outbox dispatcher."""

import asyncio
import logging
import os
from contextlib import asynccontextmanager

import nats
from fastapi import FastAPI, HTTPException
from nats.js.errors import NotFoundError
from psycopg import errors as pg_errors

from .artifact import SignedEvent, SignedFinding, SignedRevocation, event_id
from .config import load_publishers
from .core import Coordinator
from .postgres import PostgresRepository, SequenceConflict

SUBJECT = "aegis.findings.v1"
REVOCATION_SUBJECT = "aegis.revocations.v1"
STREAM = "AEGIS_FINDINGS"
logger = logging.getLogger(__name__)


class OutboxBus:
    """The repository transaction creates the outbox row; background task publishes it."""

    def publish(self, envelope: SignedEvent) -> None:
        pass


async def dispatch_once(repo: PostgresRepository, js) -> int:
    sent = 0
    pending = await asyncio.to_thread(repo.pending)
    for envelope in pending:
        eid = event_id(envelope)
        subject = SUBJECT if isinstance(envelope, SignedFinding) else REVOCATION_SUBJECT
        await js.publish(
            subject, envelope.model_dump_json().encode(), headers={"Nats-Msg-Id": eid},
        )
        await asyncio.to_thread(repo.mark_sent, eid)
        sent += 1
    return sent


async def dispatch(repo: PostgresRepository, js) -> None:
    while True:
        try:
            await dispatch_once(repo, js)
        except Exception:
            logger.exception("outbox dispatch failed")
        await asyncio.sleep(0.2)


@asynccontextmanager
async def lifespan(app: FastAPI):
    repo = PostgresRepository(os.environ["AEGIS_DATABASE_URL"])
    publishers = load_publishers(os.environ["AEGIS_PUBLISHERS_FILE"])
    nc = await nats.connect(os.environ["AEGIS_NATS_URL"])
    js = nc.jetstream()
    try:
        info = await js.stream_info(STREAM)
        subjects = set(info.config.subjects or [])
        if REVOCATION_SUBJECT not in subjects:
            info.config.subjects = sorted(subjects | {SUBJECT, REVOCATION_SUBJECT})
            await js.update_stream(info.config)
    except NotFoundError:
        await js.add_stream(name=STREAM, subjects=[SUBJECT, REVOCATION_SUBJECT])
    app.state.coordinator = Coordinator(publishers, repo, OutboxBus())
    task = asyncio.create_task(dispatch(repo, js))
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await nc.drain()


app = FastAPI(title="Aegis Mesh lab coordinator", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/findings", status_code=202)
def submit(envelope: SignedFinding):
    try:
        created = app.state.coordinator.submit(envelope)
    except ValueError as exc:
        if isinstance(exc, SequenceConflict):
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except pg_errors.UniqueViolation as exc:
        raise HTTPException(status_code=409, detail="publisher sequence conflict") from exc
    return {"artifact_id": str(envelope.finding.artifact_id), "accepted": created}


@app.post("/v1/revocations", status_code=202)
def revoke(envelope: SignedRevocation):
    try:
        created = app.state.coordinator.revoke(envelope)
    except SequenceConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"revocation_id": str(envelope.revocation.revocation_id), "accepted": created}
