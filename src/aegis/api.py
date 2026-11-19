"""Coordinator HTTP ingestion and durable outbox dispatcher."""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from functools import partial

import nats
from anyio import CapacityLimiter, to_thread
from fastapi import FastAPI, HTTPException, Query
from nats.js.api import DiscardPolicy, RetentionPolicy, StorageType, StreamConfig
from nats.js.errors import NotFoundError
from psycopg import errors as pg_errors

from .artifact import SignedEvent, SignedFinding, SignedRevocation, event_id
from .config import load_publishers
from .core import Coordinator
from .mesh import (
    CRITICAL_MAX_BYTES, CRITICAL_STREAM, CRITICAL_SUBJECT, DEAD_LETTER_STREAM,
    DEAD_LETTER_SUBJECT, MAX_EVENT_BYTES, REVOCATION_SUBJECT, STREAM, SUBJECT, priority_enabled,
)
from .postgres import AdmissionFull, EventTooLarge, PostgresRepository, SequenceConflict

FINDING_RETENTION_SECONDS = 24 * 60 * 60
DEAD_LETTER_RETENTION_SECONDS = 7 * FINDING_RETENTION_SECONDS
STREAM_MAX_BYTES = 64 * 1024 * 1024
OUTBOX_BATCH_SIZE = 100
OUTBOX_POLL_SECONDS = 0.2
CRITICAL_BATCH_SIZE = 16
logger = logging.getLogger(__name__)


class OutboxBus:
    """Nudge the dispatcher after the repository has committed the outbox row."""

    def __init__(self, loop: asyncio.AbstractEventLoop, wakeup: asyncio.Event, critical=None):
        self.loop = loop
        self.wakeup = wakeup
        self.critical = critical

    def publish(self, envelope: SignedEvent) -> None:
        try:
            wakeup = self.critical if self.critical is not None and isinstance(envelope, SignedRevocation) else self.wakeup
            self.loop.call_soon_threadsafe(wakeup.set)
        except RuntimeError:
            # The next process will recover the already committed row by polling.
            pass


async def dispatch_once(repo: PostgresRepository, js, *, kind=None) -> int:
    sent = 0
    batch_size = CRITICAL_BATCH_SIZE if kind == "revocation" else OUTBOX_BATCH_SIZE
    pending = (await asyncio.to_thread(repo.pending) if kind is None else
               await asyncio.to_thread(repo.pending, batch_size, kind=kind))
    for envelope in pending:
        eid = event_id(envelope)
        if kind == "revocation":
            subject = CRITICAL_SUBJECT
        else:
            subject = SUBJECT if isinstance(envelope, SignedFinding) else REVOCATION_SUBJECT
        await js.publish(
            subject, envelope.model_dump_json().encode(), headers={"Nats-Msg-Id": eid},
        )
        await asyncio.to_thread(repo.mark_sent, eid)
        sent += 1
    return sent


async def dispatch(repo: PostgresRepository, js, wakeup: asyncio.Event, *, kind=None) -> None:
    while True:
        # Clear before reading: commits during the poll or publish must wake us.
        wakeup.clear()
        try:
            sent = await dispatch_once(repo, js) if kind is None else await dispatch_once(repo, js, kind=kind)
        except Exception:
            logger.exception("outbox dispatch failed")
            await asyncio.sleep(OUTBOX_POLL_SECONDS)
            continue
        if sent >= (CRITICAL_BATCH_SIZE if kind == "revocation" else OUTBOX_BATCH_SIZE):
            continue
        try:
            await asyncio.wait_for(wakeup.wait(), timeout=OUTBOX_POLL_SECONDS)
        except TimeoutError:
            pass


async def ensure_streams(js, *, priority=False) -> None:
    specs = [
        (STREAM, [SUBJECT, REVOCATION_SUBJECT], FINDING_RETENTION_SECONDS),
        (DEAD_LETTER_STREAM, [DEAD_LETTER_SUBJECT], DEAD_LETTER_RETENTION_SECONDS),
    ]
    if priority:
        specs.append((CRITICAL_STREAM, [CRITICAL_SUBJECT], FINDING_RETENTION_SECONDS))
    for name, subjects, max_age in specs:
        try:
            info = await js.stream_info(name)
            config = info.config
            config.subjects = sorted(set(config.subjects or []) | set(subjects))
            exists = True
        except NotFoundError:
            config = StreamConfig(name=name, subjects=subjects)
            exists = False
        config.retention = RetentionPolicy.LIMITS
        config.storage = StorageType.FILE
        config.max_age = max_age
        config.max_bytes = CRITICAL_MAX_BYTES if name == CRITICAL_STREAM else STREAM_MAX_BYTES
        config.discard = DiscardPolicy.NEW
        if name in (STREAM, CRITICAL_STREAM):
            config.max_msg_size = MAX_EVENT_BYTES
        if exists:
            await js.update_stream(config)
        else:
            await js.add_stream(config)


@asynccontextmanager
async def lifespan(app: FastAPI):
    priority = priority_enabled()
    repo = PostgresRepository(os.environ["AEGIS_DATABASE_URL"], priority=priority)
    publishers = load_publishers(os.environ["AEGIS_PUBLISHERS_FILE"])
    nc = await nats.connect(os.environ["AEGIS_NATS_URL"])
    js = nc.jetstream()
    await ensure_streams(js, priority=priority)
    app.state.repo = repo
    app.state.revocation_workers = CapacityLimiter(4)
    app.state.revocation_replay_workers = CapacityLimiter(4)
    wakeup = asyncio.Event()
    critical = asyncio.Event() if priority else None
    bus = OutboxBus(asyncio.get_running_loop(), wakeup, critical)
    app.state.coordinator = Coordinator(publishers, repo, bus)
    tasks = [asyncio.create_task(dispatch(repo, js, wakeup, kind="finding" if priority else None))]
    if priority:
        tasks.append(asyncio.create_task(dispatch(repo, js, critical, kind="revocation")))
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await nc.drain()


app = FastAPI(title="Aegis Mesh lab coordinator", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/v1/events")
def replay_events(after: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=100)):
    events, head = app.state.repo.events_after(after, limit)
    return {"events": events, "head": head}


@app.get("/v1/revocations")
async def replay_revocations(after: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1, le=100)):
    read = partial(app.state.repo.events_after, after, limit, critical=True)
    limiter = getattr(app.state, "revocation_replay_workers", None)
    events, head = await to_thread.run_sync(read, limiter=limiter)
    return {"events": events, "head": head}


def admission_error(exc: AdmissionFull | EventTooLarge) -> HTTPException:
    if isinstance(exc, AdmissionFull):
        return HTTPException(status_code=503, detail=str(exc), headers={"Retry-After": "1"})
    return HTTPException(status_code=413, detail=str(exc))


@app.post("/v1/findings", status_code=202)
def submit(envelope: SignedFinding):
    try:
        created = app.state.coordinator.submit(envelope)
    except (AdmissionFull, EventTooLarge) as exc:
        raise admission_error(exc) from exc
    except ValueError as exc:
        if isinstance(exc, SequenceConflict):
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except pg_errors.UniqueViolation as exc:
        raise HTTPException(status_code=409, detail="publisher sequence conflict") from exc
    return {"artifact_id": str(envelope.finding.artifact_id), "accepted": created}


@app.post("/v1/revocations", status_code=202)
async def revoke(envelope: SignedRevocation):
    try:
        limiter = getattr(app.state, "revocation_workers", None)
        created = await to_thread.run_sync(app.state.coordinator.revoke, envelope, limiter=limiter)
    except SequenceConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (AdmissionFull, EventTooLarge) as exc:
        raise admission_error(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"revocation_id": str(envelope.revocation.revocation_id), "accepted": created}
