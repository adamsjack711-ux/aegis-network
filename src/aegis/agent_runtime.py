"""One lab agent consumes its own durable JetStream copy and audits dry runs."""

import asyncio
import base64
from datetime import datetime, timezone
from functools import partial
import json
import logging
import os
import signal
import time
from uuid import uuid4

import httpx
import nats
from nats.js.api import AckPolicy, ConsumerConfig
from nats.js.errors import NotFoundError
from pydantic import ValidationError

from .artifact import SignedRevocation, parse_event
from .config import load_local
from .core import LocalAgent
from .identity import IdentityLease, IdentityLost, canonical_agent_id, renew_lease
from .mesh import CRITICAL_STREAM, CRITICAL_SUBJECT, DEAD_LETTER_SUBJECT, STREAM, priority_enabled
from .recovery import RecoveryBlocked, reconcile
from .storage import SqliteAudit

logger = logging.getLogger(__name__)


def durable_name(agent_id: str) -> str:
    return f"aegis-{canonical_agent_id(agent_id)}"


async def dead_letter(js, message, agent_id: str, reason: str) -> None:
    metadata = getattr(message, "metadata", None)
    stream_seq = getattr(getattr(metadata, "sequence", None), "stream", None)
    stream = getattr(metadata, "stream", STREAM)
    deliveries = getattr(metadata, "num_delivered", None)
    record = {
        "schema_version": "1.0", "agent_id": agent_id,
        "stream": stream, "stream_sequence": stream_seq, "deliveries": deliveries,
        "subject": getattr(message, "subject", None), "reason": reason,
        "body_base64": base64.b64encode(message.data).decode("ascii"),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    namespace = f"{agent_id}-{stream}" if stream != STREAM else agent_id
    await js.publish(DEAD_LETTER_SUBJECT, json.dumps(record, sort_keys=True).encode(),
                     headers={"Nats-Msg-Id": f"dead-{namespace}-{stream_seq or uuid4()}"})


async def process_message(message, agent: LocalAgent, js=None, lease=None,
                          max_attempts: int = 5, *, observe=None, critical=False, on_commit=None,
                          received_ns=None, ordered_revocations=True, fence_ack=False) -> None:
    received_ns = received_ns if received_ns is not None else time.perf_counter_ns()
    if lease is not None:
        await lease.ensure()
    lease_checked_ns = time.perf_counter_ns()
    envelope = None
    try:
        envelope = parse_event(message.data)
        if critical and not isinstance(envelope, SignedRevocation):
            raise ValueError("critical lane only accepts signed revocations")
        decision = (agent.evaluate_revocation(envelope, ordered=ordered_revocations and not critical)
                    if isinstance(envelope, SignedRevocation) else agent.evaluate_event(envelope))
    except (ValidationError, ValueError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        logger.warning("rejected malformed or conflicting event")
        try:
            if js is not None:
                await dead_letter(js, message, agent.audit.agent_id, type(exc).__name__)
            if not isinstance(envelope, SignedRevocation):
                await message.term()
        except Exception:
            logger.exception("dead-letter publish failed; delivery will retry")
        return
    except Exception as exc:
        logger.exception("agent processing failed; delivery will retry")
        deliveries = getattr(getattr(message, "metadata", None), "num_delivered", 1)
        if js is not None and deliveries >= max_attempts:
            try:
                await dead_letter(js, message, agent.audit.agent_id, type(exc).__name__)
                # An unaudited revocation can withdraw a prior allow. Keep
                # retrying its source message until the local ledger commits.
                if not isinstance(envelope, SignedRevocation):
                    await message.term()
            except Exception:
                logger.exception("dead-letter publish failed; delivery will retry")
        return
    committed_ns = time.perf_counter_ns()
    if on_commit is not None:
        on_commit(decision, received_ns, committed_ns)
    if observe is None and not critical:
        print(json.dumps(decision.__dict__, sort_keys=True), flush=True)
    if (critical or fence_ack) and lease is not None:
        await lease.ensure()
    try:
        await message.ack_sync()
    except Exception:
        logger.exception("ack failed after commit; delivery will retry")
    else:
        if observe is not None:
            observe(decision, received_ns, lease_checked_ns, committed_ns, time.perf_counter_ns())
        elif critical:
            print(json.dumps({"state": "ack_confirmed", "decision": decision.__dict__,
                              "received_ns": received_ns, "committed_ns": committed_ns,
                              "ack_confirmed_ns": time.perf_counter_ns()}, sort_keys=True), flush=True)


async def run() -> None:
    agent_id = os.environ["AEGIS_AGENT_ID"]
    durable = durable_name(agent_id)
    policy, inventory = load_local(os.environ["AEGIS_LOCAL_CONFIG"])
    audit = SqliteAudit(os.environ["AEGIS_AUDIT_DB"], agent_id=agent_id)
    agent = LocalAgent(policy, inventory, audit)
    nc = await nats.connect(os.environ["AEGIS_NATS_URL"])
    js = nc.jetstream()
    lease = await IdentityLease.claim(js, agent_id, wait_seconds=45)
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, task.cancel)
        except NotImplementedError:
            pass
    renew_task = asyncio.create_task(renew_lease(lease))
    client = httpx.AsyncClient(base_url=os.environ["AEGIS_COORDINATOR_URL"], timeout=10)
    try:
        await consume(agent, audit, js, lease, renew_task, client, durable, priority=priority_enabled())
    finally:
        renew_task.cancel()
        await client.aclose()
        await lease.release()
        await nc.close()


async def critical_delivery(agent, audit, js, lease, client, durable, *,
                            on_ack=None, on_commit=None, on_stage=None):
    """Independent wire and replay loops share only the identity and local audit."""

    async def wire():
        name = f"{durable}-withdrawals"
        while True:
            lease.require_live()
            subscription = None
            try:
                subscription = await js.pull_subscribe(
                    CRITICAL_SUBJECT, durable=name, stream=CRITICAL_STREAM,
                    config=ConsumerConfig(max_deliver=-1, ack_wait=2, max_ack_pending=16,
                                          ack_policy=AckPolicy.EXPLICIT),
                )
                if on_stage is not None:
                    on_stage("critical_subscribed", time.perf_counter_ns(), None)
                while True:
                    lease.require_live()
                    try:
                        messages = await subscription.fetch(1, timeout=0.5)
                    except TimeoutError:
                        continue
                    message = messages[0]
                    received_ns = time.perf_counter_ns()
                    if on_stage is not None:
                        on_stage("critical_received", received_ns, message.metadata.sequence.stream)
                    observe = partial(on_ack, message) if on_ack is not None else None
                    committed = partial(on_commit, message) if on_commit is not None else None
                    await process_message(message, agent, js, lease, observe=observe, critical=True,
                                          on_commit=committed, received_ns=received_ns)
            except IdentityLost:
                raise
            except Exception:
                logger.exception("withdrawal wire delivery paused until broker and lease recover")
                await asyncio.sleep(0.5)
            finally:
                if subscription is not None:
                    try:
                        await subscription.unsubscribe()
                    except nats.errors.BadSubscriptionError:
                        pass

    async def replay():
        while True:
            lease.require_live()
            try:
                if on_stage is not None:
                    on_stage("critical_replay_start", time.perf_counter_ns(), None)
                count = await reconcile(agent, audit, client, lease, page_size=16, critical=True)
                if on_stage is not None:
                    on_stage("critical_replay_end", time.perf_counter_ns(), count)
            except IdentityLost:
                raise
            except Exception:
                logger.exception("withdrawal replay unavailable")
                count = 0
            await asyncio.sleep(0 if count == 16 else 0.25)

    async with asyncio.TaskGroup() as tasks:
        tasks.create_task(wire())
        tasks.create_task(replay())


async def consume(agent, audit, js, lease, renew_task, client, durable, *, priority=False,
                  on_reconcile=None, before_message=None, on_ack=None, on_critical_commit=None,
                  on_critical_stage=None):
    ordinary = partial(consume_ordinary, agent, audit, js, lease, renew_task, client, durable,
                       on_reconcile=on_reconcile, before_message=before_message, on_ack=on_ack, priority=priority)
    if not priority:
        return await ordinary()
    async with asyncio.TaskGroup() as tasks:
        tasks.create_task(critical_delivery(agent, audit, js, lease, client, durable,
                                            on_ack=on_ack, on_commit=on_critical_commit,
                                            on_stage=on_critical_stage))
        tasks.create_task(ordinary())


async def consume_ordinary(agent, audit, js, lease, renew_task, client, durable, *, priority=False,
                  on_reconcile=None, before_message=None, on_ack=None):
    while True:
        try:
            await js.stream_info(STREAM)
            break
        except NotFoundError:
            await asyncio.sleep(0.5)
    subscription = await js.pull_subscribe(
        "aegis.>",
        durable=durable,
        stream=STREAM,
        config=ConsumerConfig(max_deliver=-1, ack_wait=10, ack_policy=AckPolicy.EXPLICIT),
    )
    next_reconcile = 0.0
    while True:
        if lease.lost or renew_task.done():
            raise IdentityLost("agent identity lease was lost")
        if asyncio.get_running_loop().time() >= next_reconcile:
            started_ns = time.perf_counter_ns() if on_reconcile is not None else 0
            try:
                recovered = await reconcile(agent, audit, client, lease, snapshot=priority)
            except IdentityLost:
                raise
            except RecoveryBlocked:
                if not priority:
                    logger.critical("signed replay journal failed validation; agent stopped")
                    raise
                logger.critical("ordinary replay blocked; withdrawal delivery continues")
                await asyncio.sleep(1)
                continue
            except Exception:
                logger.exception("journal reconciliation failed; pausing event delivery")
                await asyncio.sleep(1)
                continue
            if on_reconcile is not None:
                on_reconcile(recovered, started_ns, time.perf_counter_ns())
            next_reconcile = asyncio.get_running_loop().time() + 5
        try:
            messages = await subscription.fetch(10, timeout=1)
        except TimeoutError:
            continue
        except Exception:
            logger.exception("broker fetch failed; waiting for reconnect")
            await asyncio.sleep(0.5)
            continue
        if priority:
            try:
                # Wire delivery can race between coordinators. Apply the already
                # committed prefix in journal order before auditing this batch.
                await reconcile(agent, audit, client, lease, snapshot=True)
            except IdentityLost:
                raise
            except Exception:
                logger.exception("ordinary wire batch waiting for ordered replay")
                next_reconcile = 0
                continue
        for message in messages:
            try:
                if before_message is not None:
                    await before_message(message)
                observe = partial(on_ack, message) if on_ack is not None else None
                await process_message(message, agent, js, lease, observe=observe,
                                      ordered_revocations=not priority, fence_ack=priority)
            except IdentityLost:
                raise
            except Exception:
                logger.exception("message processing paused until broker and lease recover")
                await asyncio.sleep(0.5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run())
