"""One lab agent consumes its own durable JetStream copy and audits dry runs."""

import asyncio
import base64
from datetime import datetime, timezone
import json
import logging
import os
import signal
from uuid import uuid4

import httpx
import nats
from nats.js.api import AckPolicy, ConsumerConfig
from nats.js.errors import NotFoundError
from pydantic import ValidationError

from .api import DEAD_LETTER_SUBJECT, STREAM
from .artifact import SignedRevocation, parse_event
from .config import load_local
from .core import LocalAgent
from .identity import IdentityLease, IdentityLost, canonical_agent_id, renew_lease
from .recovery import RecoveryBlocked, reconcile
from .storage import SqliteAudit

logger = logging.getLogger(__name__)


def durable_name(agent_id: str) -> str:
    return f"aegis-{canonical_agent_id(agent_id)}"


async def dead_letter(js, message, agent_id: str, reason: str) -> None:
    metadata = getattr(message, "metadata", None)
    stream_seq = getattr(getattr(metadata, "sequence", None), "stream", None)
    deliveries = getattr(metadata, "num_delivered", None)
    record = {
        "schema_version": "1.0", "agent_id": agent_id,
        "stream_sequence": stream_seq, "deliveries": deliveries,
        "subject": getattr(message, "subject", None), "reason": reason,
        "body_base64": base64.b64encode(message.data).decode("ascii"),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    await js.publish(DEAD_LETTER_SUBJECT, json.dumps(record, sort_keys=True).encode(),
                     headers={"Nats-Msg-Id": f"dead-{agent_id}-{stream_seq or uuid4()}"})


async def process_message(message, agent: LocalAgent, js=None, lease=None,
                          max_attempts: int = 5) -> None:
    if lease is not None:
        await lease.ensure()
    envelope = None
    try:
        envelope = parse_event(message.data)
        decision = agent.evaluate_event(envelope)
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
    print(json.dumps(decision.__dict__, sort_keys=True), flush=True)
    try:
        await message.ack_sync()
    except Exception:
        logger.exception("ack failed after commit; delivery will retry")


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
        await consume(agent, audit, js, lease, renew_task, client, durable)
    finally:
        renew_task.cancel()
        await client.aclose()
        await lease.release()
        await nc.close()


async def consume(agent, audit, js, lease, renew_task, client, durable):
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
            try:
                await reconcile(agent, audit, client, lease)
            except RecoveryBlocked:
                logger.critical("signed replay journal failed validation; agent stopped")
                raise
            except Exception:
                logger.exception("journal reconciliation failed; pausing event delivery")
                await asyncio.sleep(1)
                continue
            next_reconcile = asyncio.get_running_loop().time() + 5
        try:
            messages = await subscription.fetch(10, timeout=1)
        except TimeoutError:
            continue
        except Exception:
            logger.exception("broker fetch failed; waiting for reconnect")
            await asyncio.sleep(0.5)
            continue
        for message in messages:
            try:
                await process_message(message, agent, js, lease)
            except IdentityLost:
                raise
            except Exception:
                logger.exception("message processing paused until broker and lease recover")
                await asyncio.sleep(0.5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run())
