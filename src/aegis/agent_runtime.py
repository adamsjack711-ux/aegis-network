"""One lab agent consumes its own durable JetStream copy and audits dry runs."""

import asyncio
import json
import logging
import os
import re

import nats
from nats.js.api import AckPolicy, ConsumerConfig
from nats.js.errors import NotFoundError
from pydantic import ValidationError

from .api import STREAM
from .artifact import parse_event
from .config import load_local
from .core import LocalAgent
from .storage import SqliteAudit

logger = logging.getLogger(__name__)


def durable_name(agent_id: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", agent_id):
        raise ValueError("AEGIS_AGENT_ID must be a stable lowercase identifier")
    return f"aegis-{agent_id}"


async def process_message(message, agent: LocalAgent) -> None:
    try:
        envelope = parse_event(message.data)
        decision = agent.evaluate_event(envelope)
        print(json.dumps(decision.__dict__, sort_keys=True), flush=True)
        await message.ack_sync()
    except (ValidationError, ValueError, TypeError, AttributeError, json.JSONDecodeError):
        logger.warning("rejected malformed or conflicting event")
        await message.term()
    except Exception:
        logger.exception("agent processing failed; delivery will retry")


async def run() -> None:
    agent_id = os.environ["AEGIS_AGENT_ID"]
    durable = durable_name(agent_id)
    policy, inventory = load_local(os.environ["AEGIS_LOCAL_CONFIG"])
    audit = SqliteAudit(os.environ["AEGIS_AUDIT_DB"], agent_id=agent_id)
    agent = LocalAgent(policy, inventory, audit)
    nc = await nats.connect(os.environ["AEGIS_NATS_URL"])
    js = nc.jetstream()
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
        config=ConsumerConfig(max_deliver=5, ack_wait=10, ack_policy=AckPolicy.EXPLICIT),
    )
    while True:
        try:
            messages = await subscription.fetch(10, timeout=1)
        except TimeoutError:
            continue
        except Exception:
            logger.exception("broker fetch failed; waiting for reconnect")
            await asyncio.sleep(0.5)
            continue
        for message in messages:
            await process_message(message, agent)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run())
