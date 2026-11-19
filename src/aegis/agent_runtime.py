"""One lab agent consumes its own durable JetStream copy and audits dry runs."""

import asyncio
import json
import logging
import os

import nats
from nats.js.api import ConsumerConfig
from nats.js.errors import NotFoundError
from pydantic import ValidationError

from .api import STREAM, SUBJECT
from .artifact import SignedFinding
from .config import load_local
from .core import LocalAgent
from .storage import SqliteAudit

logger = logging.getLogger(__name__)


async def run() -> None:
    policy, inventory = load_local(os.environ["AEGIS_LOCAL_CONFIG"])
    audit = SqliteAudit(os.environ["AEGIS_AUDIT_DB"])
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
        SUBJECT,
        durable="lab-agent",
        stream=STREAM,
        config=ConsumerConfig(max_deliver=5, ack_wait=10),
    )
    while True:
        try:
            messages = await subscription.fetch(10, timeout=1)
        except TimeoutError:
            continue
        for message in messages:
            try:
                envelope = SignedFinding.model_validate_json(message.data)
                decision = agent.evaluate(envelope)
                print(json.dumps(decision.__dict__, sort_keys=True), flush=True)
                await message.ack()
            except (ValidationError, ValueError):
                logger.warning("rejected malformed or conflicting event")
                await message.term()
            except Exception:
                logger.exception("agent processing failed; delivery will retry")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run())
