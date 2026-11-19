"""Read-only summary of local dead letters; never replays their payloads."""

import argparse
import asyncio
import base64
import hashlib
import json

import nats
from nats.js.errors import NotFoundError

from aegis.api import DEAD_LETTER_STREAM


async def run(url: str, limit: int):
    nc = await nats.connect(url)
    try:
        js = nc.jetstream()
        info = await js.stream_info(DEAD_LETTER_STREAM)
        first = max(info.state.first_seq, info.state.last_seq - limit + 1)
        for sequence in range(first, info.state.last_seq + 1):
            try:
                message = await js.get_msg(DEAD_LETTER_STREAM, seq=sequence)
            except NotFoundError:
                continue
            record = json.loads(message.data)
            body = base64.b64decode(record["body_base64"], validate=True)
            print(json.dumps({
                "dead_letter_sequence": sequence,
                "agent_id": record["agent_id"],
                "source_stream_sequence": record["stream_sequence"],
                "deliveries": record["deliveries"],
                "reason": record["reason"],
                "recorded_at": record["recorded_at"],
                "body_sha256": hashlib.sha256(body).hexdigest(),
            }, sort_keys=True))
    finally:
        await nc.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--nats", default="nats://127.0.0.1:14222")
    parser.add_argument("--limit", type=int, default=100)
    arguments = parser.parse_args()
    if arguments.limit < 1:
        parser.error("--limit must be positive")
    asyncio.run(run(arguments.nats, arguments.limit))
