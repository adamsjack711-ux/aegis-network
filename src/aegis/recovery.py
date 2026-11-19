"""Fail-closed replay from the coordinator's durable signed-event journal."""

import httpx
import json

from .artifact import SignedRevocation, parse_event
from .core import LocalAgent
from .storage import SqliteAudit


class RecoveryBlocked(RuntimeError):
    pass


async def reconcile(agent: LocalAgent, audit: SqliteAudit, client: httpx.AsyncClient,
                    lease, page_size: int = 100) -> int:
    recovered = 0
    while True:
        cursor = audit.journal_position()
        response = await client.get("/v1/events", params={"after": cursor, "limit": page_size})
        response.raise_for_status()
        try:
            page = response.json()
        except ValueError as exc:
            raise RecoveryBlocked("invalid replay page JSON") from exc
        if not isinstance(page, dict) or type(page.get("head")) is not int or not isinstance(page.get("events"), list):
            raise RecoveryBlocked("invalid replay page")
        head, events = page["head"], page["events"]
        if head < cursor or (not events and head > cursor):
            raise RecoveryBlocked("coordinator replay journal has a gap or rollback")
        for item in events:
            if not isinstance(item, dict) or type(item.get("position")) is not int:
                raise RecoveryBlocked("invalid replay event position")
            position = item["position"]
            if position <= cursor or position > head:
                raise RecoveryBlocked("out-of-order replay journal")
            try:
                envelope = parse_event(json.dumps(item["envelope"]).encode())
            except Exception as exc:
                raise RecoveryBlocked("invalid signed replay envelope") from exc
            await lease.ensure()
            try:
                decision = agent.evaluate_event(envelope)
            except ValueError as exc:
                raise RecoveryBlocked("replay event conflicts with local audit") from exc
            if isinstance(envelope, SignedRevocation) and decision.outcome != "revoked_dry_run":
                raise RecoveryBlocked("revocation replay failed local verification")
            audit.advance_journal(position)
            cursor = position
            recovered += 1
        if not events or cursor >= head:
            return recovered
