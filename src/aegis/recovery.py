"""Fail-closed replay from the coordinator's durable signed-event journal."""

import httpx
import json

from .artifact import SignedRevocation, parse_event
from .core import LocalAgent
from .storage import SqliteAudit


class RecoveryBlocked(RuntimeError):
    pass


async def reconcile(agent: LocalAgent, audit: SqliteAudit, client: httpx.AsyncClient,
                    lease, page_size: int = 100, *, critical: bool = False, snapshot: bool = False) -> int:
    recovered = 0
    cutoff = None
    while True:
        cursor = audit.journal_position(critical=critical)
        route = "/v1/revocations" if critical else "/v1/events"
        response = await client.get(route, params={"after": cursor, "limit": page_size})
        response.raise_for_status()
        try:
            page = response.json()
        except ValueError as exc:
            raise RecoveryBlocked("invalid replay page JSON") from exc
        if not isinstance(page, dict) or type(page.get("head")) is not int or not isinstance(page.get("events"), list):
            raise RecoveryBlocked("invalid replay page")
        head, events = page["head"], page["events"]
        if len(events) > page_size or head < cursor or (not events and head > cursor):
            raise RecoveryBlocked("coordinator replay journal has a gap or rollback")
        if not snapshot or cutoff is None:
            cutoff = head
        elif head < cutoff:
            raise RecoveryBlocked("coordinator replay journal head rolled back mid-scan")
        for item in events:
            if not isinstance(item, dict) or type(item.get("position")) is not int:
                raise RecoveryBlocked("invalid replay event position")
            position = item["position"]
            if position <= cursor or position > head:
                raise RecoveryBlocked("out-of-order replay journal")
            if position > cutoff:
                return recovered
            try:
                envelope = parse_event(json.dumps(item["envelope"]).encode())
            except Exception as exc:
                raise RecoveryBlocked("invalid signed replay envelope") from exc
            if critical and not isinstance(envelope, SignedRevocation):
                raise RecoveryBlocked("critical replay contained an ordinary event")
            await lease.ensure()
            try:
                decision = (agent.evaluate_revocation(envelope, ordered=False) if critical
                            else agent.evaluate_event(envelope))
            except ValueError as exc:
                raise RecoveryBlocked("replay event conflicts with local audit") from exc
            if isinstance(envelope, SignedRevocation) and decision.outcome != "revoked_dry_run":
                raise RecoveryBlocked("revocation replay failed local verification")
            audit.advance_journal(position, critical=critical)
            cursor = position
            recovered += 1
        if critical or not events or cursor >= cutoff:
            return recovered
