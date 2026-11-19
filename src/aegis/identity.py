"""Broker-scoped active lease for a stable UUIDv4 deployment identity."""

import asyncio
import secrets
import time
from uuid import UUID

from nats.js.api import KeyValueConfig, StorageType
from nats.js.errors import (
    BucketNotFoundError, KeyDeletedError, KeyNotFoundError, KeyWrongLastSequenceError,
)

LEASE_BUCKET = "AEGIS_AGENT_LEASES"
LEASE_TTL_SECONDS = 30


class IdentityInUse(ValueError):
    pass


class IdentityLost(RuntimeError):
    pass


def canonical_agent_id(value: str) -> str:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ValueError("AEGIS_AGENT_ID must be a canonical UUIDv4") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError("AEGIS_AGENT_ID must be a canonical UUIDv4")
    return value


class IdentityLease:
    def __init__(self, kv, agent_id: str, token: bytes, revision: int):
        self.kv = kv
        self.agent_id = canonical_agent_id(agent_id)
        self.token = token
        self.revision = revision
        self.lost = False
        self.lock = asyncio.Lock()

    @classmethod
    async def claim(cls, js, agent_id: str, wait_seconds: float = 0):
        canonical_agent_id(agent_id)
        try:
            kv = await js.key_value(LEASE_BUCKET)
        except BucketNotFoundError:
            try:
                kv = await js.create_key_value(KeyValueConfig(
                    bucket=LEASE_BUCKET, history=1, ttl=LEASE_TTL_SECONDS,
                    storage=StorageType.FILE,
                ))
            except Exception:
                # A second process may have created the bucket concurrently.
                kv = await js.key_value(LEASE_BUCKET)
        token = secrets.token_bytes(32)
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                revision = await kv.create(agent_id, token)
                break
            except KeyWrongLastSequenceError as exc:
                if time.monotonic() >= deadline:
                    raise IdentityInUse("agent identity already has an active broker lease") from exc
                await asyncio.sleep(1)
        return cls(kv, agent_id, token, revision)

    async def ensure(self) -> None:
        async with self.lock:
            if self.lost:
                raise IdentityLost("agent identity lease was lost")
            try:
                self.revision = await self.kv.update(
                    self.agent_id, self.token, last=self.revision)
            except (KeyNotFoundError, KeyDeletedError):
                try:
                    self.revision = await self.kv.create(self.agent_id, self.token)
                except KeyWrongLastSequenceError as exc:
                    self.lost = True
                    raise IdentityLost("agent identity was claimed by another process") from exc
            except KeyWrongLastSequenceError as exc:
                try:
                    entry = await self.kv.get(self.agent_id)
                except (KeyNotFoundError, KeyDeletedError):
                    self.lost = True
                    raise IdentityLost("agent identity lease disappeared") from exc
                if entry.value != self.token:
                    self.lost = True
                    raise IdentityLost("agent identity was claimed by another process") from exc
                # The update may have committed while its response was lost.
                self.revision = entry.revision

    async def release(self) -> None:
        async with self.lock:
            if not self.lost:
                try:
                    await self.kv.delete(self.agent_id, last=self.revision)
                except (KeyWrongLastSequenceError, KeyNotFoundError, KeyDeletedError):
                    pass


async def renew_lease(lease: IdentityLease) -> None:
    while True:
        await asyncio.sleep(LEASE_TTL_SECONDS / 3)
        try:
            await lease.ensure()
        except IdentityLost:
            raise
        except Exception:
            # The message path also checks the lease and will withhold ack.
            # Retry when the broker reconnects.
            await asyncio.sleep(1)
