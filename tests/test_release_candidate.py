"""Regression tests for the performance changes on the hardened agent path."""

import asyncio
from contextlib import suppress
from dataclasses import replace
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.artifact import sign
from aegis import api
from aegis.trust import TrustStore
from test_phase2c_hardening import NOW, finding, grant, local


def test_post_commit_signal_during_dispatch_is_not_lost(monkeypatch):
    async def scenario():
        wakeup = asyncio.Event()
        first_poll = asyncio.Event()
        finish_poll = asyncio.Event()
        second_poll = asyncio.Event()

        async def dispatch_once(repo, js):
            if first_poll.is_set():
                second_poll.set()
            else:
                first_poll.set()
                await finish_poll.wait()
            return 0

        monkeypatch.setattr(api, "dispatch_once", dispatch_once)
        monkeypatch.setattr(api, "OUTBOX_POLL_SECONDS", 60)
        bus = api.OutboxBus(asyncio.get_running_loop(), wakeup)
        task = asyncio.create_task(api.dispatch(None, None, wakeup))
        try:
            await asyncio.wait_for(first_poll.wait(), 2)
            await asyncio.to_thread(bus.publish, None)
            finish_poll.set()
            await asyncio.wait_for(second_poll.wait(), 2)
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    asyncio.run(scenario())


def test_key_rotation_keeps_audited_old_finding_denied_on_replay(tmp_path):
    old_key = Ed25519PrivateKey.generate()
    old_grant = grant("finder", old_key, {"finding"})
    old = finding(old_key)
    agent, audit = local(tmp_path, TrustStore([old_grant]))
    assert agent.evaluate(old, NOW).outcome == "allow_dry_run"
    audit.db.close()

    replacement = Ed25519PrivateKey.generate()
    new_grant = replace(grant("finder", replacement, {"finding"}), key_id="rotated")
    revoked = replace(old_grant, revoked_at=NOW - timedelta(seconds=1))
    restarted, audit = local(tmp_path, TrustStore([revoked, new_grant]))
    assert restarted.evaluate(old, NOW).reason_code == "PUBLISHER_KEY_REVOKED"
    assert len(audit.all_decisions()) == 1
    newer = sign(finding(replacement, sequence=2).finding, replacement, "rotated")
    assert restarted.evaluate(newer, NOW).outcome == "allow_dry_run"
    assert audit.high_water("finder") == 2
    audit.db.close()
