"""Regression tests for the performance changes on the hardened agent path."""

import asyncio
from contextlib import suppress

from aegis import api


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
