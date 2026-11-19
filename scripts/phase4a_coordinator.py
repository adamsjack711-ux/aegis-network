"""Trace the existing coordinator's HTTP routes in a disposable lab."""

from contextlib import asynccontextmanager
import json
import time

import resource
import sys

from aegis.api import app


def log_resources(stage, ns):
    usage = resource.getrusage(resource.RUSAGE_SELF)
    print(json.dumps(dict(kind="resources", stage=stage, ns=ns,
                          cpu_s=usage.ru_utime + usage.ru_stime,
                          peak_rss_bytes=usage.ru_maxrss *
                          (1 if sys.platform == "darwin" else 1024))), flush=True)


class TimedRequests:
    def __init__(self, app):
        self.app = app
        self.next_resource_sample = 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        start = time.perf_counter_ns()
        status = None

        async def observe(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, observe)
        finally:
            end = time.perf_counter_ns()
            print(json.dumps(dict(route=scope["path"], status=status, start=start,
                                  end=end)), flush=True)
            if end >= self.next_resource_sample:
                self.next_resource_sample = end + 1_000_000_000
                log_resources("serving", end)


original_lifespan = app.router.lifespan_context


@asynccontextmanager
async def measured_lifespan(app):
    async with original_lifespan(app):
        yield
    log_resources("shutdown", time.perf_counter_ns())


app.router.lifespan_context = measured_lifespan
app.add_middleware(TimedRequests)
