"""Dormant OpenAI Responses transport for the provider-independent research protocol.

Construction is inert. Every call requires an explicit authorization flag supplied by
an approved experiment runner; this module is never used by the offline evaluator.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .research import ProviderResult, Usage


_ENDPOINT = "https://api.openai.com/v1/responses"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("provider redirect refused")


@dataclass(frozen=True)
class OpenAIResponsesProvider:
    """Bounded implementation of JSONProvider; no feed or protected writer access."""

    model: str
    api_key: str = field(repr=False)
    authorized: bool = False
    timeout_seconds: float = 15.0
    _gate: threading.BoundedSemaphore = field(default_factory=lambda: threading.BoundedSemaphore(1),
                                              init=False, repr=False, compare=False)

    def __post_init__(self):
        if not self.model or len(self.model) > 128 or not self.api_key:
            raise ValueError("model and API key required")
        if not 1 <= self.timeout_seconds <= 30:
            raise ValueError("provider timeout outside allowed limits")

    def complete_json(self, instructions: str, payload: str, *, max_output_tokens: int) -> ProviderResult:
        if not self.authorized:
            raise PermissionError("external inference has not been authorized")
        if not self._gate.acquire(timeout=self.timeout_seconds):
            raise TimeoutError("provider concurrency limit")
        try:
            return self._complete_once(instructions, payload, max_output_tokens=max_output_tokens)
        finally:
            self._gate.release()

    def _complete_once(self, instructions: str, payload: str, *, max_output_tokens: int) -> ProviderResult:
        if not 100 <= max_output_tokens <= 1000:
            raise ValueError("provider output token limit")
        if len(instructions.encode()) + len(payload.encode()) > 20_000:
            raise ValueError("provider input byte limit")
        body = json.dumps({"model": self.model, "instructions": instructions,
                           "input": [{"role": "user", "content": payload}],
                           "max_output_tokens": max_output_tokens, "store": False,
                           "truncation": "disabled", "tools": []},
                          separators=(",", ":")).encode()
        request = urllib.request.Request(
            _ENDPOINT, data=body, method="POST",
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.api_key})
        try:
            with urllib.request.build_opener(_NoRedirect()).open(request, timeout=self.timeout_seconds) as response:
                if response.status != 200:
                    raise ValueError("provider HTTP status rejected")
                raw = response.read(16_385)
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ValueError("provider transport failed") from exc
        if len(raw) > 16_384:
            raise ValueError("provider response byte limit")
        try:
            data = json.loads(raw)
            if data["status"] != "completed" or data["model"] != self.model:
                raise ValueError("provider response incomplete or model mismatch")
            parts = [part["text"] for item in data["output"] if item.get("type") == "message"
                     and item.get("role") == "assistant" for part in item["content"]
                     if part.get("type") == "output_text"]
            if len(parts) != 1 or not isinstance(parts[0], str) or len(parts[0].encode()) > 8_000:
                raise ValueError("provider text response invalid")
            usage = data["usage"]
            input_tokens, output_tokens = usage["input_tokens"], usage["output_tokens"]
            if (type(input_tokens) is not int or type(output_tokens) is not int or
                    not 0 <= input_tokens <= 10_000 or not 0 <= output_tokens <= max_output_tokens):
                raise ValueError("provider token usage invalid")
            return ProviderResult(content=parts[0], provider="openai-responses",
                                  model=self.model, provider_version=None,
                                  usage=Usage(input_tokens=input_tokens, output_tokens=output_tokens))
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("provider response invalid") from exc
