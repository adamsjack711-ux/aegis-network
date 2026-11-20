"""Opt-in, bounded HTTPS JSON completion transport for private research only."""

import json
import ipaddress
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from .research import ProviderResult, Usage


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("provider redirect refused")


@dataclass(frozen=True)
class HTTPSJSONProvider:
    """Provider-neutral contract: POST instructions/payload, return content and usage.

    A caller must explicitly authorize each run. The endpoint is an exact HTTPS URL,
    with no redirects. The transport has no feed or Aegis writer capability.
    """

    endpoint: str
    model: str
    token: str
    authorized: bool = False
    timeout_seconds: float = 15.0
    provider_name: str = "authorized-https-json"

    def __post_init__(self):
        url = urllib.parse.urlsplit(self.endpoint)
        if (url.scheme != "https" or not url.hostname or url.username or url.password or
                url.fragment or url.port not in (None, 443) or
                not re.fullmatch(r"[A-Za-z0-9.-]+", url.hostname)):
            raise ValueError("provider endpoint must be an exact HTTPS host URL")
        host = url.hostname.lower()
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            raise ValueError("provider endpoint must be external")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            raise ValueError("provider endpoint must be external")
        if not self.model or len(self.model) > 128 or not self.token:
            raise ValueError("provider model and token required")
        if not 1 <= self.timeout_seconds <= 30:
            raise ValueError("provider timeout outside allowed limits")

    def complete_json(self, instructions: str, payload: str, *, max_output_tokens: int) -> ProviderResult:
        if not self.authorized:
            raise PermissionError("external model calls require explicit authorization")
        if not 100 <= max_output_tokens <= 1000:
            raise ValueError("provider output budget outside allowed limits")
        body = json.dumps({"model": self.model, "instructions": instructions,
                           "payload": payload, "max_output_tokens": max_output_tokens,
                           "response_format": "json"}, separators=(",", ":")).encode()
        if len(body) > 20_000:
            raise ValueError("provider input exceeds byte budget")
        request = urllib.request.Request(self.endpoint, data=body, method="POST",
                                         headers={"Content-Type": "application/json",
                                                  "Authorization": "Bearer " + self.token})
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            with opener.open(request, timeout=self.timeout_seconds) as response:
                if response.status != 200:
                    raise ValueError("provider HTTP status rejected")
                raw = response.read(max_output_tokens * 8 + 4097)
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ValueError("provider transport failed") from exc
        if len(raw) > max_output_tokens * 8 + 4096:
            raise ValueError("provider response exceeds byte budget")
        try:
            data = json.loads(raw)
            usage = data["usage"]
            content = data["content"]
            if (not isinstance(content, str) or not isinstance(usage, dict) or
                    not isinstance(data.get("provider_version"), (str, type(None))) or
                    not isinstance(usage.get("input_tokens"), int) or
                    not isinstance(usage.get("output_tokens"), int) or
                    isinstance(usage["input_tokens"], bool) or
                    isinstance(usage["output_tokens"], bool) or
                    usage["input_tokens"] < 0 or usage["input_tokens"] > 10_000 or
                    usage["output_tokens"] < 0 or
                    usage["output_tokens"] > max_output_tokens):
                raise ValueError("invalid provider response")
            return ProviderResult(content=content, provider=self.provider_name,
                                  model=self.model, provider_version=data.get("provider_version"),
                                  usage=Usage(input_tokens=usage["input_tokens"],
                                              output_tokens=usage["output_tokens"]))
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid provider response") from exc
