"""Bounded Responses transport for an already authorized research request."""

from dataclasses import dataclass
from hashlib import sha256
from http.client import HTTPSConnection
import json
import multiprocessing
import os
from pathlib import Path
import re
import stat
from tempfile import TemporaryFile
from time import monotonic

from aegis.intelligence.investigator import Draft, Limits
from aegis.intelligence.models import Record

HOST = "api.openai.com"
PATH = "/v1/responses"
DEADLINE_SECONDS = 10
RAW_REPLY_LIMIT = 16_384
DRAFT_LIMIT = Limits().max_output_bytes
REQUEST_LIMIT = Limits().max_input_bytes
OUTPUT_TOKENS = Limits().max_output_tokens
REQUEST_FIELDS = {"input", "instructions", "model", "text", "tool_choice", "tools",
                  "max_output_tokens", "service_tier", "store"}


class Refused(Exception):
    """Operator-facing outcome with no raw remote data."""


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON field")
        result[name] = value
    return result


def decode_json(content):
    return json.loads(content.decode("utf-8"), object_pairs_hook=unique_object)


def private_error_path(value):
    path = Path(value)
    mode = path.parent.lstat()
    if (not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.getuid() or mode.st_mode & 0o077
            or path.exists() or path.is_symlink()):
        raise Refused("HTTP diagnostic requires a new file in an owner-only directory")
    return path


def retain_http_error(response, credential, path):
    encoding = response.getheader("Content-Encoding", "identity").strip().lower()
    if encoding != "identity" or (response.length is not None and response.length > RAW_REPLY_LIMIT):
        return False
    raw = response.read(RAW_REPLY_LIMIT + 1)
    if (not raw or len(raw) > RAW_REPLY_LIMIT or response.length not in (None, 0)
            or credential.encode() in raw):
        return False
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory_fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            return False
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory_fd)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
        return True
    finally:
        os.close(directory_fd)


def request_once(body, credential, connection_factory, timeout, error_body_path):
    # Direct stdlib HTTPS has no redirect, proxy discovery, or retry handler.
    connection = connection_factory(HOST, port=443, timeout=timeout)
    try:
        connection.request("POST", PATH, body=body, headers={
            "Authorization": f"Bearer {credential}", "Content-Type": "application/json",
            "Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close",
        })
        response = connection.getresponse()
        if response.status != 200:
            if error_body_path is not None and 400 <= response.status <= 599:
                try:
                    retained = retain_http_error(response, credential, error_body_path)
                except OSError:
                    retained = False
                outcome = "retained" if retained else "unavailable"
                raise Refused(f"HTTP {response.status} refused; raw diagnostic {outcome}; attempt consumed")
            raise Refused("HTTP response refused; attempt consumed")
        content_type = response.getheader("Content-Type", "").partition(";")[0].strip().lower()
        encoding = response.getheader("Content-Encoding", "identity").strip().lower()
        if content_type != "application/json" or encoding != "identity":
            raise Refused("response format refused")
        if response.length is not None and response.length > RAW_REPLY_LIMIT:
            raise Refused("raw reply exceeds limit")
        raw = response.read(RAW_REPLY_LIMIT + 1)
        if len(raw) > RAW_REPLY_LIMIT or response.length not in (None, 0):
            raise Refused("raw reply oversized or incomplete")
        if credential.encode() in raw:
            raise Refused("response contained sensitive content")
        return raw
    finally:
        connection.close()


def transport_child(mailbox, perform):
    try:
        raw = perform()
        frame = b"+" + raw
    except Refused as exc:
        frame = b"!" + str(exc).encode()
    except Exception:
        frame = b"!transport failed; attempt consumed"
    mailbox.write(frame)
    mailbox.flush()


def supervise(perform, seconds=DEADLINE_SECONDS):
    with TemporaryFile() as mailbox:
        worker = multiprocessing.get_context("fork").Process(
            target=transport_child, args=(mailbox, perform), daemon=True)
        deadline = monotonic() + seconds
        worker.start()
        worker.join(max(0, deadline - monotonic()))
        if worker.is_alive() or monotonic() >= deadline:
            if worker.is_alive():
                worker.kill()
                worker.join(0.25)
            if not worker.is_alive():
                worker.close()
            raise Refused("supervised deadline exceeded; attempt consumed")
        exit_code = worker.exitcode
        worker.close()
        if exit_code != 0:
            raise Refused("transport worker failed; attempt consumed")
        mailbox.seek(0)
        frame = mailbox.read(RAW_REPLY_LIMIT + 2)
    if frame.startswith(b"!"):
        raise Refused(frame[1:].decode("ascii"))
    if not frame.startswith(b"+") or len(frame) > RAW_REPLY_LIMIT + 1:
        raise Refused("transport worker response refused")
    return frame[1:]


@dataclass(frozen=True)
class ResponsesReply:
    response_id: str
    model: str
    draft: Record
    draft_sha256: str
    reply_sha256: str
    input_tokens: int
    output_tokens: int


def parse_reply(raw, model, input_token_limit, output_token_limit, *, draft_parser=None, draft_type=Draft):
    """Check an envelope, leaving an unknown input-token upper bound explicit for offline reviews."""
    try:
        data = decode_json(raw)
        if (data["object"] != "response" or data["status"] != "completed" or data["model"] != model
                or data["service_tier"] != "default" or data["store"] is not False
                or data.get("error") is not None or data.get("incomplete_details") is not None):
            raise ValueError()
        output = data["output"]
        if not isinstance(output, list) or any(item["type"] not in {"reasoning", "message"} for item in output):
            raise ValueError()
        message, = (item for item in output if item["type"] == "message")
        part, = message["content"]
        if (message["role"] != "assistant" or message["status"] != "completed" or part["type"] != "output_text"
                or len(part["text"].encode()) > DRAFT_LIMIT):
            raise ValueError()
        draft_bytes = part["text"].encode()
        usage = data["usage"]
        i, o, total = (usage[name] for name in ("input_tokens", "output_tokens", "total_tokens"))
        if (any(type(n) is not int for n in (i, o, total)) or i < 0
                or (input_token_limit is not None and i > input_token_limit)
                or not 0 <= o <= output_token_limit or total != i + o):
            raise ValueError()
        response_id = data["id"]
        if re.fullmatch(r"resp_[A-Za-z0-9_-]{1,128}", response_id) is None:
            raise ValueError()
        decode_json(draft_bytes)  # Reject duplicate fields before the strict draft parser.
        parser = draft_type.model_validate_json if draft_parser is None else draft_parser
        draft = parser(draft_bytes)
        if type(draft) is not draft_type:
            raise ValueError()
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
        raise Refused("response envelope, draft or usage refused") from None

    return ResponsesReply(response_id, model, draft, sha256(draft_bytes).hexdigest(),
                          sha256(raw).hexdigest(), i, o)


def complete_responses_once(body, *, body_sha256, model, input_token_limit, credential_reader,
                            deadline_seconds=DEADLINE_SECONDS, connection_factory=HTTPSConnection,
                            draft_parser=None, draft_type=Draft, error_body_path=None):
    """Send one approved text-only request; caller owns authorization and replay state.

    The credential supplier runs only inside the supervised child after local
    request checks. The optional parser receives exact draft bytes only after
    envelope validation and returns the exact requested record type. Refusals contain no raw
    provider payload or transport error.
    """
    try:
        if (not 0 < len(body) <= REQUEST_LIMIT or sha256(body).hexdigest() != body_sha256
                or type(input_token_limit) is not int or input_token_limit < 1
                or not 0 < deadline_seconds <= DEADLINE_SECONDS):
            raise ValueError()
        request = decode_json(body)
        output_token_limit = request["max_output_tokens"]
        if (set(request) != REQUEST_FIELDS or not isinstance(model, str) or not model
                or request["model"] != model or request["service_tier"] != "default"
                or request["store"] is not False or request["tools"] != []
                or request["tool_choice"] != "none"
                or not all(isinstance(request[key], str) for key in ("input", "instructions"))
                or type(output_token_limit) is not int or not 1 <= output_token_limit <= OUTPUT_TOKENS
                or request["text"]["format"]["type"] != "json_schema"
                or request["text"]["format"]["strict"] is not True):
            raise ValueError()
    except (KeyError, TypeError, ValueError, RecursionError):
        raise Refused("request bytes or limits outside the adapter contract") from None

    if error_body_path is not None:
        try:
            error_body_path = private_error_path(error_body_path)
        except OSError:
            raise Refused("HTTP diagnostic directory is unavailable") from None

    def perform():
        try:
            credential = credential_reader()
            if not isinstance(credential, str) or re.fullmatch(r"[A-Za-z0-9_-]{16,1024}", credential) is None:
                raise ValueError()
        except Exception:
            raise Refused("credential unavailable or invalid") from None
        return request_once(body, credential, connection_factory, deadline_seconds, error_body_path)

    raw = supervise(perform, seconds=deadline_seconds)
    return parse_reply(raw, model, input_token_limit, output_token_limit, draft_parser=draft_parser, draft_type=draft_type)
