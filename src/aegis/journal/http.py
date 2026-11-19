"""Transport adapters for independently operated witnesses and cohort archives."""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
import httpx
from pydantic import Field, TypeAdapter, ValidationError

from ..artifact import SignedEvent, StrictModel
from .protocol import (Admission, Entry, Envelope, Hash, Head, Index, JournalBlocked, Leaf,
                       Policy, Proof, SignedHead, Vote, canonical)
from .witness import PAGE_SIZE, choose_cut

PREFIX = "/v1/journal"
MAX_EVENT = 256 * 1024
MAX_PAGE = PAGE_SIZE * (MAX_EVENT + 8192)
envelope_wire = TypeAdapter(Envelope)
entries_wire = TypeAdapter(Annotated[tuple[Entry, ...], Field(max_length=PAGE_SIZE)])
proof_wire = TypeAdapter(Proof)


class Query(StrictModel):
    head: Head
    index: Index
    limit: Annotated[int, Field(strict=True, ge=1, le=PAGE_SIZE)] = PAGE_SIZE


class AppendResult(StrictModel):
    index: Index


class AdmissionVote(StrictModel):
    admission: Admission
    vote: Vote


class RecoveredAdmission(AdmissionVote):
    envelope: Envelope


class CoverageVote(StrictModel):
    signed: SignedHead
    vote: Vote


async def _read(request, validate, limit):
    wire = bytearray()
    async for chunk in request.stream():
        if len(wire) + len(chunk) > limit:
            raise HTTPException(413, "journal request exceeds limit")
        wire.extend(chunk)
    try:
        return validate(wire)
    except ValidationError as exc:
        raise HTTPException(422, "invalid journal wire record") from exc


def _response(value) -> Response:
    return Response(canonical(value), media_type="application/json")


def archive_router(archive, authorize) -> APIRouter:
    """Mount behind authenticated, cohort-restricted access. Authorize runs for every route."""
    router = APIRouter(prefix=PREFIX, dependencies=[Depends(authorize)])

    @router.post("/append")
    async def append(request: Request):
        leaf = await _read(request, Leaf.model_validate_json, MAX_EVENT + 8192)
        try:
            return _response(AppendResult(index=archive.append(leaf)))
        except JournalBlocked as exc:
            raise HTTPException(409, str(exc)) from exc

    @router.post("/consistency")
    async def consistency(request: Request):
        query = await _read(request, Query.model_validate_json, 4096)
        try:
            return _response(archive.consistency(query.index, query.head))
        except (ValueError, JournalBlocked) as exc:
            raise HTTPException(409, "archive cannot serve that consistency proof") from exc

    @router.post("/page")
    async def page(request: Request):
        query = await _read(request, Query.model_validate_json, 4096)
        try:
            entries = archive.page(query.head, query.index, query.limit)
            return _response([entry.model_dump(mode="json") for entry in entries])
        except (ValueError, JournalBlocked) as exc:
            raise HTTPException(409, "archive cannot serve that page") from exc

    return router


def witness_router(witness, archive, authorize) -> APIRouter:
    """Use a locally accessible archive and an authority-specific access dependency."""
    router = APIRouter(prefix=PREFIX, dependencies=[Depends(authorize)])

    @router.post("/admit")
    async def admit(request: Request):
        envelope = await _read(request, envelope_wire.validate_json, MAX_EVENT)
        try:
            admission, vote = witness.admit(envelope)
            return _response(AdmissionVote(admission=admission, vote=vote))
        except JournalBlocked as exc:
            raise HTTPException(409, str(exc)) from exc

    @router.get("/admission/{epoch}/{event}")
    async def admitted(epoch: Annotated[int, Path(ge=0, le=2**31 - 1)], event: Hash):
        record = witness.admitted(event, epoch)
        if record is None:
            raise HTTPException(404, "admission is unavailable")
        envelope, admission, vote = record
        return _response(RecoveredAdmission(admission=admission, vote=vote, envelope=envelope))

    @router.post("/cosign")
    async def cosign(request: Request):
        signed = await _read(request, SignedHead.model_validate_json, 4096)
        try:
            return _response(CoverageVote(signed=signed, vote=witness.cosign(signed, archive)))
        except JournalBlocked as exc:
            raise HTTPException(409, str(exc)) from exc

    @router.get("/head")
    async def head():
        published = witness.published()
        if published is None:
            raise HTTPException(404, "witness has no checkpoint")
        signed, vote = published
        return _response(CoverageVote(signed=signed, vote=vote))

    return router


async def _fetch(client, method, path, validate, limit, body=None):
    async with client.stream(method, PREFIX + path, content=None if body is None else canonical(body),
                             headers={"Content-Type": "application/json"}) as response:
        response.raise_for_status()
        wire = bytearray()
        async for chunk in response.aiter_bytes():
            if len(wire) + len(chunk) > limit:
                raise JournalBlocked("journal response exceeds limit")
            wire.extend(chunk)
        return validate(wire)


class HTTPArchive:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def append(self, leaf: Leaf) -> int:
        result = await _fetch(self.client, "POST", "/append", AppendResult.model_validate_json, 4096, leaf)
        return result.index

    async def consistency(self, before: int, head: Head) -> Proof:
        return await _fetch(self.client, "POST", "/consistency", proof_wire.validate_json, 8192,
                            Query(head=head, index=before))

    async def page(self, head: Head, start: int, limit: int) -> tuple[Entry, ...]:
        return await _fetch(self.client, "POST", "/page", entries_wire.validate_json, MAX_PAGE,
                            Query(head=head, index=start, limit=limit))


class HTTPWitness:
    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def admit(self, envelope: SignedEvent) -> AdmissionVote:
        return await _fetch(self.client, "POST", "/admit", AdmissionVote.model_validate_json, 4096, envelope)

    async def admitted(self, event: str, epoch: int) -> RecoveredAdmission:
        return await _fetch(self.client, "GET", f"/admission/{epoch}/{event}",
                            RecoveredAdmission.model_validate_json, MAX_EVENT + 8192)

    async def cosign(self, signed: SignedHead) -> CoverageVote:
        return await _fetch(self.client, "POST", "/cosign", CoverageVote.model_validate_json, 4096, signed)

    async def head(self) -> CoverageVote:
        return await _fetch(self.client, "GET", "/head", CoverageVote.model_validate_json, 4096)


class HTTPHeads:
    """Poll distinct pinned operators. TLS configuration is provided per client."""

    def __init__(self, policy: Policy, witnesses: dict[str, HTTPWitness]):
        if set(witnesses) - policy.operators.keys():
            raise ValueError("checkpoint source contains an operator outside the roster")
        self.policy, self.witnesses = policy, dict(witnesses)

    async def latest(self):
        results = await asyncio.gather(*(endpoint.head() for endpoint in self.witnesses.values()),
                                       return_exceptions=True)
        return choose_cut(self.policy, (
            (result.signed, result.vote) for operator, result in zip(self.witnesses, results, strict=True)
            if isinstance(result, CoverageVote) and result.vote.operator == operator
        ))
