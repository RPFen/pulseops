"""FastAPI Sentry webhook ingestion with atomic Redis Lua burst debounce and lease reaper."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field
from redis.asyncio import Redis

logger = logging.getLogger("pulseops.api.webhooks.sentry")

SENTRY_WEBHOOK_SECRET = os.getenv("SENTRY_WEBHOOK_SECRET", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

BURST_TTL_SECONDS = int(os.getenv("PULSEOPS_BURST_TTL_SECONDS", "900"))
MAX_SANDBOXES = int(os.getenv("PULSEOPS_MAX_SANDBOXES", "4"))
TRIAGE_STREAM_KEY = "triage:stream"
TRIAGE_CONSUMER_GROUP = "pulseops:triage-workers"
BURST_HITS_KEY = "burst:hits"
SANDBOX_SEM_KEY = "sandbox:sem"
SANDBOX_LEASES_KEY = "sandbox:leases"
REAPER_IDLE_MS = 30_000

LUA_DEBOUNCE_AND_ENQUEUE = """
-- KEYS[1]: burst:lock:{fp}, KEYS[2]: burst:hits, KEYS[3]: sandbox:sem, KEYS[4]: triage:stream
-- ARGV[1]: fp, ARGV[2]: ttl(900), ARGV[3]: max_sandboxes(4), ARGV[4]: payload
local locked = redis.call('SET', KEYS[1], '1', 'NX', 'EX', tonumber(ARGV[2]))
local hits = redis.call('HINCRBY', KEYS[2], ARGV[1], 1)
if not locked then
  return {0, hits} -- duplicate burst dropped in O(1)
end
local active = tonumber(redis.call('GET', KEYS[3]) or '0')
local status = (active < tonumber(ARGV[3])) and 'READY' or 'QUEUED'
if status == 'READY' then redis.call('INCR', KEYS[3]) end
local msg_id = redis.call('XADD', KEYS[4], 'MAXLEN', '~', 500, '*', 'fp', ARGV[1], 'state', status, 'data', ARGV[4])
return {1, hits, status, msg_id}
""".strip()

LUA_HEARTBEAT_LEASE_REAPER = """
-- KEYS[1]: sandbox:leases, KEYS[2]: sandbox:sem
local jobs = redis.call('SMEMBERS', KEYS[1])
local reaped = 0
for _, job_id in ipairs(jobs) do
  if redis.call('EXISTS', 'sandbox:lease:' .. job_id) == 0 then
    redis.call('SREM', KEYS[1], job_id)
    local cur = tonumber(redis.call('GET', KEYS[2]) or '0')
    if cur > 0 then redis.call('DECR', KEYS[2]) end
    reaped = reaped + 1
  end
end
return reaped
""".strip()


@dataclass(frozen=True, slots=True)
class ReapReport:
    reaped_leases: int
    reclaimed_stream_ids: list[str]
    next_start_id: str


class WebhookIngestResponse(BaseModel):
    accepted: bool
    fingerprint: str
    burst_hits: int
    dispatch_state: str = Field(description="DROPPED_DUPLICATE, READY, or QUEUED")
    stream_message_id: str | None = None


class LeaseReaperResponse(BaseModel):
    reaped_leases: int
    reclaimed_count: int
    reclaimed_stream_ids: list[str]
    next_start_id: str


_redis_client: Redis | None = None


async def get_redis() -> Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = Redis.from_url(REDIS_URL, decode_responses=True)
    return _redis_client


async def verify_sentry_signature(request: Request) -> bytes:
    """Validate Sentry HMAC-SHA256 signature against raw request bytes before JSON parsing.

    Reading ``await request.body()`` directly avoids FastAPI dependency/middleware
    body-consumption bugs where re-serialized JSON alters key order or whitespace and
    breaks cryptographic digest verification.
    """
    if not SENTRY_WEBHOOK_SECRET:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SENTRY_WEBHOOK_SECRET is not configured",
        )

    raw_body: bytes = await request.body()
    provided_sig = request.headers.get("sentry-hook-signature", "").strip()
    if not provided_sig:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Sentry-Hook-Signature header",
        )

    expected_sig = hmac.new(
        key=SENTRY_WEBHOOK_SECRET.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Sentry-Hook-Signature HMAC-SHA256 digest",
        )

    return raw_body


def extract_top_stack_frame(payload: dict[str, Any]) -> str:
    """Extract the most specific in-app frame (or topmost frame) from a Sentry alert payload."""
    data = payload.get("data") or {}
    event = data.get("event") or data.get("issue") or {}

    exception_values = (event.get("exception") or {}).get("values") or []
    for exc in reversed(exception_values):
        frames = (exc.get("stacktrace") or {}).get("frames") or []
        in_app_frames = [frame for frame in frames if frame.get("in_app")]
        candidate_frames = in_app_frames or frames
        if candidate_frames:
            top = candidate_frames[-1]
            filename = top.get("filename") or top.get("abs_path") or "unknown"
            function = top.get("function") or "<module>"
            lineno = top.get("lineno") or 0
            return f"{filename}:{function}:{lineno}"

    metadata = event.get("metadata") or {}
    filename = metadata.get("filename") or "unknown"
    function = metadata.get("function") or event.get("culprit") or "unknown"
    return f"{filename}:{function}:0"


def compute_incident_fingerprint(
    project_id: str, issue_id: str, top_stack_frame: str
) -> str:
    """Compute deterministic sha256(project_id + issue_id + top_stack_frame)."""
    material = f"{project_id}{issue_id}{top_stack_frame}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


async def ensure_consumer_group(redis_client: Redis) -> None:
    """Ensure the triage stream consumer group exists before XAUTOCLAIM runs."""
    try:
        await redis_client.xgroup_create(
            name=TRIAGE_STREAM_KEY,
            groupname=TRIAGE_CONSUMER_GROUP,
            id="0-0",
            mkstream=True,
        )
    except Exception as exc:  # noqa: BLE001
        if "BUSYGROUP" not in str(exc):
            raise


async def reap_expired_leases_and_claim_orphans(
    redis_client: Redis,
    consumer_name: str = "pulseops-reaper",
    min_idle_ms: int = REAPER_IDLE_MS,
    count: int = 25,
) -> ReapReport:
    """Atomically reap expired sandbox leases and reclaim stream messages idle > 30s."""
    await ensure_consumer_group(redis_client)

    reaped_leases = int(
        await redis_client.eval(
            LUA_HEARTBEAT_LEASE_REAPER,
            2,
            SANDBOX_LEASES_KEY,
            SANDBOX_SEM_KEY,
        )
    )

    next_start_id, claimed_entries, *_ = await redis_client.xautoclaim(
        name=TRIAGE_STREAM_KEY,
        groupname=TRIAGE_CONSUMER_GROUP,
        consumername=consumer_name,
        min_idle_time=min_idle_ms,
        start_id="0-0",
        count=count,
    )
    reclaimed_ids = [entry_id for entry_id, _fields in claimed_entries]

    if reaped_leases or reclaimed_ids:
        logger.warning(
            "Reaped %d expired sandbox leases and reclaimed %d idle stream entries",
            reaped_leases,
            len(reclaimed_ids),
        )

    return ReapReport(
        reaped_leases=reaped_leases,
        reclaimed_stream_ids=reclaimed_ids,
        next_start_id=str(next_start_id),
    )


router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post(
    "/sentry",
    response_model=WebhookIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_sentry_webhook(
    raw_body: bytes = Depends(verify_sentry_signature),
    redis_client: Redis = Depends(get_redis),
) -> WebhookIngestResponse:
    """Verify Sentry webhook, deduplicate bursts atomically in Redis, and enqueue triage."""
    try:
        payload: dict[str, Any] = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed JSON payload: {exc}",
        ) from exc

    data = payload.get("data") or {}
    issue = data.get("issue") or {}
    event = data.get("event") or {}
    project = issue.get("project") or {}

    project_id = str(
        project.get("id")
        or event.get("project")
        or payload.get("project_id")
        or "unknown-project"
    )
    issue_id = str(
        issue.get("id")
        or event.get("issue_id")
        or payload.get("issue_id")
        or "unknown-issue"
    )
    top_stack_frame = extract_top_stack_frame(payload)
    fingerprint = compute_incident_fingerprint(project_id, issue_id, top_stack_frame)

    normalized_envelope = json.dumps(
        {
            "fingerprint": fingerprint,
            "project_id": project_id,
            "issue_id": issue_id,
            "top_stack_frame": top_stack_frame,
            "action": payload.get("action", "triggered"),
            "repository": payload.get("repository")
            or (project.get("slug") or "ledgerflow/ledger-api"),
            "base_commit": event.get("release") or "HEAD",
            "title": issue.get("title") or event.get("title") or "Production exception",
        },
        separators=(",", ":"),
        sort_keys=True,
    )

    result = await redis_client.eval(
        LUA_DEBOUNCE_AND_ENQUEUE,
        4,
        f"burst:lock:{fingerprint}",
        BURST_HITS_KEY,
        SANDBOX_SEM_KEY,
        TRIAGE_STREAM_KEY,
        fingerprint,
        str(BURST_TTL_SECONDS),
        str(MAX_SANDBOXES),
        normalized_envelope,
    )

    accepted = int(result[0]) == 1
    burst_hits = int(result[1])

    if not accepted:
        return WebhookIngestResponse(
            accepted=False,
            fingerprint=fingerprint,
            burst_hits=burst_hits,
            dispatch_state="DROPPED_DUPLICATE",
            stream_message_id=None,
        )

    dispatch_state = str(result[2])
    stream_message_id = str(result[3])

    return WebhookIngestResponse(
        accepted=True,
        fingerprint=fingerprint,
        burst_hits=burst_hits,
        dispatch_state=dispatch_state,
        stream_message_id=stream_message_id,
    )


@router.post("/reap-leases", response_model=LeaseReaperResponse)
async def trigger_lease_reaper(
    redis_client: Redis = Depends(get_redis),
) -> LeaseReaperResponse:
    """Trigger the heartbeat lease reaper and XAUTOCLAIM sweep for orphaned triage jobs."""
    report = await reap_expired_leases_and_claim_orphans(redis_client)
    return LeaseReaperResponse(
        reaped_leases=report.reaped_leases,
        reclaimed_count=len(report.reclaimed_stream_ids),
        reclaimed_stream_ids=report.reclaimed_stream_ids,
        next_start_id=report.next_start_id,
    )


app = FastAPI(
    title="PulseOps Webhook Gateway",
    version="0.4.2",
    description="Automated Sentry incident ingestion with Redis Lua burst protection",
)
app.include_router(router)
