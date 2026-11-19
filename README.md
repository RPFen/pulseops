# PulseOps — Automated Incident Triage & Red-Green Sandbox Runner

PulseOps is an automated GitHub & Slack incident triage and self-healing platform orchestrated by **Devin Bots** on **Devin Max**. It ingests Sentry and Datadog production alerts, reproduces failing stack traces inside ephemeral Docker sandboxes, runs AST blast-radius checks against repository boundaries, and opens guarded draft pull requests only after deterministic red-to-green verification.

## Core Architecture

```
Sentry / Datadog Alerts
        │
        ▼ (HMAC-SHA256 raw-body verification)
FastAPI Webhook Gateway (apps/api/webhooks/sentry.py)
        │
        ├─▶ Redis Lua Atomic Burst Debounce & Semaphore Gate
        │       (burst:lock:{fp}, burst:hits, sandbox:sem, triage:stream)
        │
        ├─▶ Heartbeat Lease Reaper + XAUTOCLAIM (>30s idle recovery)
        │
        ▼
Dramatiq Sandbox Runner (apps/worker/sandbox_runner.py)
        │
        ├─▶ Ephemeral Docker Container + 10s Heartbeat Thread (PX 30000)
        ├─▶ Demuxed Non-Blocking Stream Reader (pytest FD deadlock fix)
        ├─▶ Three-Layer Flaky-Test Circuit Breaker
        ├─▶ AST Blast-Radius & Schema Boundary Verifier
        │
        ▼
Devin Bots (Devin Max) ──▶ Guarded Draft PR + Slack Incident Thread
```

### 1. FastAPI + Redis Lua Atomic Burst Protection & Semaphore Lease Reaper (`XAUTOCLAIM`)

Production incidents frequently trigger cascading webhook storms. `apps/api/webhooks/sentry.py` protects downstream Docker capacity with zero race conditions:

- **Raw-Body Signature Verification**: `verify_sentry_signature()` reads `await request.body()` directly before JSON deserialization, eliminating FastAPI middleware body-consumption mismatches during HMAC-SHA256 validation.
- **Deterministic Incident Fingerprinting**: Alerts are normalized into `sha256(project_id + issue_id + top_stack_frame)` so identical production crashes collapse to a single triage workflow regardless of noisy event IDs.
- **Atomic Burst Debounce & Semaphore Acquisition (`LUA_DEBOUNCE_AND_ENQUEUE`)**: A single Redis Lua script acquires `burst:lock:{fp}` with a 900-second TTL, increments `burst:hits` for storm telemetry, checks active capacity against `sandbox:sem` (`max_sandboxes=4`), and enqueues the payload onto `triage:stream` (`MAXLEN ~ 500`) tagged as `READY` or `QUEUED`.
- **Self-Healing Lease Reaper (`LUA_HEARTBEAT_LEASE_REAPER` + `XAUTOCLAIM`)**: Workers renew `sandbox:lease:{job_id}` (`PX 30000`) every 10 seconds. If a worker is OOM-killed or preempted, the reaper atomically removes expired job IDs from `sandbox:leases`, decrements `sandbox:sem`, and reclaims orphaned stream entries idle for >30 seconds via `XAUTOCLAIM`.

### 2. Three-Layer Flaky-Test Circuit Breaker

To prevent autonomous repair loops from chasing nondeterministic test failures or burning compute on unfixable regressions, `apps/worker/sandbox_runner.py` enforces three independent circuit-breaker layers:

1. **Layer 1 — 3x Baseline Flake Check (`run_baseline_flake_check`)**: Executes the failing reproduction test 3 times against the unmodified base commit with frozen random seeds (`PYTHONHASHSEED=0`, `PULSEOPS_FROZEN_SEED=42`) and mocked external I/O. If the test passes even once on the base commit, the incident is immediately quarantined as `FLAKY_BASELINE` and routed to Slack without invoking Devin Bots.
2. **Layer 2 — State-Hash Loop Detection (`check_state_hash_loop`)**: After every repair attempt, PulseOps hashes the normalized Python AST diff combined with the canonicalized `stderr` stack trace. If the resulting state digest has already been observed in the current run, the breaker trips with `STATE_HASH_LOOP` to stop oscillatory edits.
3. **Layer 3 — Hard Execution & TTL Caps**: Every sandbox run is strictly bounded to `MAX_REPAIR_ITERATIONS = 3` and `CONTAINER_TTL_SECONDS = 300` (5 minutes), backed by a non-blocking demuxed Docker exec stream reader that prevents `pytest` child processes holding open stdout/stderr descriptors from deadlocking container teardown.

### 3. Fintech Design Partner Shadow-Mode Guardrails (LedgerFlow Integration)

PulseOps runs in shadow mode for fintech design partners such as **LedgerFlow**, enforcing hard safety policies codified in [`.devin/playbook.md`](.devin/playbook.md) (`!settlement-safe-fix`):

- **Hard Read-Only Boundaries**: Autonomous agents are strictly blocked from modifying `services/ledger-api/alembic/versions/*`, `packages/db/schema.ts`, or `services/ledger-api/models/ledger_entry.py`. Any required DDL change triggers `SCHEMA_LOCK_ABORT` and pages `@human-dba`.
- **AST Blast-Radius Verification**: Before a draft PR is opened, the worker inspects the AST of every modified Python module and asserts that `git diff --name-only` contains zero `*(alembic|schema|migrations)*` paths.
- **Financial Invariant Enforcement**: Settlement fixes must use `decimal.Decimal` with `ROUND_HALF_EVEN`, preserve double-entry zero-sum invariants (`SUM(debits) - SUM(credits) == Decimal('0.00')`), maintain idempotency keys on `settlement_tx_id`, and pass `pytest services/ledger-api/tests/test_invariants.py -v` before and after patching.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `.devin/playbook.md` | Devin Bot `!settlement-safe-fix` fintech guardrails and verification gate |
| `apps/api/webhooks/sentry.py` | FastAPI Sentry webhook router, raw-body HMAC check, Redis Lua scripts & `XAUTOCLAIM` reaper |
| `apps/worker/sandbox_runner.py` | Dramatiq Docker sandbox runner, lease heartbeat, demuxed stream fix, 3-layer circuit breaker & AST verifier |
| `packages/db/schema.ts` | Drizzle ORM PostgreSQL schema for `incidents`, `sandbox_runs`, `circuit_breaker_events`, and `draft_prs` |
| `docker-compose.yml` | Local development stack (Redis 7 + PostgreSQL 16) |

## Local Development

```bash
# Start Redis 7 and PostgreSQL 16
docker compose up -d

# Install Python & TypeScript dependencies
uv sync
pnpm install

# Run FastAPI webhook gateway
uvicorn apps.api.webhooks.sentry:app --reload --port 8080

# Run Dramatiq sandbox worker
dramatiq apps.worker.sandbox_runner
```
