# Playbook: Fintech Hotfix & Schema Guardrails (!settlement-safe-fix)

This playbook governs all **Devin Bot** triage and hotfix sessions triggered by PulseOps for fintech production repositories (including **LedgerFlow** shadow-mode and live settlement pipelines). Every rule below is mandatory and audited automatically by `apps/worker/sandbox_runner.py` before a draft pull request may be created.

---

## 1. Hard Read-Only Boundaries

Devin Bots operating under `!settlement-safe-fix` **MUST NEVER** create, modify, rename, or delete any file matching the following protected paths:

- `services/ledger-api/alembic/versions/*`
- `packages/db/schema.ts`
- `services/ledger-api/models/ledger_entry.py`

### Mandatory Abort Protocol

If root-cause analysis shows that resolving the incident requires a database schema migration, column type change, index alteration, or ORM table definition update:

1. **STOP immediately** and revert any tentative local edits.
2. Emit the structured abort code **`SCHEMA_LOCK_ABORT`** in the incident triage summary and worker telemetry payload.
3. Post the root-cause findings and proposed SQL/migration sketch to the incident Slack thread and explicitly tag **`@human-dba`** for manual review and execution.
4. Do **NOT** open a draft pull request.

---

## 2. Financial Invariants & Precision Rules

All code changes touching monetary amounts, fee calculations, FX conversions, reconciliation jobs, or ledger postings must adhere strictly to the following invariants:

1. **Exact Decimal Arithmetic Only**:
   - Always use Python `decimal.Decimal` quantized explicitly with `ROUND_HALF_EVEN` (banker's rounding).
   - Never introduce binary floating-point types (`float`, `numpy.float64`, implicit float division `/`) into monetary calculations or serialization paths.
2. **Double-Entry Zero-Sum Invariant**:
   - Every ledger posting batch and settlement transaction must strictly preserve the double-entry accounting invariant:
     ```python
     SUM(debits) - SUM(credits) == Decimal('0.00')
     ```
   - Patches must never suppress, defer, or bypass balance assertions in service or repository layers.
3. **Settlement Idempotency Keys**:
   - Every mutation path handling clearing, capture, refund, or payout execution must enforce a deterministic idempotency key bound to `settlement_tx_id`.
   - Retried webhook deliveries or worker replays sharing the same `settlement_tx_id` must return the previously committed ledger outcome without inserting duplicate postings.

---

## 3. Sandbox Verification Gate

Before opening a guarded draft PR via **Devin Bots** on **Devin Max**, the sandbox runner must pass every verification gate in sequence:

1. **Pre-Patch Invariant Baseline**:
   - Run the financial invariant suite prior to applying any candidate patch:
     ```bash
     pytest services/ledger-api/tests/test_invariants.py -v
     ```
2. **Post-Patch Red-to-Green & Invariant Verification**:
   - Confirm the targeted reproduction test transitions cleanly from red (failing on unmodified base commit across 3 deterministic baseline runs) to green after patching.
   - Re-run the full ledger invariant suite after patching and confirm zero regressions:
     ```bash
     pytest services/ledger-api/tests/test_invariants.py -v
     ```
3. **Protected Path Diff Assertion**:
   - Inspect `git diff --name-only` against the base branch and assert that **zero** modified or untracked files match `*(alembic|schema|migrations)*`:
     ```bash
     git diff --name-only | grep -E '(alembic|schema|migrations)' && exit 1 || true
     ```
   - Any match aborts PR creation with `SCHEMA_LOCK_ABORT` and notifies `@human-dba`.
