"""Dramatiq + Redis ephemeral Docker sandbox runner with 3-layer flaky-test circuit breaker."""

from __future__ import annotations

import ast
import hashlib
import logging
import os
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import docker
import dramatiq
import httpx
from docker.models.containers import Container
from docker.utils.socket import frames_iter_no_tty
from dramatiq.brokers.redis import RedisBroker
from redis import Redis

logger = logging.getLogger("pulseops.worker.sandbox_runner")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DEVIN_API_URL = os.getenv("DEVIN_MAX_API_URL", "https://api.devin.ai/v1/sessions")
DEVIN_API_KEY = os.getenv("DEVIN_API_KEY", "")
SANDBOX_IMAGE = os.getenv("PULSEOPS_SANDBOX_IMAGE", "pulseops/ledger-sandbox:py311")

HEARTBEAT_INTERVAL_SECONDS = 10
LEASE_TTL_MS = 30_000
MAX_REPAIR_ITERATIONS = 3
CONTAINER_TTL_SECONDS = 300
BASELINE_FLAKE_RUNS = 3
EXEC_SOCKET_TIMEOUT_SECONDS = 5.0

SANDBOX_LEASES_KEY = "sandbox:leases"
SANDBOX_SEM_KEY = "sandbox:sem"

PROTECTED_SCHEMA_PATTERNS = (
    re.compile(r"^services/ledger-api/alembic/versions/.*"),
    re.compile(r"^packages/db/schema\.ts$"),
    re.compile(r"^services/ledger-api/models/ledger_entry\.py$"),
    re.compile(r".*(alembic|schema|migrations).*"),
)

redis_broker = RedisBroker(url=REDIS_URL)
dramatiq.set_broker(redis_broker)


@dataclass(frozen=True, slots=True)
class ExecOutcome:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass(slots=True)
class BlastRadiusReport:
    modified_files: list[str]
    modified_symbols: list[str]
    schema_violations: list[str]
    blast_radius_score: int

    @property
    def is_schema_safe(self) -> bool:
        return len(self.schema_violations) == 0


@dataclass(slots=True)
class SandboxTriageResult:
    job_id: str
    status: str
    reason_code: str
    iterations_used: int
    state_hashes: list[str] = field(default_factory=list)
    blast_radius: BlastRadiusReport | None = None
    draft_pr_url: str | None = None


class LeaseHeartbeatThread(threading.Thread):
    """Background daemon refreshing ``sandbox:lease:{job_id}`` (PX 30000) every 10 seconds."""

    def __init__(self, redis_client: Redis, job_id: str) -> None:
        super().__init__(name=f"lease-heartbeat-{job_id}", daemon=True)
        self._redis = redis_client
        self._job_id = job_id
        self._lease_key = f"sandbox:lease:{job_id}"
        self._stop_event = threading.Event()

    def register(self) -> None:
        pipe = self._redis.pipeline(transaction=True)
        pipe.sadd(SANDBOX_LEASES_KEY, self._job_id)
        pipe.set(self._lease_key, "1", px=LEASE_TTL_MS)
        pipe.execute()

    def run(self) -> None:
        while not self._stop_event.wait(HEARTBEAT_INTERVAL_SECONDS):
            try:
                self._redis.set(self._lease_key, "1", px=LEASE_TTL_MS)
            except Exception:  # noqa: BLE001
                logger.exception("Failed to refresh sandbox lease for job %s", self._job_id)

    def stop_and_release(self) -> None:
        self._stop_event.set()
        if self.is_alive():
            self.join(timeout=2.0)
        pipe = self._redis.pipeline(transaction=True)
        pipe.delete(self._lease_key)
        pipe.srem(SANDBOX_LEASES_KEY, self._job_id)
        pipe.execute()


def run_demuxed_exec(
    container: Container,
    command: str,
    env: dict[str, str] | None = None,
    timeout_seconds: int = 90,
) -> ExecOutcome:
    """Run a container command with demuxed stdout/stderr without pytest FD deadlocks.

    ``docker-py`` ``exec_run(stream=True, demux=True)`` can hang indefinitely when a
    ``pytest`` worker spawns a background subprocess that inherits open stdout/stderr
    descriptors. Wrapping the command to close inherited child FDs (``exec 3>&- 4>&-``),
    forcing non-blocking socket timeouts on the hijacked exec socket, and inspecting
    exec completion prevents stream deadlocks.
    """
    api = container.client.api
    wrapped_cmd = [
        "/bin/bash",
        "-lc",
        f"set -o pipefail; ({command}) < /dev/null 3>&- 4>&-",
    ]
    exec_handle = api.exec_create(
        container.id,
        wrapped_cmd,
        stdout=True,
        stderr=True,
        tty=False,
        environment=env or {},
    )
    exec_id: str = exec_handle["Id"]
    raw_sock = api.exec_start(exec_id, detach=False, tty=False, stream=False, socket=True)

    # Demuxed stream reader fix for docker-py exec_run(stream=True, demux=True):
    # enforce a non-blocking socket timeout and explicitly close child stdout/stderr
    # descriptors once the deadline expires or exec completes so pytest never deadlocks.
    underlying_sock = getattr(raw_sock, "_sock", raw_sock)
    underlying_sock.settimeout(EXEC_SOCKET_TIMEOUT_SECONDS)

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    deadline = time.monotonic() + timeout_seconds
    timed_out = False

    try:
        frame_stream = frames_iter_no_tty(raw_sock)
        while True:
            if time.monotonic() >= deadline:
                timed_out = True
                break
            try:
                stream_id, chunk = next(frame_stream)
            except StopIteration:
                break
            except (TimeoutError, socket.timeout):
                inspection = api.exec_inspect(exec_id)
                if not inspection.get("Running", False):
                    break
                continue

            if stream_id == 1:
                stdout_chunks.append(chunk)
            elif stream_id == 2:
                stderr_chunks.append(chunk)
    finally:
        try:
            underlying_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        raw_sock.close()

    if timed_out:
        container.exec_run(["pkill", "-9", "-f", "pytest"], detach=True)
        exit_code = 124
    else:
        exit_code = int(api.exec_inspect(exec_id).get("ExitCode", 1))

    return ExecOutcome(
        exit_code=exit_code,
        stdout=b"".join(stdout_chunks).decode("utf-8", errors="replace"),
        stderr=b"".join(stderr_chunks).decode("utf-8", errors="replace"),
        timed_out=timed_out,
    )


def _canonicalize_ast_module(source: str) -> str:
    """Return a deterministic AST dump ignoring formatting/comment-only churn."""
    try:
        tree = ast.parse(source)
        return ast.dump(tree, annotate_fields=True, include_attributes=False)
    except SyntaxError:
        return source.strip()


def _extract_python_symbols(source: str) -> dict[str, str]:
    """Map qualified class/function symbol names to their normalized AST dumps."""
    symbols: dict[str, str] = {}
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return symbols

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbols[node.name] = ast.dump(node, include_attributes=False)
    return symbols


def analyze_ast_blast_radius(
    modified_files: list[str],
    before_sources: dict[str, str],
    after_sources: dict[str, str],
) -> BlastRadiusReport:
    """Inspect modified Python symbols via ``ast`` and assert zero schema/migration edits."""
    schema_violations = [
        path
        for path in modified_files
        if any(pattern.match(path) for pattern in PROTECTED_SCHEMA_PATTERNS)
    ]

    modified_symbols: list[str] = []
    for rel_path in sorted(modified_files):
        if not rel_path.endswith(".py"):
            continue
        before_syms = _extract_python_symbols(before_sources.get(rel_path, ""))
        after_syms = _extract_python_symbols(after_sources.get(rel_path, ""))
        changed_names = sorted(
            name
            for name in (set(before_syms) | set(after_syms))
            if before_syms.get(name) != after_syms.get(name)
        )
        for sym in changed_names:
            modified_symbols.append(f"{rel_path}::{sym}")

    blast_radius_score = len(modified_files) * 10 + len(modified_symbols) * 5
    return BlastRadiusReport(
        modified_files=sorted(modified_files),
        modified_symbols=modified_symbols,
        schema_violations=sorted(schema_violations),
        blast_radius_score=blast_radius_score,
    )


def _normalize_stderr_stack_trace(stderr: str) -> str:
    """Strip ephemeral timestamps, memory addresses, and temp paths before hashing."""
    cleaned = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", stderr)
    cleaned = re.sub(r"/tmp/[a-zA-Z0-9_.-]+", "/tmp/TEMP", cleaned)
    cleaned = re.sub(r"\d+\.\d+s", "0.00s", cleaned)
    lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
    return "\n".join(lines[-40:])


class ThreeLayerCircuitBreaker:
    """Three-layer flaky-test and repair-loop circuit breaker."""

    def __init__(
        self,
        max_iterations: int = MAX_REPAIR_ITERATIONS,
        container_ttl_seconds: int = CONTAINER_TTL_SECONDS,
    ) -> None:
        self.max_iterations = max_iterations
        self.container_ttl_seconds = container_ttl_seconds
        self._started_at = time.monotonic()
        self._seen_state_hashes: set[str] = set()
        self.recorded_hashes: list[str] = []

    def run_baseline_flake_check(
        self,
        container: Container,
        test_command: str,
    ) -> tuple[bool, ExecOutcome]:
        """Layer 1: Run failing test 3x against unmodified base commit with frozen seeds.

        Returns ``(is_deterministic_failure, last_outcome)``. If the test passes even once
        with frozen seeds and mocked external I/O, it is quarantined immediately.
        """
        deterministic_env = {
            "PYTHONHASHSEED": "0",
            "PULSEOPS_FROZEN_SEED": "42",
            "PULSEOPS_MOCK_EXTERNAL_IO": "1",
            "TZ": "UTC",
        }
        last_outcome = ExecOutcome(exit_code=1, stdout="", stderr="")
        for attempt in range(1, BASELINE_FLAKE_RUNS + 1):
            last_outcome = run_demuxed_exec(
                container,
                test_command,
                env=deterministic_env,
                timeout_seconds=60,
            )
            if last_outcome.exit_code == 0:
                logger.warning(
                    "Layer 1 breaker tripped: baseline test passed on attempt %d/%d",
                    attempt,
                    BASELINE_FLAKE_RUNS,
                )
                return False, last_outcome
        return True, last_outcome

    def check_state_hash_loop(
        self,
        ast_diff_payload: str,
        stderr_stack_trace: str,
    ) -> tuple[bool, str]:
        """Layer 2: Hash ``AST_diff + stderr_stack_trace`` and trip on duplicate signature."""
        normalized_stderr = _normalize_stderr_stack_trace(stderr_stack_trace)
        digest = hashlib.sha256(
            f"{ast_diff_payload}\n---\n{normalized_stderr}".encode("utf-8")
        ).hexdigest()
        self.recorded_hashes.append(digest)

        if digest in self._seen_state_hashes:
            logger.warning("Layer 2 breaker tripped: duplicate state hash %s", digest)
            return True, digest

        self._seen_state_hashes.add(digest)
        return False, digest

    def is_budget_exhausted(self, iteration: int) -> tuple[bool, str]:
        """Layer 3: Enforce hard cap of MAX_REPAIR_ITERATIONS=3 and CONTAINER_TTL_SECONDS=300."""
        elapsed = time.monotonic() - self._started_at
        if elapsed >= self.container_ttl_seconds:
            return True, "CONTAINER_TTL_EXCEEDED"
        if iteration >= self.max_iterations:
            return True, "MAX_REPAIR_ITERATIONS_REACHED"
        return False, ""


def _read_container_file(container: Container, rel_path: str) -> str:
    outcome = run_demuxed_exec(container, f"cat -- '{rel_path}'", timeout_seconds=15)
    return outcome.stdout if outcome.exit_code == 0 else ""


def _list_git_modified_files(container: Container) -> list[str]:
    outcome = run_demuxed_exec(container, "git diff --name-only HEAD", timeout_seconds=15)
    if outcome.exit_code != 0:
        return []
    return [line.strip() for line in outcome.stdout.splitlines() if line.strip()]


def _build_ast_diff_signature(
    container: Container,
    modified_files: list[str],
    before_sources: dict[str, str],
) -> tuple[str, dict[str, str]]:
    after_sources: dict[str, str] = {}
    parts: list[str] = []
    for path in sorted(modified_files):
        after_src = _read_container_file(container, path)
        after_sources[path] = after_src
        if path.endswith(".py"):
            before_ast = _canonicalize_ast_module(before_sources.get(path, ""))
            after_ast = _canonicalize_ast_module(after_src)
            parts.append(f"{path}:{before_ast}=>{after_ast}")
        else:
            parts.append(f"{path}:{hashlib.sha256(after_src.encode('utf-8')).hexdigest()}")
    return "\n".join(parts), after_sources


def dispatch_devin_bot_patch(
    job_id: str,
    repository: str,
    stderr_trace: str,
    iteration: int,
    playbook_path: Path = Path(".devin/playbook.md"),
) -> str:
    """Invoke a Devin Bot sub-agent on Devin Max to synthesize a candidate unified diff."""
    playbook_text = playbook_path.read_text(encoding="utf-8") if playbook_path.exists() else ""
    if not DEVIN_API_KEY:
        raise RuntimeError(
            f"DEVIN_API_KEY must be configured to dispatch Devin Bot session for job {job_id}"
        )

    payload = {
        "prompt": (
            f"Apply !settlement-safe-fix for repository {repository} (iteration {iteration}).\n"
            f"Reproduced stderr stack trace:\n{stderr_trace}\n\n"
            f"Playbook constraints:\n{playbook_text}"
        ),
        "idempotent": True,
        "tags": ["pulseops", "devin-max", f"job:{job_id}", f"iter:{iteration}"],
    }
    response = httpx.post(
        DEVIN_API_URL,
        headers={
            "Authorization": f"Bearer {DEVIN_API_KEY}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=45.0,
    )
    response.raise_for_status()
    data: dict[str, Any] = response.json()
    return str(data.get("patch_diff", ""))


def _release_semaphore_slot(redis_client: Redis) -> None:
    current = int(redis_client.get(SANDBOX_SEM_KEY) or 0)
    if current > 0:
        redis_client.decr(SANDBOX_SEM_KEY)


@dramatiq.actor(max_retries=0, time_limit=CONTAINER_TTL_SECONDS * 1000)
def run_incident_sandbox(
    job_id: str,
    repository: str,
    base_commit: str,
    test_command: str,
    invariant_command: str = "pytest services/ledger-api/tests/test_invariants.py -v",
) -> dict[str, Any]:
    """Execute full red-green incident reproduction and guarded Devin Bot patch workflow."""
    redis_client = Redis.from_url(REDIS_URL, decode_responses=True)
    docker_client = docker.from_env()
    heartbeat = LeaseHeartbeatThread(redis_client=redis_client, job_id=job_id)
    breaker = ThreeLayerCircuitBreaker(
        max_iterations=MAX_REPAIR_ITERATIONS,
        container_ttl_seconds=CONTAINER_TTL_SECONDS,
    )
    container: Container | None = None

    heartbeat.register()
    heartbeat.start()

    try:
        container = docker_client.containers.run(
            image=SANDBOX_IMAGE,
            command=["sleep", str(CONTAINER_TTL_SECONDS + 30)],
            detach=True,
            auto_remove=False,
            network_disabled=True,
            mem_limit="2g",
            cpu_quota=100_000,
            labels={"pulseops.job_id": job_id, "pulseops.repo": repository},
        )

        checkout = run_demuxed_exec(
            container,
            f"git checkout --force '{base_commit}'",
            timeout_seconds=30,
        )
        if checkout.exit_code != 0:
            return SandboxTriageResult(
                job_id=job_id,
                status="ABORTED",
                reason_code="BASE_COMMIT_CHECKOUT_FAILED",
                iterations_used=0,
            ).__dict__

        # Layer 1: 3x baseline flake check on unmodified base commit
        deterministic_failure, baseline_outcome = breaker.run_baseline_flake_check(
            container, test_command
        )
        if not deterministic_failure:
            return SandboxTriageResult(
                job_id=job_id,
                status="QUARANTINED",
                reason_code="FLAKY_BASELINE",
                iterations_used=0,
            ).__dict__

        # Pre-patch financial invariant baseline gate
        pre_invariants = run_demuxed_exec(container, invariant_command, timeout_seconds=90)
        if pre_invariants.exit_code != 0:
            return SandboxTriageResult(
                job_id=job_id,
                status="ABORTED",
                reason_code="PRE_PATCH_INVARIANTS_FAILED",
                iterations_used=0,
            ).__dict__

        before_sources: dict[str, str] = {}
        last_stderr = baseline_outcome.stderr

        for iteration in range(1, MAX_REPAIR_ITERATIONS + 1):
            exhausted, budget_reason = breaker.is_budget_exhausted(iteration - 1)
            if exhausted:
                return SandboxTriageResult(
                    job_id=job_id,
                    status="CIRCUIT_BROKEN",
                    reason_code=budget_reason,
                    iterations_used=iteration - 1,
                    state_hashes=breaker.recorded_hashes,
                ).__dict__

            patch_diff = dispatch_devin_bot_patch(
                job_id=job_id,
                repository=repository,
                stderr_trace=last_stderr,
                iteration=iteration,
            )
            if not patch_diff.strip():
                return SandboxTriageResult(
                    job_id=job_id,
                    status="CIRCUIT_BROKEN",
                    reason_code="EMPTY_DEVIN_PATCH",
                    iterations_used=iteration,
                    state_hashes=breaker.recorded_hashes,
                ).__dict__

            # Snapshot pre-patch files prior to applying candidate diff
            apply_check = run_demuxed_exec(
                container,
                f"git apply --stat <<'PATCH'\n{patch_diff}\nPATCH",
                timeout_seconds=15,
            )
            if apply_check.exit_code == 0:
                for line in apply_check.stdout.splitlines():
                    if "|" in line:
                        candidate_path = line.split("|", 1)[0].strip()
                        if candidate_path not in before_sources:
                            before_sources[candidate_path] = _read_container_file(
                                container, candidate_path
                            )

            apply_outcome = run_demuxed_exec(
                container,
                f"git apply --whitespace=nowarn <<'PATCH'\n{patch_diff}\nPATCH",
                timeout_seconds=20,
            )
            if apply_outcome.exit_code != 0:
                last_stderr = apply_outcome.stderr
                looped, _ = breaker.check_state_hash_loop("APPLY_FAILED", last_stderr)
                if looped:
                    return SandboxTriageResult(
                        job_id=job_id,
                        status="CIRCUIT_BROKEN",
                        reason_code="STATE_HASH_LOOP",
                        iterations_used=iteration,
                        state_hashes=breaker.recorded_hashes,
                    ).__dict__
                continue

            modified_files = _list_git_modified_files(container)
            ast_diff_sig, after_sources = _build_ast_diff_signature(
                container, modified_files, before_sources
            )
            blast_report = analyze_ast_blast_radius(
                modified_files=modified_files,
                before_sources=before_sources,
                after_sources=after_sources,
            )
            if not blast_report.is_schema_safe:
                run_demuxed_exec(container, "git checkout -- .", timeout_seconds=15)
                return SandboxTriageResult(
                    job_id=job_id,
                    status="ABORTED",
                    reason_code="SCHEMA_LOCK_ABORT",
                    iterations_used=iteration,
                    state_hashes=breaker.recorded_hashes,
                    blast_radius=blast_report,
                ).__dict__

            verify_repro = run_demuxed_exec(container, test_command, timeout_seconds=90)
            verify_invariants = run_demuxed_exec(
                container, invariant_command, timeout_seconds=90
            )
            if verify_repro.exit_code == 0 and verify_invariants.exit_code == 0:
                return SandboxTriageResult(
                    job_id=job_id,
                    status="GREEN",
                    reason_code="VERIFIED_RED_TO_GREEN",
                    iterations_used=iteration,
                    state_hashes=breaker.recorded_hashes,
                    blast_radius=blast_report,
                    draft_pr_url=f"https://github.com/{repository}/pull/draft-{job_id}",
                ).__dict__

            last_stderr = verify_repro.stderr or verify_invariants.stderr
            looped, _ = breaker.check_state_hash_loop(ast_diff_sig, last_stderr)
            if looped:
                return SandboxTriageResult(
                    job_id=job_id,
                    status="CIRCUIT_BROKEN",
                    reason_code="STATE_HASH_LOOP",
                    iterations_used=iteration,
                    state_hashes=breaker.recorded_hashes,
                    blast_radius=blast_report,
                ).__dict__

        return SandboxTriageResult(
            job_id=job_id,
            status="CIRCUIT_BROKEN",
            reason_code="MAX_REPAIR_ITERATIONS_REACHED",
            iterations_used=MAX_REPAIR_ITERATIONS,
            state_hashes=breaker.recorded_hashes,
        ).__dict__
    finally:
        heartbeat.stop_and_release()
        _release_semaphore_slot(redis_client)
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:  # noqa: BLE001
                logger.exception("Failed to remove ephemeral sandbox container %s", container.id)
