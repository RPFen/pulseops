import {
  pgEnum,
  pgTable,
  uuid,
  varchar,
  text,
  integer,
  boolean,
  timestamp,
  jsonb,
  index,
  uniqueIndex,
} from "drizzle-orm/pg-core";

export const incidentStatusEnum = pgEnum("incident_status", [
  "INGESTED",
  "DEBOUNCED",
  "QUEUED",
  "TRIAGING",
  "QUARANTINED",
  "SCHEMA_LOCK_ABORT",
  "PR_OPENED",
  "RESOLVED",
  "FAILED",
]);

export const sandboxRunStatusEnum = pgEnum("sandbox_run_status", [
  "READY",
  "RUNNING",
  "LEASE_EXPIRED",
  "GREEN",
  "CIRCUIT_BROKEN",
  "TIMED_OUT",
  "ABORTED",
]);

export const circuitBreakerLayerEnum = pgEnum("circuit_breaker_layer", [
  "BASELINE_FLAKE_CHECK",
  "STATE_HASH_LOOP",
  "ITERATION_OR_TTL_CAP",
  "SCHEMA_BOUNDARY_GUARD",
]);

export const draftPrStatusEnum = pgEnum("draft_pr_status", [
  "OPEN_DRAFT",
  "READY_FOR_REVIEW",
  "MERGED",
  "CLOSED",
]);

export const incidents = pgTable(
  "incidents",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    fingerprint: varchar("fingerprint", { length: 64 }).notNull(),
    source: varchar("source", { length: 32 }).notNull().default("sentry"),
    projectId: varchar("project_id", { length: 128 }).notNull(),
    issueId: varchar("issue_id", { length: 128 }).notNull(),
    topStackFrame: text("top_stack_frame").notNull(),
    repository: varchar("repository", { length: 256 }).notNull(),
    baseCommitSha: varchar("base_commit_sha", { length: 64 }).notNull(),
    partnerTenant: varchar("partner_tenant", { length: 64 })
      .notNull()
      .default("ledgerflow"),
    shadowMode: boolean("shadow_mode").notNull().default(true),
    status: incidentStatusEnum("status").notNull().default("INGESTED"),
    burstHitCount: integer("burst_hit_count").notNull().default(1),
    streamMessageId: varchar("stream_message_id", { length: 64 }),
    slackThreadTs: varchar("slack_thread_ts", { length: 64 }),
    rawPayload: jsonb("raw_payload").$type<Record<string, unknown>>().notNull(),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => ({
    fingerprintUniqueIdx: uniqueIndex("incidents_fingerprint_idx").on(
      table.fingerprint
    ),
    statusTenantIdx: index("incidents_status_tenant_idx").on(
      table.status,
      table.partnerTenant
    ),
  })
);

export const sandboxRuns = pgTable(
  "sandbox_runs",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    incidentId: uuid("incident_id")
      .notNull()
      .references(() => incidents.id, { onDelete: "cascade" }),
    jobId: varchar("job_id", { length: 128 }).notNull(),
    containerId: varchar("container_id", { length: 128 }),
    workerId: varchar("worker_id", { length: 128 }).notNull(),
    status: sandboxRunStatusEnum("status").notNull().default("READY"),
    iterationCount: integer("iteration_count").notNull().default(0),
    maxIterations: integer("max_iterations").notNull().default(3),
    ttlSeconds: integer("ttl_seconds").notNull().default(300),
    baselineRunsPassed: integer("baseline_runs_passed").notNull().default(0),
    baselineRunsTotal: integer("baseline_runs_total").notNull().default(3),
    lastStateHash: varchar("last_state_hash", { length: 64 }),
    modifiedSymbols: jsonb("modified_symbols")
      .$type<string[]>()
      .notNull()
      .default([]),
    modifiedFiles: jsonb("modified_files")
      .$type<string[]>()
      .notNull()
      .default([]),
    leaseExpiresAt: timestamp("lease_expires_at", { withTimezone: true }),
    startedAt: timestamp("started_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    finishedAt: timestamp("finished_at", { withTimezone: true }),
  },
  (table) => ({
    jobIdUniqueIdx: uniqueIndex("sandbox_runs_job_id_idx").on(table.jobId),
    incidentStatusIdx: index("sandbox_runs_incident_status_idx").on(
      table.incidentId,
      table.status
    ),
  })
);

export const circuitBreakerEvents = pgTable(
  "circuit_breaker_events",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    sandboxRunId: uuid("sandbox_run_id")
      .notNull()
      .references(() => sandboxRuns.id, { onDelete: "cascade" }),
    incidentId: uuid("incident_id")
      .notNull()
      .references(() => incidents.id, { onDelete: "cascade" }),
    layer: circuitBreakerLayerEnum("layer").notNull(),
    reasonCode: varchar("reason_code", { length: 64 }).notNull(),
    iteration: integer("iteration").notNull().default(0),
    stateHash: varchar("state_hash", { length: 64 }),
    stderrExcerpt: text("stderr_excerpt"),
    metadata: jsonb("metadata")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    triggeredAt: timestamp("triggered_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => ({
    runLayerIdx: index("cb_events_run_layer_idx").on(
      table.sandboxRunId,
      table.layer
    ),
    incidentTriggeredIdx: index("cb_events_incident_triggered_idx").on(
      table.incidentId,
      table.triggeredAt
    ),
  })
);

export const draftPrs = pgTable(
  "draft_prs",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    incidentId: uuid("incident_id")
      .notNull()
      .references(() => incidents.id, { onDelete: "cascade" }),
    sandboxRunId: uuid("sandbox_run_id")
      .notNull()
      .references(() => sandboxRuns.id, { onDelete: "cascade" }),
    repository: varchar("repository", { length: 256 }).notNull(),
    branchName: varchar("branch_name", { length: 256 }).notNull(),
    prNumber: integer("pr_number").notNull(),
    prUrl: text("pr_url").notNull(),
    playbookName: varchar("playbook_name", { length: 128 })
      .notNull()
      .default("!settlement-safe-fix"),
    devinSessionId: varchar("devin_session_id", { length: 128 }).notNull(),
    astBlastRadiusScore: integer("ast_blast_radius_score").notNull().default(0),
    invariantsVerified: boolean("invariants_verified").notNull().default(false),
    schemaGuardPassed: boolean("schema_guard_passed").notNull().default(false),
    status: draftPrStatusEnum("status").notNull().default("OPEN_DRAFT"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => ({
    repoPrUniqueIdx: uniqueIndex("draft_prs_repo_pr_number_idx").on(
      table.repository,
      table.prNumber
    ),
    incidentIdx: index("draft_prs_incident_idx").on(table.incidentId),
  })
);

export type Incident = typeof incidents.$inferSelect;
export type NewIncident = typeof incidents.$inferInsert;
export type SandboxRun = typeof sandboxRuns.$inferSelect;
export type CircuitBreakerEvent = typeof circuitBreakerEvents.$inferSelect;
export type DraftPr = typeof draftPrs.$inferSelect;
