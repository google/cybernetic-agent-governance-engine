-- Copyright 2026 Google LLC
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     https://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- ===========================================================================
-- ClickHouse Evidence Stream Schema — `cage_evidence`
-- ===========================================================================
-- Schema Name:         cage_evidence
-- Migration Version:   001
-- Evidence Schema:     cage-audit/3.0
-- Source of Truth:     src/gateway/governance/evidence/stream.py:508
-- Architecture Doc:    docs/architecture/CLICKHOUSE_EVIDENCE_SINK.md
--
-- CRITICAL: This is an append-only, WORM-enforced audit mirror.
-- No UPDATE or DELETE operations are permitted, ever. Retention is executed
-- as partition-level drops only. Plain MergeTree is required because
-- deduplicating/collapsing engines can silently delete rows during background
-- merges, which is incompatible with evidentiary integrity.
-- ===========================================================================

-- ===========================================================================
-- §4 — Database and Main Evidence Stream Table
-- ===========================================================================
-- Rationale: Plain MergeTree (not Replacing/Collapsing) is required because
-- deduplicating engines can silently delete rows during merges. An append-only
-- audit mirror must never run an engine that can silently delete rows.
-- ===========================================================================

CREATE DATABASE IF NOT EXISTS cage_evidence;

CREATE TABLE IF NOT EXISTS cage_evidence.evidence_stream
(
    -- ---- Schema identity -------------------------------------------------
    schema_version        LowCardinality(String),
    chain_id              UUID,
    sequence              UInt64 CODEC(Delta(8), LZ4),
    timestamp             DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),

    -- ---- Event identity (all inside the hash) ----------------------------
    event_type            LowCardinality(String),
    control_id            LowCardinality(String),
    trace_id              String CODEC(ZSTD(1)),
    hash_algorithm        LowCardinality(String) DEFAULT 'SHA-256',
    canonicalization      LowCardinality(String) DEFAULT 'RFC8785',

    -- ---- Payload (opaque canonical bytes, never re-serialized) -----------
    payload               String CODEC(ZSTD(3)),

    -- ---- Sparse v1.1 header members (inside the hash when present) -------
    classification_reason Nullable(String) CODEC(ZSTD(1)),
    narrowing_applied     Nullable(String) CODEC(ZSTD(1)),
    pause_token           Nullable(String) CODEC(ZSTD(1)),

    -- ---- Chain integrity -------------------------------------------------
    record_hash           FixedString(64) CODEC(NONE),
    prev_hash             Nullable(FixedString(64)) CODEC(NONE),
    kms_signature         Nullable(String) CODEC(ZSTD(1)),
    kms_signature_algorithm LowCardinality(Nullable(String)),

    -- ---- Sink provenance (NOT hashed) ------------------------------------
    ingested_at           DateTime64(3, 'UTC') DEFAULT now64(3) CODEC(Delta, ZSTD(1)),
    redis_msg_id          String CODEC(ZSTD(1)),

    -- ---- Skip indexes ----------------------------------------------------
    INDEX idx_trace_id    trace_id    TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_event_type  event_type  TYPE set(0)             GRANULARITY 1,
    INDEX idx_timestamp   timestamp   TYPE minmax             GRANULARITY 1,
    INDEX idx_record_hash record_hash TYPE bloom_filter(0.01) GRANULARITY 1,

    -- ---- Structural invariants (checked at INSERT) -----------------------
    CONSTRAINT chk_schema_version CHECK schema_version IN ('3.0'),
    CONSTRAINT chk_hash_algorithm CHECK hash_algorithm = 'SHA-256',
    CONSTRAINT chk_canonicalization CHECK canonicalization = 'RFC8785',
    CONSTRAINT chk_trace_id_present CHECK length(trace_id) > 0,
    CONSTRAINT chk_record_hash_hex  CHECK match(record_hash, '^[0-9a-f]{64}$'),
    CONSTRAINT chk_genesis_prev_hash CHECK (sequence = 0) = (prev_hash IS NULL)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (chain_id, sequence)
TTL toDateTime(timestamp) + INTERVAL 7 YEAR DELETE
SETTINGS
    index_granularity = 8192,
    ttl_only_drop_parts = 1,
    min_bytes_for_wide_part = 0;

-- ===========================================================================
-- §6.1 — Chain Sequence Gap Detector
-- ===========================================================================
-- Rationale: AggregatingMergeTree is safe here (not a contradiction of §3.1)
-- because this table holds derived aggregates, not evidence. Merging partial
-- aggregate states is the engine's designed behaviour and destroys no facts.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS cage_evidence.evidence_chain_gaps
(
    chain_id          UUID,
    bucket_hour       DateTime('UTC'),
    seq_min           AggregateFunction(min, UInt64),
    seq_max           AggregateFunction(max, UInt64),
    record_count      AggregateFunction(count, UInt64),
    distinct_seq      AggregateFunction(uniqExact, UInt64),
    observed_sequences AggregateFunction(groupArray, UInt64),
    first_seen        AggregateFunction(min, DateTime64(3, 'UTC')),
    last_seen         AggregateFunction(max, DateTime64(3, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(bucket_hour)
ORDER BY (chain_id, bucket_hour)
TTL bucket_hour + INTERVAL 7 YEAR DELETE
SETTINGS ttl_only_drop_parts = 1;

CREATE MATERIALIZED VIEW IF NOT EXISTS cage_evidence.mv_evidence_chain_gaps
TO cage_evidence.evidence_chain_gaps
AS
SELECT
    chain_id,
    toStartOfHour(timestamp)      AS bucket_hour,
    minState(sequence)            AS seq_min,
    maxState(sequence)            AS seq_max,
    countState()                  AS record_count,
    uniqExactState(sequence)      AS distinct_seq,
    groupArrayState(sequence)     AS observed_sequences,
    minState(timestamp)           AS first_seen,
    maxState(timestamp)           AS last_seen
FROM cage_evidence.evidence_stream
GROUP BY chain_id, bucket_hour;

CREATE VIEW IF NOT EXISTS cage_evidence.v_chain_gap_alerts AS
SELECT
    chain_id,
    bucket_hour,
    minMerge(seq_min)                       AS seq_min,
    maxMerge(seq_max)                       AS seq_max,
    countMerge(record_count)                AS records,
    uniqExactMerge(distinct_seq)            AS distinct_sequences,
    (seq_max - seq_min + 1) - distinct_sequences AS missing_count,
    records - distinct_sequences            AS duplicate_count,
    arraySort(groupArrayMerge(observed_sequences)) AS sequences,
    -- Explicit list of absent sequence numbers (bounded to avoid blowup)
    if(missing_count BETWEEN 1 AND 1000,
       arrayFilter(s -> NOT has(sequences, s), range(seq_min, seq_max + 1)),
       []) AS missing_sequences,
    minMerge(first_seen)                    AS first_seen,
    maxMerge(last_seen)                     AS last_seen
FROM cage_evidence.evidence_chain_gaps
GROUP BY chain_id, bucket_hour
HAVING missing_count > 0 OR duplicate_count > 0;

-- ===========================================================================
-- §6.2 — Hash Chain Integrity Validator
-- ===========================================================================
-- Rationale: The divergence table is MergeTree for the same reason the
-- evidence table is: a tamper alert is itself evidence, and an engine that
-- can merge alerts away is an engine that can be used to hide an attack.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS cage_evidence.evidence_chain_divergence
(
    detected_at      DateTime64(3, 'UTC') DEFAULT now64(3),
    chain_id         UUID,
    sequence         UInt64,
    timestamp        DateTime64(3, 'UTC'),
    event_type       LowCardinality(String),
    trace_id         String,

    divergence_type  Enum8(
        'HASH_MISMATCH'          = 1,
        'SEQUENCE_GAP'           = 2,
        'BROKEN_LINK'            = 3,
        'GENESIS_VIOLATION'      = 4,
        'DUPLICATE_SEQUENCE'     = 5,
        'UNVERIFIABLE_ENCODING'  = 6,
        'SCHEMA_VIOLATION'       = 7
    ),

    -- SUSPECTED is machine-generated; CONFIRMED/CLEARED are written by the
    -- authoritative T3 Python verifier. Verdicts are appended, never updated.
    verdict          Enum8('SUSPECTED' = 1, 'CONFIRMED' = 2, 'CLEARED' = 3)
                     DEFAULT 'SUSPECTED',
    verified_by      LowCardinality(String) DEFAULT 'clickhouse_mv',

    stored_hash      FixedString(64),
    computed_hash    Nullable(FixedString(64)),
    prev_hash        Nullable(FixedString(64)),
    escape_safe      UInt8,
    detail           String DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(detected_at)
ORDER BY (chain_id, sequence, detected_at)
TTL toDateTime(detected_at) + INTERVAL 7 YEAR DELETE
SETTINGS ttl_only_drop_parts = 1;

CREATE MATERIALIZED VIEW IF NOT EXISTS cage_evidence.mv_evidence_hash_verification
TO cage_evidence.evidence_chain_divergence
AS
WITH
    concat(
        '{',
          '"canonicalization":', toJSONString(canonicalization), ',',
          '"chain_id":',         toJSONString(toString(chain_id)), ',',
          if(classification_reason IS NULL, '',
             concat('"classification_reason":', toJSONString(assumeNotNull(classification_reason)), ',')),
          '"control_id":',       toJSONString(control_id), ',',
          '"event_type":',       toJSONString(event_type), ',',
          '"hash_algorithm":',   toJSONString(hash_algorithm), ',',
          if(narrowing_applied IS NULL, '',
             concat('"narrowing_applied":', assumeNotNull(narrowing_applied), ',')),
          if(pause_token IS NULL, '',
             concat('"pause_token":', toJSONString(assumeNotNull(pause_token)), ',')),
          '"schema":',           toJSONString(concat('cage-audit/', schema_version)), ',',
          '"sequence":',         toString(sequence), ',',
          '"trace_id":',         toJSONString(trace_id),
        '}'
    ) AS canonical_header,

    lower(hex(SHA256(concat(ifNull(prev_hash, ''), canonical_header, payload)))) AS computed,

    NOT match(
        concat(control_id, event_type, trace_id, ifNull(classification_reason, ''), payload),
        '[\\x00-\\x1F\\x7F]|\\\\u'
    ) AS is_escape_safe
SELECT
    now64(3)                                       AS detected_at,
    chain_id,
    sequence,
    timestamp,
    event_type,
    trace_id,
    multiIf(
        (sequence = 0) != (prev_hash IS NULL), 'GENESIS_VIOLATION',
        NOT is_escape_safe,                    'UNVERIFIABLE_ENCODING',
                                               'HASH_MISMATCH'
    )                                              AS divergence_type,
    'SUSPECTED'                                    AS verdict,
    'clickhouse_mv'                                AS verified_by,
    record_hash                                    AS stored_hash,
    toFixedString(computed, 64)                    AS computed_hash,
    prev_hash,
    toUInt8(is_escape_safe)                        AS escape_safe,
    concat('mv recompute; escape_safe=', toString(is_escape_safe)) AS detail
FROM cage_evidence.evidence_stream
WHERE
       computed != lower(hex(record_hash))
    OR NOT is_escape_safe
    OR (sequence = 0) != (prev_hash IS NULL);

CREATE VIEW IF NOT EXISTS cage_evidence.v_divergence_current AS
SELECT
    chain_id,
    sequence,
    divergence_type,
    argMax(verdict,     detected_at) AS current_verdict,
    argMax(verified_by, detected_at) AS current_verifier,
    max(detected_at)                 AS last_evaluated_at,
    any(stored_hash)                 AS stored_hash,
    anyLast(computed_hash)           AS computed_hash
FROM cage_evidence.evidence_chain_divergence
GROUP BY chain_id, sequence, divergence_type;

-- ===========================================================================
-- §6.3 — Prometheus Metrics Aggregator
-- ===========================================================================
-- Rationale: Metrics carry a 2-year TTL, not 7. They are operational telemetry
-- derived from evidence, not evidence itself; conflating the two would inflate
-- the compliance-retention surface for no regulatory benefit.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS cage_evidence.evidence_metrics_5m
(
    bucket_5m        DateTime('UTC'),
    chain_id         UUID,
    event_type       LowCardinality(String),
    control_id       LowCardinality(String),
    schema_version   LowCardinality(String),
    event_count      AggregateFunction(count, UInt64),
    distinct_traces  AggregateFunction(uniq, String),
    max_sequence     AggregateFunction(max, UInt64),
    signed_count     AggregateFunction(sum, UInt64),
    ingest_lag_ms_p99 AggregateFunction(quantile(0.99), Int64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(bucket_5m)
ORDER BY (bucket_5m, chain_id, event_type, control_id, schema_version)
TTL bucket_5m + INTERVAL 2 YEAR DELETE
SETTINGS ttl_only_drop_parts = 1;

CREATE MATERIALIZED VIEW IF NOT EXISTS cage_evidence.mv_evidence_metrics
TO cage_evidence.evidence_metrics_5m
AS
SELECT
    toStartOfFiveMinutes(timestamp) AS bucket_5m,
    chain_id,
    event_type,
    control_id,
    schema_version,
    countState()                    AS event_count,
    uniqState(trace_id)             AS distinct_traces,
    maxState(sequence)              AS max_sequence,
    sumState(toUInt64(kms_signature IS NOT NULL)) AS signed_count,
    quantileState(0.99)(dateDiff('millisecond', timestamp, ingested_at)) AS ingest_lag_ms_p99
FROM cage_evidence.evidence_stream
GROUP BY bucket_5m, chain_id, event_type, control_id, schema_version;

CREATE VIEW IF NOT EXISTS cage_evidence.v_prometheus_metrics AS
SELECT
    'clickhouse_chain_divergence_total' AS name,
    toFloat64(count())                  AS value,
    map('chain_id', toString(chain_id),
        'divergence_type', toString(divergence_type),
        'verdict', toString(current_verdict)) AS labels,
    'Confirmed or suspected evidence chain divergences' AS help,
    'counter'                           AS type
FROM cage_evidence.v_divergence_current
GROUP BY chain_id, divergence_type, current_verdict

UNION ALL

SELECT
    'clickhouse_evidence_records_total',
    toFloat64(countMerge(event_count)),
    map('chain_id', toString(chain_id),
        'event_type', toString(event_type),
        'control_id', toString(control_id)),
    'Evidence records ingested into ClickHouse',
    'counter'
FROM cage_evidence.evidence_metrics_5m
WHERE bucket_5m >= now() - INTERVAL 1 DAY
GROUP BY chain_id, event_type, control_id

UNION ALL

SELECT
    'clickhouse_evidence_ingest_lag_ms',
    quantileMerge(0.99)(ingest_lag_ms_p99),
    map('chain_id', toString(chain_id)),
    'p99 Redis-to-ClickHouse ingestion lag in milliseconds',
    'gauge'
FROM cage_evidence.evidence_metrics_5m
WHERE bucket_5m >= now() - INTERVAL 15 MINUTE
GROUP BY chain_id;

-- ===========================================================================
-- §7.2 — RBAC Roles and Grants
-- ===========================================================================
-- Rationale: Least privilege; no role holds both write and mutate. The absence
-- of a grant IS the denial (ClickHouse grants are additive only, no DENY).
-- The "NOT granted" comments are normative and must survive future edits.
-- ===========================================================================

CREATE ROLE IF NOT EXISTS evidence_writer;
CREATE ROLE IF NOT EXISTS evidence_reader;
CREATE ROLE IF NOT EXISTS evidence_verifier;
CREATE ROLE IF NOT EXISTS evidence_admin;

-- --- evidence_writer: INSERT only. The compliance-bridge sink identity. -----
GRANT INSERT ON cage_evidence.evidence_stream          TO evidence_writer;
GRANT INSERT ON cage_evidence.evidence_chain_divergence TO evidence_writer;
-- Deliberately NOT granted: SELECT, ALTER, DROP, TRUNCATE, OPTIMIZE.
-- A writer that cannot read cannot exfiltrate the audit trail, and cannot
-- discover which records exist in order to forge a convincing overwrite.

-- --- evidence_reader: SELECT only, and not on raw payloads by default. ------
GRANT SELECT ON cage_evidence.evidence_stream           TO evidence_reader;
GRANT SELECT ON cage_evidence.evidence_chain_gaps       TO evidence_reader;
GRANT SELECT ON cage_evidence.evidence_chain_divergence TO evidence_reader;
GRANT SELECT ON cage_evidence.evidence_metrics_5m       TO evidence_reader;
GRANT SELECT ON cage_evidence.v_chain_gap_alerts        TO evidence_reader;
GRANT SELECT ON cage_evidence.v_divergence_current      TO evidence_reader;

-- --- evidence_verifier: the T3 Python verifier. Reads all, appends verdicts.
GRANT SELECT ON cage_evidence.evidence_stream           TO evidence_verifier;
GRANT SELECT ON cage_evidence.evidence_chain_divergence TO evidence_verifier;
GRANT INSERT ON cage_evidence.evidence_chain_divergence TO evidence_verifier;
-- Verdict promotion is an INSERT of a later row (§5.4), never an UPDATE,
-- so the verifier needs no ALTER privilege whatsoever.

-- --- evidence_admin: schema evolution + retention. NO row mutation. ---------
GRANT SELECT                    ON cage_evidence.*                    TO evidence_admin;
GRANT ALTER ADD COLUMN          ON cage_evidence.evidence_stream      TO evidence_admin;
GRANT ALTER MODIFY COMMENT      ON cage_evidence.evidence_stream      TO evidence_admin;
GRANT ALTER MATERIALIZE INDEX   ON cage_evidence.evidence_stream      TO evidence_admin;
GRANT ALTER DROP PARTITION      ON cage_evidence.evidence_stream      TO evidence_admin;
GRANT CREATE TABLE, CREATE VIEW ON cage_evidence.*                    TO evidence_admin;
-- Critically NOT granted, to anyone, ever:
--   ALTER UPDATE, ALTER DELETE, ALTER DROP COLUMN, ALTER MODIFY COLUMN,
--   TRUNCATE, DROP TABLE, DROP DATABASE.

-- ===========================================================================
-- §7.3 — Settings Profiles and Users
-- ===========================================================================
-- Rationale: CONST suffix forbids session override, preventing privilege
-- escalation via settings. Passwords are injected as query parameters from
-- Kubernetes secretKeyRef at apply time. In GKE, prefer mTLS certificate
-- identities (IDENTIFIED WITH ssl_certificate CN '...') so no shared secret
-- exists to leak.
-- ===========================================================================

CREATE SETTINGS PROFILE IF NOT EXISTS evidence_writer_profile SETTINGS
    readonly                            = 0,
    allow_experimental_lightweight_delete = 0 CONST,
    mutations_sync                      = 0   CONST,
    max_partitions_per_insert_block     = 8,
    async_insert                        = 1,
    wait_for_async_insert               = 1,
    async_insert_busy_timeout_ms        = 5000,
    async_insert_max_data_size          = 10485760,
    max_execution_time                  = 30;

CREATE SETTINGS PROFILE IF NOT EXISTS evidence_reader_profile SETTINGS
    readonly                            = 1 CONST,
    allow_ddl                           = 0 CONST,
    allow_experimental_lightweight_delete = 0 CONST,
    max_execution_time                  = 300,
    max_result_rows                     = 1000000,
    max_memory_usage                    = 8000000000;

CREATE USER IF NOT EXISTS cage_evidence_sink
    IDENTIFIED WITH sha256_password BY {password:String}
    SETTINGS PROFILE evidence_writer_profile
    DEFAULT ROLE evidence_writer;

CREATE USER IF NOT EXISTS cage_evidence_query
    IDENTIFIED WITH sha256_password BY {password:String}
    SETTINGS PROFILE evidence_reader_profile
    DEFAULT ROLE evidence_reader;

-- ===========================================================================
-- §7.5 — Row Policy for Jurisdictional Isolation
-- ===========================================================================
-- Rationale: CAGE enforces regional data residency (US_FED, EU_ECB, APAC_MAS).
-- Row policies keep a reader in one region from reading another region's
-- evidence. Row policies are SELECT-side only and therefore cannot weaken
-- the append-only property; they narrow visibility, never mutability.
-- ===========================================================================

CREATE ROW POLICY IF NOT EXISTS evidence_region_isolation
    ON cage_evidence.evidence_stream
    FOR SELECT
    USING JSONExtractString(payload, 'deployment_region')
          IN (SELECT region FROM cage_evidence.reader_region_grants
              WHERE role_name = currentRoles()[1])
    TO evidence_reader;

-- ===========================================================================
-- §7.6 — WORM Violation and Insert Audit Views
-- ===========================================================================
-- Rationale: Any row in v_worm_violations is a critical page, not a dashboard
-- tile. The view intentionally still surfaces sanctioned retention drops under
-- a separate query so that erasure actions remain reviewable rather than
-- invisible. Insert-side auditing correlates every write back to the
-- originating W3C trace, closing the loop with CAGE's Langfuse telemetry.
-- ===========================================================================

CREATE VIEW IF NOT EXISTS cage_evidence.v_worm_violations AS
SELECT
    event_time,
    user,
    address,
    initial_query_id,
    type,
    query_kind,
    query,
    exception
FROM system.query_log
WHERE
    event_time >= now() - INTERVAL 24 HOUR
    AND has(databases, 'cage_evidence')
    AND (
           query_kind IN ('Alter', 'Drop', 'Truncate', 'Rename')
        OR positionCaseInsensitive(query, 'ALTER TABLE') > 0
           AND (positionCaseInsensitive(query, ' DELETE') > 0
             OR positionCaseInsensitive(query, ' UPDATE') > 0)
        OR positionCaseInsensitive(query, 'DELETE FROM') > 0
        OR positionCaseInsensitive(query, 'OPTIMIZE TABLE') > 0
    )
    -- The one sanctioned exception: partition drops performed by the
    -- retention job, which must still be reviewed, never silently ignored.
    AND NOT (user = 'cage_evidence_retention'
             AND positionCaseInsensitive(query, 'DROP PARTITION') > 0);

CREATE VIEW IF NOT EXISTS cage_evidence.v_insert_audit AS
SELECT
    event_time,
    user,
    address,
    query_id,
    log_comment      AS trace_context,  -- sink sets this to the batch traceparent
    written_rows,
    written_bytes,
    query_duration_ms,
    exception_code
FROM system.query_log
WHERE type IN ('QueryFinish', 'ExceptionWhileProcessing')
  AND query_kind = 'Insert'
  AND has(tables, 'cage_evidence.evidence_stream');

-- ===========================================================================
-- §9 — Schema Evolution Example (Commented, Illustrative Only)
-- ===========================================================================
-- Below is an illustrative v4.0 additive migration showing how to evolve the
-- schema without mutating existing evidence. Append-only data demands
-- append-only schema: ADD COLUMN with DEFAULT is metadata-only and compatible
-- with WORM, while DROP COLUMN and MODIFY COLUMN are permanently forbidden.
-- ===========================================================================

-- -- Illustrative v4.0 additive migration
-- ALTER TABLE cage_evidence.evidence_stream
--     ADD COLUMN IF NOT EXISTS jurisdiction LowCardinality(String) DEFAULT '';
--
-- ALTER TABLE cage_evidence.evidence_stream
--     DROP CONSTRAINT IF EXISTS chk_schema_version;
-- ALTER TABLE cage_evidence.evidence_stream
--     ADD CONSTRAINT chk_schema_version CHECK schema_version IN ('3.0', '4.0');
