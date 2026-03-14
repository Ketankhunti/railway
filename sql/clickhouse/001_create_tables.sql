-- Railway Observability Engine — ClickHouse Schema
-- 
-- Run these in order. All tables use MergeTree (prototype).
-- Production would use ReplicatedMergeTree.
--
-- Partitioned by DATE only (not per-project) to avoid partition explosion.
-- Tenant isolation achieved via ORDER BY key (project_id first).

-- =============================================================================
-- Table 1: spans (raw span data — hot storage, 7-day TTL)
-- =============================================================================

CREATE TABLE IF NOT EXISTS spans (
    -- Identity
    trace_id        FixedString(32),    -- hex-encoded 128-bit trace ID
    span_id         UInt64,
    parent_span_id  UInt64,             -- 0 for root spans

    -- Railway tenant isolation
    project_id      LowCardinality(String),
    service_id      LowCardinality(String),
    environment_id  LowCardinality(String),

    -- HTTP data
    http_method     LowCardinality(String),
    http_path       String,             -- raw path: /api/users/123
    http_route      LowCardinality(String),  -- normalized: /api/users/:id
    http_status     UInt16,
    http_host       LowCardinality(String),

    -- Timing
    start_time      DateTime64(6, 'UTC'),   -- microsecond precision
    duration_us     UInt64,

    -- Network
    src_ip          IPv4,
    src_port        UInt16,
    dst_ip          IPv4,
    dst_port        UInt16,

    -- Destination service (resolved by ingestion pipeline)
    dst_service_id  LowCardinality(String),  -- '' if destination is external

    -- Metadata
    host_id         LowCardinality(String),
    container_id    String,
    is_error        UInt8,              -- 0 or 1
    is_root         UInt8,              -- 0 or 1
    sample_rate     Float32,

    -- Partition helper
    _date           Date DEFAULT toDate(start_time)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(start_time)
ORDER BY (project_id, service_id, start_time, trace_id)
TTL start_time + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;

-- Bloom filter index for trace_id lookups (not in ORDER BY prefix)
ALTER TABLE spans ADD INDEX IF NOT EXISTS idx_trace_id
    trace_id TYPE bloom_filter(0.01) GRANULARITY 4;

-- =============================================================================
-- Table 2: spans_5min_rollup (pre-aggregated metrics — warm storage, 90-day TTL)
-- Uses AggregatingMergeTree for quantileState merge support.
-- =============================================================================

-- Backing table for the materialized view
CREATE TABLE IF NOT EXISTS spans_5min_rollup_data (
    project_id      LowCardinality(String),
    service_id      LowCardinality(String),
    environment_id  LowCardinality(String),
    http_route      LowCardinality(String),
    http_method     LowCardinality(String),

    window_start    DateTime('UTC'),

    request_count_state   AggregateFunction(count, UInt8),
    error_count_state     AggregateFunction(countIf, UInt8, UInt8),
    total_duration_state  AggregateFunction(sum, UInt64),

    p50_state       AggregateFunction(quantile(0.5), UInt64),
    p95_state       AggregateFunction(quantile(0.95), UInt64),
    p99_state       AggregateFunction(quantile(0.99), UInt64),

    min_duration_state  AggregateFunction(min, UInt64),
    max_duration_state  AggregateFunction(max, UInt64)
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(window_start)
ORDER BY (project_id, service_id, http_route, http_method, window_start)
TTL window_start + INTERVAL 90 DAY;

-- Materialized view populates the rollup on every INSERT into spans
CREATE MATERIALIZED VIEW IF NOT EXISTS spans_5min_rollup
TO spans_5min_rollup_data
AS SELECT
    project_id,
    service_id,
    environment_id,
    http_route,
    http_method,

    toStartOfFiveMinutes(start_time) AS window_start,

    countState()                         AS request_count_state,
    countStateIf(is_error = 1)           AS error_count_state,
    sumState(duration_us)                AS total_duration_state,

    quantileState(0.5)(duration_us)      AS p50_state,
    quantileState(0.95)(duration_us)     AS p95_state,
    quantileState(0.99)(duration_us)     AS p99_state,

    minState(duration_us)                AS min_duration_state,
    maxState(duration_us)                AS max_duration_state

FROM spans
GROUP BY
    project_id, service_id, environment_id,
    http_route, http_method, window_start;

-- =============================================================================
-- Table 3: service_dependencies (topology — 30-day TTL)
-- Uses SummingMergeTree since all columns are simple numerics.
-- =============================================================================

CREATE TABLE IF NOT EXISTS service_dependencies (
    project_id          LowCardinality(String),
    environment_id      LowCardinality(String),

    caller_service_id   LowCardinality(String),
    callee_service_id   LowCardinality(String),

    window_start        DateTime('UTC'),

    call_count          UInt64,
    error_count         UInt64,
    total_duration_us   UInt64,
    duration_count      UInt64       -- for computing avg = total / count
)
ENGINE = SummingMergeTree((call_count, error_count, total_duration_us, duration_count))
PARTITION BY toYYYYMMDD(window_start)
ORDER BY (project_id, caller_service_id, callee_service_id, window_start)
TTL window_start + INTERVAL 30 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS service_dependencies_mv
TO service_dependencies
AS SELECT
    project_id,
    environment_id,

    service_id          AS caller_service_id,
    dst_service_id      AS callee_service_id,

    toStartOfFiveMinutes(start_time) AS window_start,

    count()                 AS call_count,
    countIf(is_error = 1)   AS error_count,
    sum(duration_us)        AS total_duration_us,
    count()                 AS duration_count

FROM spans
WHERE dst_service_id != ''
GROUP BY
    project_id, environment_id,
    caller_service_id, callee_service_id, window_start;

-- =============================================================================
-- Table 4: trace_logs (log-trace correlation — 7-day TTL)
-- =============================================================================

CREATE TABLE IF NOT EXISTS trace_logs (
    project_id      LowCardinality(String),
    service_id      LowCardinality(String),
    trace_id        FixedString(32),
    span_id         UInt64,

    timestamp       DateTime64(6, 'UTC'),
    log_level       LowCardinality(String),   -- info, warn, error
    message         String,

    _date           Date DEFAULT toDate(timestamp)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (project_id, trace_id, timestamp)
TTL timestamp + INTERVAL 7 DAY;
