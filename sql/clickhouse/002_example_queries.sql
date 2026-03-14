-- Railway Observability Engine — Example Queries
--
-- These demonstrate the query patterns the API layer uses.
-- All queries include WHERE project_id = ... for tenant isolation.

-- =============================================================================
-- 1. Get all spans for a trace (waterfall view)
-- =============================================================================

SELECT
    trace_id,
    span_id,
    parent_span_id,
    service_id,
    http_method,
    http_path,
    http_status,
    start_time,
    duration_us,
    is_error
FROM spans
WHERE project_id = 'proj_demo'
  AND trace_id = '4bf92f3577b58681a1038a16d442e168'
ORDER BY start_time ASC;

-- =============================================================================
-- 2. Service metrics from rollup (p50/p95/p99 latency, request count, error rate)
-- =============================================================================

SELECT
    window_start,
    countMerge(request_count_state)                             AS request_count,
    countMerge(error_count_state)                               AS error_count,
    if(request_count > 0, error_count / request_count, 0)       AS error_rate,
    quantileMerge(0.5)(p50_state)                               AS p50_us,
    quantileMerge(0.95)(p95_state)                              AS p95_us,
    quantileMerge(0.99)(p99_state)                              AS p99_us,
    minMerge(min_duration_state)                                AS min_us,
    maxMerge(max_duration_state)                                AS max_us
FROM spans_5min_rollup_data
WHERE project_id = 'proj_demo'
  AND service_id = 'svc_api_gateway'
  AND window_start >= now() - INTERVAL 1 HOUR
GROUP BY window_start
ORDER BY window_start ASC;

-- =============================================================================
-- 3. Top endpoints by request count for a service
-- =============================================================================

SELECT
    http_route,
    http_method,
    countMerge(request_count_state)                             AS request_count,
    countMerge(error_count_state)                               AS error_count,
    quantileMerge(0.99)(p99_state)                              AS p99_us
FROM spans_5min_rollup_data
WHERE project_id = 'proj_demo'
  AND service_id = 'svc_api_gateway'
  AND window_start >= now() - INTERVAL 1 HOUR
GROUP BY http_route, http_method
ORDER BY request_count DESC
LIMIT 20;

-- =============================================================================
-- 4. Service dependency graph (topology)
-- =============================================================================

SELECT
    caller_service_id,
    callee_service_id,
    sum(call_count)                                 AS total_calls,
    sum(error_count)                                AS total_errors,
    if(total_calls > 0, total_errors / total_calls, 0) AS error_rate,
    sum(total_duration_us) / sum(duration_count)    AS avg_duration_us
FROM service_dependencies
WHERE project_id = 'proj_demo'
  AND window_start >= now() - INTERVAL 1 HOUR
GROUP BY caller_service_id, callee_service_id
ORDER BY total_calls DESC;

-- =============================================================================
-- 5. Find slow traces (latency > threshold)
-- =============================================================================

SELECT
    trace_id,
    service_id,
    http_method,
    http_path,
    http_status,
    duration_us,
    start_time,
    is_error
FROM spans
WHERE project_id = 'proj_demo'
  AND service_id = 'svc_api_gateway'
  AND start_time >= now() - INTERVAL 1 HOUR
  AND duration_us > 500000  -- > 500ms
  AND is_root = 1
ORDER BY duration_us DESC
LIMIT 50;

-- =============================================================================
-- 6. Correlation: metric spike → contributing traces
-- =============================================================================

-- Step 1: Identify the spike window from rollup
-- (This is done programmatically in the API; here we show the concept)

-- Step 2: Find traces during that window above the p99 threshold
SELECT
    trace_id,
    span_id,
    service_id,
    http_method,
    http_path,
    http_status,
    duration_us,
    start_time
FROM spans
WHERE project_id = 'proj_demo'
  AND service_id = 'svc_api_gateway'
  AND start_time BETWEEN '2026-03-14 15:00:00' AND '2026-03-14 15:05:00'
  AND duration_us > 200000  -- above the p99 threshold identified in step 1
ORDER BY duration_us DESC
LIMIT 20;

-- =============================================================================
-- 7. Logs correlated with a trace
-- =============================================================================

SELECT
    service_id,
    timestamp,
    log_level,
    message,
    span_id
FROM trace_logs
WHERE project_id = 'proj_demo'
  AND trace_id = '4bf92f3577b58681a1038a16d442e168'
ORDER BY timestamp ASC;

-- =============================================================================
-- 8. Error rate by service (last 24h, from rollup)
-- =============================================================================

SELECT
    service_id,
    countMerge(request_count_state)                         AS requests,
    countMerge(error_count_state)                           AS errors,
    if(requests > 0, errors / requests, 0)                  AS error_rate,
    quantileMerge(0.99)(p99_state)                          AS p99_us
FROM spans_5min_rollup_data
WHERE project_id = 'proj_demo'
  AND window_start >= now() - INTERVAL 24 HOUR
GROUP BY service_id
ORDER BY error_rate DESC;
