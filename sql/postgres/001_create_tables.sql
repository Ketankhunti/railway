-- Railway Observability Engine — PostgreSQL Schema (Alert Rules + Events)
--
-- Alert rules need transactional CRUD and consistent reads.
-- ClickHouse's eventual-merge semantics are unsuitable for mutable
-- config that drives real-time alerting.

-- =============================================================================
-- Alert Rules
-- =============================================================================

CREATE TABLE IF NOT EXISTS alert_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      TEXT NOT NULL,
    name            TEXT NOT NULL,
    rule_type       TEXT NOT NULL CHECK (rule_type IN ('threshold', 'anomaly', 'rate_of_change')),
    config          JSONB NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    severity        TEXT NOT NULL CHECK (severity IN ('critical', 'warning', 'info')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_alert_rule_name_per_project UNIQUE (project_id, name)
);

CREATE INDEX idx_alert_rules_project ON alert_rules(project_id, enabled);

-- =============================================================================
-- Alert Events (firing / resolved)
-- =============================================================================

CREATE TABLE IF NOT EXISTS alert_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id             UUID NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    project_id          TEXT NOT NULL,
    service_id          TEXT NOT NULL,
    fingerprint         TEXT NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('firing', 'resolved')),
    severity            TEXT NOT NULL CHECK (severity IN ('critical', 'warning', 'info')),
    message             TEXT NOT NULL,
    metric_value        DOUBLE PRECISION,
    threshold_value     DOUBLE PRECISION,
    started_at          TIMESTAMPTZ NOT NULL,
    resolved_at         TIMESTAMPTZ,
    last_seen_at        TIMESTAMPTZ NOT NULL,
    notification_sent   BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_alert_events_project ON alert_events(project_id, status, started_at DESC);
CREATE INDEX idx_alert_events_fingerprint ON alert_events(fingerprint, status);
CREATE INDEX idx_alert_events_rule ON alert_events(rule_id, started_at DESC);
