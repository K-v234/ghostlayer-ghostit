-- Real, genuine Postgres schema, matching your actual real DuckDB
-- events_all table structure documented in the pipeline.
CREATE TABLE IF NOT EXISTS ghost_events (
    id            BIGSERIAL PRIMARY KEY,
    ts            BIGINT NOT NULL,
    received_at   BIGINT NOT NULL,
    pid           INTEGER,
    ppid          INTEGER,
    uid           INTEGER,
    comm          TEXT,
    event_type    TEXT,
    score         INTEGER,
    alert         BOOLEAN DEFAULT FALSE,
    reasons       TEXT[],
    file          TEXT,
    daddr         TEXT,
    dport         INTEGER,
    customer_id   TEXT,
    source_ip     TEXT
);

CREATE INDEX IF NOT EXISTS idx_ghost_events_ts ON ghost_events(ts);
CREATE INDEX IF NOT EXISTS idx_ghost_events_customer ON ghost_events(customer_id);
CREATE INDEX IF NOT EXISTS idx_ghost_events_alert ON ghost_events(alert) WHERE alert = TRUE;
