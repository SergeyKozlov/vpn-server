-- +goose Up
CREATE TABLE node_health (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id    UUID NOT NULL REFERENCES nodes(id),
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status     VARCHAR(16) NOT NULL CHECK (status IN ('ok','blocked','degraded')),
    source     VARCHAR(16) NOT NULL CHECK (source IN ('client_report','self_check')),
    detail     JSONB NULL
);

CREATE TABLE traffic_usage (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id),
    node_id      UUID NULL REFERENCES nodes(id),
    period_start TIMESTAMPTZ NOT NULL,
    period_end   TIMESTAMPTZ NOT NULL,
    bytes_up     BIGINT NOT NULL DEFAULT 0,
    bytes_down   BIGINT NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE traffic_usage;
DROP TABLE node_health;
