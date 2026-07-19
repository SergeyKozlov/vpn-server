-- +goose Up
CREATE TABLE clients (
    id BIGSERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    xui_inbound_id INTEGER NOT NULL DEFAULT 1,
    vless_uuid_enc BYTEA NOT NULL,
    hysteria2_username TEXT NOT NULL UNIQUE,
    hysteria2_password_enc BYTEA NOT NULL,
    sub_id TEXT NOT NULL UNIQUE,
    traffic_limit_bytes BIGINT NOT NULL DEFAULT 0,
    limit_ip SMALLINT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER clients_set_updated_at
    BEFORE UPDATE ON clients
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

-- +goose Down
DROP TRIGGER IF EXISTS clients_set_updated_at ON clients;
DROP TABLE clients;
