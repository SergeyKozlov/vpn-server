-- +goose Up
CREATE TABLE user_credentials (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id),
    protocol     VARCHAR(24) NOT NULL CHECK (protocol IN ('vless_reality','hysteria2')),
    credential   BYTEA NOT NULL, -- encrypted via internal/crypto.AESGCM
    device_label VARCHAR(64) NULL,
    status       VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    revoked_at   TIMESTAMPTZ NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER user_credentials_set_updated_at
    BEFORE UPDATE ON user_credentials
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose Down
DROP TABLE user_credentials;
