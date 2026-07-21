-- +goose Up
CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               VARCHAR(320) UNIQUE NOT NULL,
    password_hash       TEXT NOT NULL,
    status              VARCHAR(16) NOT NULL DEFAULT 'trial'
                            CHECK (status IN ('trial','active','expired','blocked')),
    preferred_region_id UUID NULL, -- FK added in 00007 once regions exists
    trial_ends_at       TIMESTAMPTZ NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ NULL
);

CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose Down
DROP TABLE users;
