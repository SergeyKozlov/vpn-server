-- +goose Up
CREATE TABLE sessions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- append-only in spirit: no updated_at (see AC-DB-6). Not written to until P2.2 —
-- POST /login still issues the stateless HMAC cookie from internal/session.

-- +goose Down
DROP TABLE sessions;
