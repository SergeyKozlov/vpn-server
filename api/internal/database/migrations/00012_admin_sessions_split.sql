-- +goose Up
-- 1) отдельная таблица admin-сессий (FK -> admins)
CREATE TABLE admin_sessions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES admins(id),  -- имя колонки user_id намеренно (см. раздел 4: единый generic SessionManager)
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX admin_sessions_token_hash_idx ON admin_sessions(token_hash);

-- 2) sessions возвращаем на users, как требует AC-DB-6
--    (в sessions сейчас лежат admin-сессии из P2.2 — они несовместимы с новым FK; таблица техническая, чистим)
TRUNCATE TABLE sessions;
ALTER TABLE sessions DROP CONSTRAINT sessions_user_id_fkey;
ALTER TABLE sessions ADD CONSTRAINT sessions_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id);
CREATE INDEX IF NOT EXISTS sessions_token_hash_idx ON sessions(token_hash);

-- +goose Down
DROP INDEX IF EXISTS sessions_token_hash_idx;
ALTER TABLE sessions DROP CONSTRAINT sessions_user_id_fkey;
ALTER TABLE sessions ADD CONSTRAINT sessions_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES admins(id);
DROP TABLE admin_sessions;
