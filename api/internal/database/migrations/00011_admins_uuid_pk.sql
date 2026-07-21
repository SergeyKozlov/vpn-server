-- +goose Up
-- P2.2: sessions.user_id must reference the table that actually logs in via
-- POST /login (admins), not the AC-DB customer `users` table. admins.id was
-- left as BIGSERIAL from Phase 1; bring it in line with AC-DB-0 (UUID PK on
-- all entities) so it can be referenced from sessions.
ALTER TABLE admins DROP CONSTRAINT admins_pkey;
ALTER TABLE admins ALTER COLUMN id DROP DEFAULT;
ALTER TABLE admins ALTER COLUMN id TYPE UUID USING gen_random_uuid();
ALTER TABLE admins ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE admins ADD PRIMARY KEY (id);
DROP SEQUENCE IF EXISTS admins_id_seq;

ALTER TABLE sessions DROP CONSTRAINT sessions_user_id_fkey;
ALTER TABLE sessions ADD CONSTRAINT sessions_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES admins(id);

-- +goose Down
ALTER TABLE sessions DROP CONSTRAINT sessions_user_id_fkey;
ALTER TABLE sessions ADD CONSTRAINT sessions_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id);

ALTER TABLE admins DROP CONSTRAINT admins_pkey;
ALTER TABLE admins ALTER COLUMN id DROP DEFAULT;
CREATE SEQUENCE admins_id_seq;
ALTER TABLE admins ALTER COLUMN id TYPE BIGINT USING nextval('admins_id_seq');
ALTER TABLE admins ALTER COLUMN id SET DEFAULT nextval('admins_id_seq');
ALTER SEQUENCE admins_id_seq OWNED BY admins.id;
ALTER TABLE admins ADD PRIMARY KEY (id);
