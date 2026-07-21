-- +goose Up
ALTER TABLE users RENAME TO admins;
ALTER TABLE admins RENAME CONSTRAINT users_pkey TO admins_pkey;
ALTER TABLE admins RENAME CONSTRAINT users_username_key TO admins_username_key;
ALTER SEQUENCE users_id_seq RENAME TO admins_id_seq;
ALTER TRIGGER users_set_updated_at ON admins RENAME TO admins_set_updated_at;

-- +goose Down
ALTER TRIGGER admins_set_updated_at ON admins RENAME TO users_set_updated_at;
ALTER SEQUENCE admins_id_seq RENAME TO users_id_seq;
ALTER TABLE admins RENAME CONSTRAINT admins_username_key TO users_username_key;
ALTER TABLE admins RENAME CONSTRAINT admins_pkey TO users_pkey;
ALTER TABLE admins RENAME TO users;
