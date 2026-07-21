-- +goose Up
CREATE TABLE regions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code       VARCHAR(16) UNIQUE NOT NULL,
    name       VARCHAR(64) NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER regions_set_updated_at BEFORE UPDATE ON regions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE nodes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    region_id  UUID NOT NULL REFERENCES regions(id),
    ip         INET NOT NULL,
    hostname   VARCHAR(255) NULL,
    decoy_sni  VARCHAR(255) NULL,
    status     VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active','blocked','maintenance')),
    enabled    BOOLEAN NOT NULL DEFAULT true,
    blocked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ NULL
);
CREATE TRIGGER nodes_set_updated_at BEFORE UPDATE ON nodes
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE node_protocols (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id    UUID NOT NULL REFERENCES nodes(id),
    protocol   VARCHAR(24) NOT NULL CHECK (protocol IN ('vless_reality','hysteria2')),
    port       INTEGER NOT NULL,
    priority   SMALLINT NOT NULL DEFAULT 0,
    params     JSONB NOT NULL DEFAULT '{}',
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER node_protocols_set_updated_at BEFORE UPDATE ON node_protocols
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- deferred FK from 00004
ALTER TABLE users ADD CONSTRAINT users_preferred_region_fk
    FOREIGN KEY (preferred_region_id) REFERENCES regions(id);

-- seed: the single current region and node (AC-0.5: schema is multi-node-ready,
-- operation is single-node for now). Values verified against the live 3x-ui
-- VLESS Reality inbound (realitySettings.target/serverNames) and
-- hysteria/config.yaml (listen :8443) before writing this migration.
INSERT INTO regions (code, name, enabled) VALUES ('kz', 'Казахстан', true);

INSERT INTO nodes (region_id, ip, hostname, decoy_sni, status, enabled)
SELECT id, '92.60.75.196', NULL, 'dl.google.com', 'active', true
FROM regions WHERE code = 'kz';

INSERT INTO node_protocols (node_id, protocol, port, priority, params)
SELECT id, 'vless_reality', 443, 10, '{}'::jsonb FROM nodes WHERE ip = '92.60.75.196';
INSERT INTO node_protocols (node_id, protocol, port, priority, params)
SELECT id, 'hysteria2', 8443, 0, '{}'::jsonb FROM nodes WHERE ip = '92.60.75.196';

-- +goose Down
ALTER TABLE users DROP CONSTRAINT users_preferred_region_fk;
DROP TABLE node_protocols;
DROP TABLE nodes;
DROP TABLE regions;
