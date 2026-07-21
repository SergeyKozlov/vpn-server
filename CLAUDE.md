# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state of this repository

This repo is pre-implementation. Today it contains only:

- `docker-compose.yml` — runs the 3X-UI panel (`ghcr.io/mhsanaei/3x-ui:latest`) in `network_mode: host`, with `./db/` bind-mounted to `/etc/x-ui/` (panel's own SQLite DB + metrics) and `./cert/` bind-mounted to `/root/cert/`.
- `db/x-ui.db`, `db/system_metrics.gob` — 3X-UI's own runtime state (SQLite DB + gob-encoded metrics). This is the panel's internal storage, not an application database — do not treat it as project schema to migrate.
- `cert/` — TLS certs for the panel/inbounds (currently empty).
- `compass_artifact.md` — a technical reference/design doc for the **planned** Phase 1 server-side build. Nothing it describes (Go backend, Postgres, goose migrations, Caddy reverse proxy, argon2id/AES-GCM helpers) exists in this repo yet — treat it as the design spec to implement against, not as documentation of existing code.

There is no build, lint, or test tooling yet because there is no application source code yet. When a Go backend (or other service) is added under this repo, update this section and the sections below with real commands (`go build`, `go test ./...`, migration commands, etc.) instead of guessing.

## Operating the existing infra

```bash
docker compose up -d      # start the 3x-ui panel
docker compose down       # stop it
docker compose logs -f    # tail panel logs
```

The panel is exposed via host networking (no port mapping needed/possible to change here — edit `network_mode`/ports in `docker-compose.yml` if that changes). `XRAY_VMESS_AEAD_FORCED=false` is set for VMess AEAD compatibility.

## Planned architecture (from compass_artifact.md)

`compass_artifact.md` is the authoritative reference for building the Phase 1 server-side system. Key points to keep in mind while implementing against it — but always re-verify specifics (route paths, struct shapes, version numbers) against the actual pinned dependency versions before relying on them, since the doc notes several of these have shifted across releases:

- **3X-UI panel API**: All routes are mounted under a configurable `webBasePath` prefix (e.g. `{webBasePath}/panel/api/inbounds/*`) — every request, including login, must include it. Prefer the Settings → Security **Bearer API Token** over cookie-based login (cookie is named `3x-ui`) to avoid session-expiry handling. The `settings` field on `addClient`/`updateClient` payloads is a **stringified JSON**, not a nested object. `expiryTime` is epoch-milliseconds; `totalGB` is bytes.
- **Hysteria2 auth**: use `auth.type: userpass` (a native `username: password` map) for per-user credentials without an external service. `type: password` is a single shared secret across all clients, not per-user. Changing users means rewriting `config.yaml` and reloading the service.
- **Caddy reverse proxy**: 443 is occupied by VLESS Reality, so the API is served on 8443 with **DNS-01 (Cloudflare)** ACME challenge, which needs no inbound 80/443. This requires a custom Caddy build with the `caddy-dns/cloudflare` module (xcaddy build or a prebuilt image like `ghcr.io/iarekylew00t/caddy-cloudflare`).
- **DB migrations**: `pressly/goose/v3`, embedded into the Go binary via `//go:embed migrations/*.sql` + `goose.SetBaseFS`, run at service startup against Postgres via the pgx v5 stdlib driver.
- **Secrets/crypto**: `github.com/alexedwards/argon2id` for password hashing (tune Argon2 memory down on the 1 GB RAM host — see "Caveats" in the doc); AES-256-GCM (`crypto/aes` + `crypto/cipher`, 32-byte key from env, random nonce per message) for encrypting secret columns at rest (VLESS UUIDs, Hysteria2 passwords).
- **Target host constraints**: 1 vCPU / 1 GB RAM box also running Postgres, Xray, Hysteria2, and Caddy — this drives the reduced Argon2 memory recommendation and general resource caution.

Read `compass_artifact.md` in full before implementing any of the above — it contains exact struct definitions, example payloads, and a "Caveats" section (e.g. 3X-UI is officially "personal use" software per its README, Caddy 2.11.x had several CVEs fixed through 2.11.4, Cloudflare token env var name differs between prebuilt Caddy images) that matter for correctness.

## Testing

`.env` on this host points at the real 3x-ui panel and a real Hysteria2 reload command. **Live smoke tests and `make test` always use `.env.test`, never `.env`** — `.env.test` is committed (dummy XUI endpoint, no-op reload command, separate `vpn_test` database under its own low-privilege Postgres role) specifically so a test run can never provision a real client or restart the real Hysteria2 service. Run `make test` from the repo root, or `cd api && ENV_FILE=.env.test go test ./...` directly.
