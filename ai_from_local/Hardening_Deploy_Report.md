# Hardening Deploy Report — api hardening pre-P2.4

Executed per `ai_from_local/TZ_Hardening_Deploy.md`, 2026-07-22, on the live control-plane host (`92.60.75.196`).

## Summary

`api` is now a docker-compose-managed service, reachable only via Caddy/TLS (`https://api.videcdn.net:8443`). It is no longer bound to `0.0.0.0` on any port. All four orphaned bare `vpn-api*` processes from the P2.3 session are killed. The temporary admin (`admin`/`admin2026`) and its 3 sessions are removed. `443`/Reality, Hysteria2 UDP, and SSH are all confirmed unaffected. `make test` (`.env.test`, isolated `vpn_test` DB) is green.

## Discovered topology (§2) — and why the path deviates from the TZ's default

The TZ's Path-A trigger condition ("Caddyfile already says `reverse_proxy api:8080`, a docker-service name") **did not hold**. Actual state:

- `docker-compose.yml` had 4 services: `3x-ui`, `postgres`, `hysteria2`, `caddy`. **`3x-ui`, `hysteria2`, and `caddy` all run `network_mode: host`** — none of them sits on a docker bridge network.
- `Caddyfile`: `reverse_proxy 127.0.0.1:8080` — host loopback, not a docker DNS name. This is consistent with Caddy running host-networked.
- Only `postgres` was on a bridge network (`vpn-net`), and it's *also* published to the host at `127.0.0.1:5432:5432` — that's the established "containerized but not internet-facing" pattern already in this repo.
- `api` was not in compose at all: 4 unmanaged bare processes, not the 2 the TZ named — `api` (`PORT=18080`), `vpn-api-p23` (`PORT=8090`), `vpn-api-new` (`0.0.0.0:8080`), `vpn-api` (`0.0.0.0:8099`) — all orphaned (reparented to PID 1), all leftovers from the P2.3 session (build cache / scratchpad dirs).
- `DATABASE_URL` in `.env`/`.env.example` pointed at `localhost:5432`.
- No `ufw` binary (`rc` — removed, config remnants only); leftover `ufw-*` iptables chains are all empty; `INPUT` policy `ACCEPT`. Only active protection: `fail2ent`'s `f2b-sshd` (ban-based, not an allowlist). **Confirmed live**: `curl http://92.60.75.196:8080/healthz` returned `200` from outside the loopback/docker context before this task's cleanup.
- No existing `Dockerfile` anywhere in the repo.
- Host resources: `free -h` → **77 MB free / 258 MB available**, 1 vCPU — informed the build strategy (below).

**Decision: still Path A, adapted to match the real topology** — containerize `api`, join it to `vpn-net` (so it can reach `postgres` by service name), and publish it to the host **only** as `127.0.0.1:8080:8080` (mirroring `postgres`'s existing pattern), instead of the TZ's literal "`expose:`-only, Caddy reaches it via docker DNS name `api:8080`" — because Caddy is host-networked and cannot resolve bridge-only container names. This achieves the same goals (not on `0.0.0.0`, compose-managed, reachable by Caddy) with the smallest change relative to the working infra, and avoids the much riskier alternative of moving Caddy off host networking.

## Build strategy: binaries built on host, not inside the image

With 77 MB free RAM, compiling Go inside a fresh `golang:1.26-alpine` build stage (module download + compile) alongside Postgres/Xray/Hysteria2/Caddy/3x-ui was judged too likely to OOM. Chose the TZ's own explicitly-allowed fallback (§4.1): build `vpn-api` and `vpn-createadmin` on the host with the already-present Go 1.26.5 toolchain (`make build-api`), and use a copy-only `api/Dockerfile` into `gcr.io/distroless/static-debian12`. Verified with a standalone `docker build` before wiring into compose.

## Files changed

| File | Change |
|---|---|
| `api/Dockerfile` | New. Copy-only distroless image (`vpn-api` + `vpn-createadmin`), `EXPOSE 8080`. |
| `docker-compose.yml` | New `api` service: `build: ./api`, `networks: [vpn-net]`, `ports: ["127.0.0.1:8080:8080"]` (no `0.0.0.0` binding, no `network_mode: host`), `depends_on: postgres: condition: service_healthy`, `env_file: .env`, `restart: unless-stopped`. |
| `.env` | `DATABASE_URL` host changed `localhost:5432` → `postgres:5432` (docker-service name; credentials unchanged). Not committed (gitignored). |
| `.env.example` | Same `DATABASE_URL` change, with a comment explaining the docker-network vs. bare-process distinction. |
| `Makefile` | Added `build-api` target (the two `go build` invocations). |
| `.gitignore` | Added `api/vpn-createadmin` (alongside the existing `api/vpn-api` entry). |
| `Caddyfile` | **Unchanged** — already correctly configured for the `127.0.0.1:8080` topology. |

No application code under `api/internal` or `api/cmd` was modified.

## Unplanned issue found and fixed during rollout: api container started without a network attachment

First `docker compose up -d --build api` failed with `address already in use` for `127.0.0.1:8080` (a bare stray process — `vpn-api-new` — still held the port). Compose left a `Created`-but-not-network-attached `vpn-api` container behind despite the failure. After freeing the port, a plain `docker compose up -d api` started that same half-created container rather than recreating it — it came up with **no network attached at all**, fell back to the host's own `/etc/resolv.conf` (`nameserver 8.8.8.8`), and crash-looped trying to resolve `postgres` (`dial udp 8.8.8.8:53: connect: network is unreachable`, since raw internet is unreachable from inside the container's isolated netns in this state).

Fix: `docker compose rm -f api && docker compose up -d api` forced a clean recreation, which attached correctly to `vpn_vpn-net` (assigned `172.18.0.3`), resolved `postgres` correctly via the embedded DNS (`127.0.0.11`), ran goose migrations (no-op, confirmed still at version `12`), and started listening. Confirmed via `/healthz` returning `200` both locally (`127.0.0.1:8080`) and through Caddy (`https://api.videcdn.net:8443`).

*(Secondary, unrelated finding surfaced while diagnosing this: a one-off `docker run --network vpn_vpn-net busybox nslookup postgres` intermittently returns `NXDOMAIN` unless the DNS server is passed explicitly — an apparent musl-libc/`ndots:0`/search-domain interaction quirk in ad-hoc `docker run` containers. It did not affect the compose-managed `api` container once properly attached, and needed no fix here — noted for awareness only.)*

## Correction to the TZ's literal SQL (§8): FK delete order

`admin_sessions.user_id` has a real `REFERENCES admins(id)` foreign key with **no `ON DELETE CASCADE`** (migration `00012_admin_sessions_split.sql`). There were 3 live session rows for the temp admin. The TZ's literal snippet deletes `admins` before `admin_sessions`, which would raise a foreign-key violation. Executed in the correct order instead: `admin_sessions` first (3 rows deleted), then `admins` (1 row deleted). Verified `count(*) FROM admins WHERE username='admin'` = `0`.

## Documented (not executed): permanent-admin creation procedure

`cmd/createadmin` already exists (`-u`, `-p` flags, `DATABASE_URL` env, argon2id hashing via `internal/password`) and is now shipped in the `api` image as `/createadmin`. When the admin panel work actually needs a permanent admin:

```bash
docker compose run --rm --no-deps --entrypoint /createadmin api -u <username> -p '<strong-password>'
```

Run this from an operator's own terminal on the server; the password must be typed directly at that prompt or sourced from a secret manager — **never** pasted into a Claude Code chat message, which is the exact mistake this task is cleaning up. Not executed as part of this task, per the TZ (no admin panel yet, not needed for P2.4).

## Acceptance table (TZ §9)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | api not on `0.0.0.0` | **PASS** | `ss -tlnp` → only `127.0.0.1:8080` via `docker-proxy`; no `0.0.0.0:8080`/`:8099` anywhere |
| 2 | External direct access to api closed | **PASS** | `curl -m4 http://92.60.75.196:8080/healthz` → `Failed to connect... Couldn't connect to server`; same for `:8099` |
| 3 | API through Caddy/TLS | **PASS** | `curl https://api.videcdn.net:8443/healthz` → `200` |
| 4 | Reality/443 intact | **PASS** | `ss -tlnp \| grep :443` → `xray-linux-amd6` still listening, untouched |
| 5 | Hysteria2 UDP intact | **PASS** (with a WARN, see below) | `ss -ulnp \| grep 8443` → `hysteria` process still listening throughout; unaffected by this task |
| 6 | No stray processes | **PASS** | `ps aux` shows only the containerized `/vpn-api` process; all 4 bare `PORT=18080/8090/8080/8099` processes killed |
| 7 | api is a managed service | **PASS** | `docker compose ps api` → `Up`, `restart: unless-stopped`; survives `docker compose restart` |
| 8 | Temp admin removed | **PASS** | `SELECT count(*) FROM admins WHERE username='admin'` → `0` |
| 9 | Firewall | **WARN** (by design — documented only, not enabled) | See below |
| 10 | Regression: `make test` | **PASS** | `make` binary isn't installed on host; ran the CLAUDE.md fallback directly: `ENV_FILE=.env.test go test ./... -count=1` → all packages `ok`, isolated `vpn_test` DB, uncached |
| 11 | SSH intact | **PASS** | `who` shows the same session still connected throughout; `sshd` still listening on `22` |

### #9 firewall detail (WARN, by design)

No active firewall (`ufw` package `rc`/removed, no binary; leftover `ufw-*` iptables chains are empty; `INPUT` policy `ACCEPT`). 8080/8099 are closed now as a *side effect* of no longer being bound/published anywhere — not because of a firewall rule. Per the TZ (§7) and an explicit check with the user during planning, **no firewall was enabled** in this task (risk of self-inflicted SSH lockout). Proposed ruleset for a future, separately-approved step:

```
ufw default deny incoming
ufw allow 22/tcp
ufw allow 443/tcp
ufw allow 8443/tcp
ufw allow 8443/udp   # Hysteria2, from hysteria/config.yaml `listen: :8443`
ufw enable
```

## Known limitations / deferred items

1. **Hysteria2 config-reload from inside the `api` container is broken.** `HYSTERIA_RELOAD_COMMAND` is `exec.CommandContext(ctx, "sh", "-c", command)` (`internal/hysteria/reload.go`) run inside whatever process/container `api` itself is in. Now that `api` is containerized: `systemctl restart hysteria2` fails outright (no systemd in the container); `docker restart hysteria2`/`docker compose restart hysteria2` would need the host's Docker socket bind-mounted into the `api` container, which is a real container-escape-adjacent security tradeoff. **Per TZ §11, this is logged as a known limitation and deferred to a separate task** — it does not block P2.4 (P2.4 is the client bootstrap flow, not Hysteria2 provisioning). The current `.env`'s `HYSTERIA_RELOAD_COMMAND` value was left as-is (not verified to actually work post-containerization).
2. **Pre-existing, unrelated to this task: the `hysteria2` compose service itself is `Exited` (has been for ~37h, since well before this session).** Live Hysteria2 UDP traffic on `:8443` is currently served by a **bare host process** (PID 344297) that predates this session, not by the compose-managed container. This is the same "unmanaged bare process" pattern this whole task addressed for `api`, but for Hysteria2 — out of scope here (TZ was scoped to `api` only), flagged as a WARN for a future, separate cleanup task.
3. `.env` has a dead `SESSION_SIGNING_KEY` entry (confirmed unused in code per `P2.2_Serverside_Sessions_Report.md`) — harmless, left untouched, noted for a future housekeeping pass.
4. The musl-libc/`ndots` DNS quirk noted above (ad-hoc `docker run --network ... busybox nslookup <name>` intermittently `NXDOMAIN`s without an explicit DNS server argument) — did not affect the actual `api` container once properly network-attached; not investigated further as it's outside this task's scope.

## UNKNOWN

- Whether `HYSTERIA_RELOAD_COMMAND`'s current value (not printed here — contains no secret material itself, but left unverified) would actually work if invoked today; not exercised during this task (no config-affecting provisioning call was made).
