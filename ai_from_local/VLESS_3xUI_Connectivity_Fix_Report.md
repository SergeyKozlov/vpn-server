# VLESS/3x-ui Connectivity Fix — Report

> Executed per `ai_from_local/TZ_VLESS_3xUI_Connectivity_Fix.md`, live on the production control-plane host (`92.60.75.196`), 2026-07-22.

## TL;DR

**Fixed.** `api` (bridge network `vpn-net`) couldn't reach the 3x-ui panel (`network_mode: host`) because `XUI_BASE_URL` pointed at `127.0.0.1`, which inside a bridge-network container is the container's own loopback, not the host's. Added `extra_hosts: host.docker.internal:host-gateway` to the `api` service and repointed `XUI_BASE_URL` at `host.docker.internal:2053` (Variant A from the TZ). Confirmed live: `POST /clients` now reaches the 3x-ui panel and successfully provisions/de-provisions a VLESS user. The request now fails one step later, at the **already-documented, separate** Hysteria2 config-write issue (`ai_from_local/Hysteria2_Reload_Diagnostic_Report.md`) — not touched here, out of this task's scope.

## Acceptance table

| # | Check | Result |
|---|---|---|
| 1 | `api` still not publishing ports to host / not `network_mode: host` | ✅ `docker compose config` — unchanged (`ports: 127.0.0.1:8080:8080`, `networks: vpn-net`), only `extra_hosts` added |
| 2 | `api` can reach the 3x-ui panel | ✅ Test `POST /clients` no longer fails with `connection refused`; the VLESS step now succeeds |
| 3 | 3x-ui panel responds as expected | ✅ No error logged for the `xui`/VLESS step; request proceeded to the next step (Hysteria2 sync) |
| 4 | Test client/admin cleaned up without trace | ✅ `admins` → 0 rows, `admin_sessions` cleared, `legacy_clients_phase1` → 0 rows (automatic rollback on the downstream Hysteria2 failure) |
| 5 | Reality/443, Hysteria2 UDP, SSH, Caddy/8443 untouched | ✅ `ss` before/after unchanged: `xray-linux-amd6` on `:443`, `hysteria` on UDP `:8443`, `caddy` on `:8443`, `sshd` on `:22`; `https://api.videcdn.net:8443/healthz` → `200` |
| 6 | `make test` green | ✅ `cd api && ENV_FILE=.env.test go test ./...` — all packages `ok` |
| 7 | Secrets not printed | ✅ No token/password values appear in this report |

## Discovery (§1 of the TZ)

- `docker network inspect` — actual (compose-project-prefixed) network name is `vpn_vpn-net`, gateway `172.18.0.1`, `api` container IP `172.18.0.3` (the TZ's draft commands used the short compose name `vpn-net`, which doesn't resolve directly with `docker network inspect` — noted for anyone re-running these commands).
- 3x-ui panel confirmed listening on `*:2053` and `*:2096` (all interfaces, not just loopback) — this is what makes `host.docker.internal`/gateway-IP reachability work without any change to the `3x-ui` service itself.
- `XUI_BASE_URL` was `http://127.0.0.1:2053` (structure/value known from this session; not a leaked secret, just a wrong host).
- `api`'s `extra_hosts` was empty (`[]`) before this fix — confirmed via `docker inspect`.
- `nft list ruleset` showed DNAT/accept/drop rules scoped to `172.18.0.2` (postgres, port 5432) and `172.18.0.3` (api, port 8080) — nothing blocking outbound traffic from the bridge subnet to the host's `2053`/`2096`. No `ufw`.

## Fix applied (§3 of the TZ) — Variant A

Files changed:
- **`docker-compose.yml`** — added to the `api` service:
  ```yaml
      extra_hosts:
        - "host.docker.internal:host-gateway"
  ```
- **`.env`** (production) — `XUI_BASE_URL` changed from `http://127.0.0.1:2053` to `http://host.docker.internal:2053`.
- **`.env.example`** — added a comment above `XUI_BASE_URL=changeme` explaining why `127.0.0.1` doesn't work once `api` is containerized separately from the host-networked `3x-ui`, and documenting the `host.docker.internal` convention.

Applied via `docker compose up -d api` — this also recreated `vpn-postgres` (compose detected the shared `env_file: .env` changed and recreated both dependents; brief restart, no data loss — same `pgdata` volume, came back `healthy` within the same `up` call). `caddy`, `3x-ui`, and `hysteria2` were not touched or recreated.

Variant B (raw gateway IP `172.18.0.1`) was not needed — Variant A worked on the first attempt.

## Test (§4 of the TZ)

Same throwaway-admin pattern as the Hysteria2 diagnostic (no `admins` rows existed beforehand either, since the prior diagnostic's throwaway admin was already cleaned up): created `diag-test-admin2` via `api/cmd/createadmin`, logged in via the real `POST /login`, called the real `POST /clients`.

**Before the fix** (from the earlier Hysteria2 diagnostic, for reference):
```
create client: add xui client: do request: Post "http://127.0.0.1:2053/panel/api/clients/add":
dial tcp 127.0.0.1:2053: connect: connection refused
```

**After the fix**, same call:
```
create client: sync hysteria users: read config: open /root/vpn/hysteria/config.yaml: no such file or directory
```

The error moved from the VLESS/3x-ui step to the Hysteria2 sync step — exactly as predicted in the TZ. This is the pre-existing, already-documented issue from `Hysteria2_Reload_Diagnostic_Report.md` (config path not mounted into the `api` container, among other issues) — **not fixed here, out of scope for this task**. `Service.Create`'s built-in rollback fired correctly: the VLESS user that was successfully added got removed again (no rollback-failure logged), and the DB row was deleted (`legacy_clients_phase1` → 0 rows after the test).

## Cleanup — confirmed

- Throwaway admin `diag-test-admin2` and its session: deleted (`admins` → 0 rows).
- Test client: rolled back automatically by `Service.Create` (0 rows in `legacy_clients_phase1`).
- Local scratch files (throwaway password, session cookie) removed from the scratchpad, never committed.

## What this does and doesn't fix

- **Fixed**: `api` → 3x-ui panel connectivity. `POST /clients` now gets past the VLESS half entirely.
- **Still broken, unchanged, tracked separately**: Hysteria2 config write/reload (`ai_from_local/Hysteria2_Reload_Diagnostic_Report.md`) — `POST /clients` still fails end-to-end because of that issue, which stopped at TZ §3.3 in the prior diagnostic (requires either a compose migration of Hysteria2 or accepting a privilege-escalation-equivalent mechanism, both out of bounds there). This task does not change that conclusion or its recommendation.

## UNKNOWNs

None outstanding for this task's scope.

## Files touched

- `docker-compose.yml` (added `extra_hosts` to `api`)
- `.env` (production — `XUI_BASE_URL` host changed)
- `.env.example` (documentation comment added)
- This report (new)
