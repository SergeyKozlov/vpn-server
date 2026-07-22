# Hysteria2 Reload/Provisioning Diagnostic Report

> Executed per `ai_from_local/TZ_Hysteria2_Reload_Diagnostic.md`, against `Architecture_Concept_VPN_Project.md` as the architectural source of truth (AC-3.2 EdgeProvisioner, AC-6.4 provisioning flow, AC-6.8 EdgeProvisioner interface). Run live on the production control-plane host (`92.60.75.196`), 2026-07-22.

## TL;DR

**Result: broken, stop at §3.3 — no fix applied in this task.** The live Hysteria2 process is a bare `systemd`-managed process entirely outside Docker; reaching it from the containerized `api` service would require privilege escalation (host PID namespace, Docker socket, or systemd control socket — all explicitly out of bounds for this task). Additionally, an **unrelated** bug (VLESS/3x-ui panel unreachable from `api`'s container network) currently blocks the admin `/clients` endpoint before it even reaches the Hysteria2 code path. **Self-registration does not provision Hysteria2 (or VLESS) credentials at all** — confirmed from code — so this is not blocking for existing users, but is squarely blocking for P2.4.

## Acceptance table

| # | Check | Result |
|---|---|---|
| 1 | Real process serving Hysteria2 UDP identified (PID, source, uptime) | ✅ PID 344297, `systemd` unit `hysteria-server.service` (not `hysteria2`), running since 2026-07-20 21:07 MSK (~1d18h at test time), config `/etc/hysteria/config.yaml` |
| 2 | Docker socket NOT mounted into `api` | ✅ Confirmed via `docker inspect vpn-api` — `Mounts: []` (no mounts at all, socket or otherwise) |
| 3 | Does self-registration call EdgeProvisioner/Hysteria2? | ✅ **NO** — confirmed by full call-chain trace (see §3 below) |
| 4 | End-to-end test: provisioning → config.yaml write → reload | ❌ Failed — blocked at the VLESS step (unrelated bug) before Hysteria2 sync was even reached; static analysis confirms Hysteria2 sync would also fail if reached |
| 5 | Test client cleaned up (DB + config.yaml) | ✅ Automatic — `clients.Service.Create`'s built-in rollback deleted the DB row on failure; nothing ever reached `config.yaml` (see §4) |
| 6 | Any fix stays within `api` container's existing privileges | ✅ N/A — no fix was applied |
| 7 | Live Hysteria2 traffic not disrupted | ✅ No restart/kill was performed; active-connections check (§2) done first |
| 8 | `make test` green | ✅ `cd api && ENV_FILE=.env.test go test ./...` — all packages `ok` |
| 9 | Reality/443, SSH untouched | ✅ `xray-linux-amd6` still listening on `:443` (PID 46147), `sshd` still listening on `:22`/`:22` (v6) |

## 1. Discovery findings

### 1.1 — Who's really serving Hysteria2 UDP
- `docker compose ps -a` shows compose's `hysteria2` service (`tobyxdd/hysteria:latest`) as **`Exited (0) 42 hours ago`** — not running, not serving traffic.
- The real listener on UDP `:8443` is PID **344297**, binary `/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml`, **not** launched by compose — its cgroup is `system.slice/hysteria-server.service`, a `systemd` unit (`/etc/systemd/system/hysteria-server.service`, `enabled`) that predates/bypasses the compose `hysteria2` service entirely. `systemctl status hysteria-server` confirms `active (running) since 2026-07-20 21:07:16 MSK`.
- **This means the `hysteria2` name in both the reload command and the systemd unit search from the original TZ hypothesis is a red herring** — there is no unit literally named `hysteria2`; the real one is `hysteria-server.service`.

### 1.2 — Active connections before any risky action
- `journalctl -u hysteria-server --since '10 min ago'` / `--since '3 hours ago'`: **no entries**. Last logged activity was a client (`id: "user"`) disconnecting at `2026-07-22T00:21:23+03:00`, ~15 hours before this diagnostic ran (15:20 MSK). No active sessions at test time — restarting would have been low-risk, but **no restart was performed or needed** (see §4).

### 1.3 — `HYSTERIA_RELOAD_COMMAND` / `HYSTERIA_CONFIG_PATH` structure
- `HYSTERIA_RELOAD_COMMAND` type: **`docker compose -f <path> restart <service-name>`** (6 shell tokens; literal command not printed). This targets the **compose service** `hysteria2` — which, per §1.1, is the *stopped, irrelevant* container, not the live systemd-managed process. Even if this command executed successfully, it would restart the wrong thing.
- `HYSTERIA_CONFIG_PATH=/root/vpn/hysteria/config.yaml` (path itself isn't a secret). This is the config file the *stopped compose container* would read (bind-mounted `./hysteria/` → `/etc/hysteria/` per `docker-compose.yml`'s `hysteria2` service) — **not** the file the live process reads.

### 1.4 — Does `api` see `HYSTERIA_CONFIG_PATH`, and is it even the right file?
- `docker inspect vpn-api --format '{{json .Mounts}}'` → **`[]`** — the `api` service has **zero volume mounts**, matching `docker-compose.yml` (no `volumes:` key on the `api` service at all). `HYSTERIA_CONFIG_PATH` is not visible inside the container.
- `api/Dockerfile` confirms the image is `gcr.io/distroless/static-debian12` with only `COPY vpn-api /vpn-api` and `COPY vpn-createadmin /createadmin` baked in — no config file, no shell, no `docker` binary. `docker compose exec api sh -c ...` fails outright: `exec: "sh": executable file not found in $PATH`.
- **New finding beyond the original TZ hypothesis**: even setting aside the missing mount, `/root/vpn/hysteria/config.yaml` (`HYSTERIA_CONFIG_PATH`) and `/etc/hysteria/config.yaml` (what the live process actually reads) are **two entirely different files** — different inodes, different sizes (122 vs 333 bytes), different mtimes (2026-07-21 16:42 vs 2026-07-08 01:27), and materially different content (different TLS cert paths, live one has `masquerade`/`bandwidth` sections the other lacks). Writing to `HYSTERIA_CONFIG_PATH` — even with a correct mount — would **never** reach the live process's actual config. The mount target and the reload target both need to point at `/etc/hysteria/config.yaml`, not `/root/vpn/hysteria/config.yaml`.

### 1.5 — Docker socket exposure to `api`
- Confirmed **not mounted** (see §1.4's empty `Mounts` array — covers this too). Safe as expected.

### 1.6 — Real provisioning call chain, and self-registration vs. EdgeProvisioner

Code path from HTTP to Hysteria2 reload (all confirmed by direct grep + read, live on the host):
```
POST /clients  (admin-only, RequireAuth)
  → api/internal/api/clients.go:33 createClientHandler
  → api/internal/clients/service.go:48 Service.Create
      → s.vless.AddUser(...)                          (3x-ui panel HTTP call)
      → s.syncHysteriaUsers(ctx)  (service.go:136)
          → SELECT ... FROM legacy_clients_phase1 WHERE enabled = true
          → s.h2.SyncUsers(ctx, users)  (provisioner/hysteria2.go:56)
              → hysteria.SyncUsers(ctx, configPath, users, reloadCommand)  (hysteria/reload.go:32)
                  → LoadConfig(configPath)   [os.ReadFile]
                  → cfg.SetUsers(users); cfg.Save(configPath)  [os.WriteFile]
                  → Reload(ctx, reloadCommand)  [exec.CommandContext("sh","-c",command)]
```
**This is the only HTTP route that reaches `Hysteria2Provisioner.SyncUsers`/`Reload`.** No public `DELETE /clients/{id}` route is registered — `deleteClientRow` (`service.go:167`) exists only as a private rollback helper inside `Create()`.

**Self-registration (`POST /api/v1/auth/register`) — confirmed NOT connected to EdgeProvisioner:**
- Handler (`api/internal/api/user_auth.go:27-60`) calls only `usersSvc.Register(...)`.
- `users.Service.Register` (`internal/users/service.go:63`) does a single `INSERT INTO users (...)` — grepping `internal/users/service.go` for `clients\.|provisioner\.|hysteria|SyncUsers|EdgeProvisioner` returns **zero matches**.
- Wiring in `cmd/api/main.go:66` constructs `usersSvc := users.NewService(pool, userSessions)` — only `pool` and `userSessions`, no `clientsSvc`, no `vlessProvisioner`, no `h2Provisioner`. It is architecturally impossible for `Register` to reach provisioning code.
- **Conclusion**: registering a user today creates a `users` row (email/password/trial) and nothing else. Nobody who self-registers gets a VLESS UUID or Hysteria2 password. **The `users` table and the `legacy_clients_phase1` table (driving `/clients`) are two disconnected systems right now.**
- **Impact on priority**: not blocking for anyone using the system today (no live user depends on self-registration → credentials, because that link doesn't exist yet). **Directly blocking for P2.4**, whose bootstrap flow is expected to hand a newly registered client real, working Hysteria2/VLESS credentials — that hand-off has no code path today, and even if it did, it would run into every issue documented in §1.1–§1.4 above.

## 2. End-to-end test (§2 of the TZ)

Per the TZ, cleanup must go through the existing code path or, if none exists, a scoped raw DELETE — no `DELETE /clients/{id}` route exists (§1.6), and there was also no admin account at all to authenticate with (`SELECT count(*) FROM admins` → 0 rows before this diagnostic). To exercise the *real* HTTP path rather than bypass it, this diagnostic used the project's own existing bootstrap tool, `api/cmd/createadmin` (comment: *"Run once, manually, on the server... there is no public registration endpoint"*), to create a throwaway admin (`diag-test-admin`, random password), logged in via the real `POST /login`, and called the real `POST /clients` with the resulting session cookie.

**Result: `500 Internal Server Error`, `{"error":"failed to create client"}`.**

`api` logs pinpoint the cause:
```
create client: add xui client: do request: Post "http://127.0.0.1:2053/panel/api/clients/add":
dial tcp 127.0.0.1:2053: connect: connection refused
```

**This is a separate, unrelated bug**, not the one this TZ targets: after containerizing `api` onto the bridge network `vpn-net` (see `7c72fa4` hardening commit), `127.0.0.1:2053` inside the `api` container refers to the container's own loopback — not the host, where 3x-ui actually listens (`network_mode: host`). The VLESS/3x-ui panel is unreachable from `api` at all right now. Since `Service.Create` calls `s.vless.AddUser` **before** `s.syncHysteriaUsers`, the flow fails and rolls back before the Hysteria2 code is ever reached.

**Net effect: `POST /clients` is completely non-functional right now — for both VLESS and Hysteria2 — regardless of anything in this TZ's scope.** This is a prerequisite bug for testing Hysteria2 reload live, and is out of this task's fix scope (TZ §0 restricts fixes to "the reload/config-write path", not panel connectivity). Flagged here for visibility; not fixed.

Because the live path couldn't reach the Hysteria2 code, this diagnostic relies on **static verification**, which is conclusive given what was already found in §1.4/§1.5:
- `os.ReadFile(HYSTERIA_CONFIG_PATH)` inside `LoadConfig` **would fail** — the path isn't mounted (`Mounts: []`) and isn't baked into the distroless image (Dockerfile only `COPY`s the two binaries).
- Even if it succeeded, `Reload()`'s `exec.CommandContext(ctx, "sh", "-c", command)` **would fail** — there is no `sh` in the image (confirmed via failed `docker compose exec`).
- Even if a shell existed, the configured reload command targets the wrong service (§1.1/§1.3) — the stopped compose container, not the live `hysteria-server.service` process.

So: **config write → NO. Reload → NO. This confirms the exact concern raised in `Hardening_Deploy_Report.md`, plus two additional problems it hadn't identified** (wrong config file target, wrong reload target).

## 3. Fix (§3 of the TZ) — not applied, stopped at §3.3

**3.1 (volume mount)**: technically straightforward — mount host `/etc/hysteria/config.yaml` (the file the live process actually reads, *not* `HYSTERIA_CONFIG_PATH`'s current value) into the `api` container at the path `HYSTERIA_CONFIG_PATH` expects. This alone would fix the *write* half.

**3.2 (reload mechanism)**: cannot be done within bounds. The live Hysteria2 process is a bare host `systemd` unit, entirely outside Docker — there is no container, network namespace, or socket shared with `api` at all. Every mechanism considered requires privilege escalation explicitly forbidden by the TZ:
- Signaling the PID directly (`kill -HUP`) requires either a shared PID namespace or `CAP_SYS_PTRACE` across namespaces — neither present, both forbidden.
- `systemctl restart` from inside the container requires either a D-Bus/systemd control socket (`/run/systemd/private`) mounted in, or the host's `docker.sock` — both are privilege-escalation-equivalent to what's explicitly forbidden, even though not named verbatim in the TZ's list.
- There is no way to reach a bare host systemd service from an unprivileged, network-isolated container short of one of the above.

**Decision: do not apply even 3.1 in isolation.** Reasoning: since 3.2 is unconditionally blocked, applying 3.1 alone would not achieve a working end-to-end fix — and it introduces a **new risk** that doesn't exist today. Currently, `LoadConfig` fails *before* any write happens (fails safe, no drift possible). If 3.1 were applied without 3.2, a future successful `Save()` followed by a failing `Reload()` would leave `/etc/hysteria/config.yaml` — the file the live process actually reads — silently rewritten with a stale/orphaned test user, while `Create()`'s automatic rollback deletes the DB row and VLESS user but has no way to undo the config file write. That would convert today's clean, fail-safe rejection into silent config drift on the production Hysteria2 config. Given 3.2 can't be completed in this task, shipping 3.1 alone would be a net risk increase with no corresponding benefit (and `/clients` is unusable today anyway due to the unrelated VLESS bug in §2, so nothing is unblocked by 3.1 today regardless).

**→ Stop at §3.3, per the TZ's own boundary.**

### Recommendation for a separate task
1. **Migrate Hysteria2 into compose** (already flagged as backlog item in `VPN_Project_Status_and_ADR.md` §4) is the cleanest real fix — puts `api` and `hysteria2` on a shared Docker network, letting a sidecar-style signal/HTTP reload replace the current shell-exec design entirely, and eliminates the "two different config files" split found in §1.4. This also resolves the VLESS/3x-ui `127.0.0.1:2053` connectivity bug found in §2 as a side effect (same containerization/networking root cause).
2. Scope estimate: moderate — needs (a) importing the live `/etc/hysteria/config.yaml` and its TLS certs into the compose-managed `./hysteria/` tree without losing the `masquerade`/`bandwidth` settings only present in the live file, (b) a cutover window (brief traffic interruption acceptable per current low usage — see §1.2), (c) updating both `HYSTERIA_CONFIG_PATH` and the reload command, (d) fixing `XUI_BASE_URL`/panel reachability for the same networking reason.
3. Until that lands, `POST /clients` should be treated as **non-functional** for both protocols — worth a heads-up outside this report, since it affects normal admin operations today, not just the P2.4 roadmap item.
4. Does this block P2.4? **Yes**, directly — P2.4's bootstrap flow needs working Hysteria2 (and VLESS) provisioning to hand real credentials to newly registered users; none of that works right now for *any* client, admin-created or self-registered.

## 4. Test artifact cleanup — confirmed

- Throwaway admin `diag-test-admin`: created via `api/cmd/createadmin`, used for one login + one `/clients` call, then deleted (`admin_sessions` row and `admins` row both removed; `SELECT count(*) FROM admins` → 0 afterward).
- Test client: `Service.Create`'s own rollback (`deleteClientRow`) fired automatically on the VLESS failure — `SELECT ... FROM legacy_clients_phase1` → 0 rows, no orphaned client ever existed.
- No write ever reached either `config.yaml` (`/etc/hysteria/config.yaml` or `/root/vpn/hysteria/config.yaml`) — confirmed no `hy_`/`diag` strings in either file post-test.
- Scratch files holding the throwaway password/session cookie were deleted from the local scratchpad, not committed anywhere.
- No files changed: `docker-compose.yml`, `.env`, `.env.example` all untouched (see git status below).

## 5. UNKNOWNs

- Whether `HYSTERIA_RELOAD_COMMAND`/`HYSTERIA_CONFIG_PATH` were ever correct at some earlier point (e.g., before `api` was containerized, when it may have run directly on the host and could reach both files/commands) — not verified; out of scope to reconstruct historically.
- Exact scope/effort of fixing the VLESS/3x-ui `127.0.0.1:2053` connectivity bug found in §2 — flagged, not investigated further (out of this TZ's scope).
- Whether Hysteria2 (`app/hysteria`, the `tobyxdd/hysteria` binary/image in use) supports a config hot-reload signal at all (e.g., `SIGHUP`) was not empirically tested, since no in-bounds delivery mechanism exists regardless — moot for this task, but worth checking when scoping the compose-migration follow-up task.

## Files touched by this task

None — this was diagnosis-only, per the §3.3 stop decision. No changes to `docker-compose.yml`, `.env`, `.env.example`, or any application code. Only this report is new.
