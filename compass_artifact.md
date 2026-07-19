# Technical Reference for VPN-Project Phase 1 (Server-Side) — 2026 Current Specifics

## TL;DR
- The 3X-UI panel (MHSanaei/3x-ui, v3.x as of 2026 — latest v3.3.1, published June 12, 2026, with v3.5.0 container images present) exposes a cookie/Bearer-token HTTP API under `{webBasePath}/panel/api/inbounds/*`; the session cookie is literally named `3x-ui`, login is `POST {webBasePath}/login`, and the `webBasePath` prefix applies to EVERY route.
- Hysteria2 (apernet/hysteria, latest release `app/v2.10.0`, released 2026-07-13) natively supports multiple distinct per-user credentials only via `auth.type: userpass` (a `username: password` map); `type: password` is a single shared secret, and `type: http` delegates to an external endpoint.
- Caddy v2 (latest v2.11.4) can serve on port 8443 while still getting a Let's Encrypt cert via the DNS-01 Cloudflare challenge — which sidesteps the occupied 443 — but requires a custom build that includes `caddy-dns/cloudflare`.

## Key Findings

### Current versions (as of July 19, 2026)
- **3X-UI**: v3.x series. Per ReleaseAlert tracking of MHSanaei/3x-ui, the latest version is **v3.3.1, published June 12, 2026** (repo ~40.5K stars); the GHCR package listing confirms container tag `ghcr.io/mhsanaei/3x-ui:v3.5.0` images are present. Module path migrated to `/v3`. Docker image `ghcr.io/mhsanaei/3x-ui:latest`.
- **Hysteria2**: `app/v2.10.0`, confirmed on the apernet/hysteria GitHub Releases page as the top/most-recent release (released 2026-07-13; repo ~22.1K stars). Docker image `tobyxdd/hysteria`.
- **Caddy**: v2.11.4 (released 2026-06-03). The 2.11.x line shipped several CVE fixes — per the caddyserver/caddy v2.11.1 release notes, six CVEs were patched (CVE-2026-27585 through CVE-2026-27590), e.g. "caddytls: CVE-2026-27586 … TLS client authentication silently fails open when CA certificate file is missing or malformed" and "caddyhttp: CVE-2026-27588 … The Host matcher becomes case-sensitive for large host lists (>100), enabling host-based route/auth bypass." A later advisory (GHSA-j8px-rmrx-76h9, published Jul 10, 2026) disclosed three more vulnerabilities in v2.11.3 (rewrite placeholder re-expansion, unbounded body buffer DoS, fileHidden case-sensitivity bypass) resolved in **v2.11.4** — so pin to v2.11.4+.
- **pressly/goose**: v3 (`github.com/pressly/goose/v3`).
- **alexedwards/argon2id**: current, wraps `golang.org/x/crypto/argon2`.

---

## Details

### 1. 3X-UI Panel API (mhsanaei/3x-ui, v3.x)

**Base URL construction — the webBasePath gotcha.** The configurable "web base path" (`WebBasePath` setting) prefixes ALL routes, including login and the entire API. It is registered as a Gin route group in `web/web.go` (`g := engine.Group(basePath)`), under which the index controller (`/login`, `/logout`, `/`), the panel controller (`/panel/...`), and the API controller (`/panel/api/...`) are all mounted.

If `webBasePath = /xyzsecret/`, then:
- Login: `POST https://host:port/xyzsecret/login`
- Add client: `POST https://host:port/xyzsecret/panel/api/inbounds/addClient`
- Inbound list: `GET https://host:port/xyzsecret/panel/api/inbounds/list`

The py3xui SDK README states this explicitly (verbatim): "If you're using a custom URI Path, ensure that you've added it to the host, for example: If your host is http://your-3x-ui-host.com:2053 and the URI Path is /test/, then the host should be http://your-3x-ui-host.com:2053/test/. Otherwise, all API requests will fail with a 404 error." Configure your Go client with the base path as an env var (e.g. `XUI_BASE_URL=https://host:port/xyzsecret`).

**Authentication (login).** Endpoint: `POST {webBasePath}/login`. The `LoginForm` struct (`web/controller`) is:
```go
type LoginForm struct {
    Username      string `json:"username"      form:"username"`
    Password      string `json:"password"      form:"password"`
    TwoFactorCode string `json:"twoFactorCode" form:"twoFactorCode"`
}
```
Both `json:` and `form:` tags are present, so the endpoint accepts either `application/x-www-form-urlencoded` or `application/json` (Gin's `ShouldBind` picks based on Content-Type). Form-encoded is the most widely used in practice:
```bash
curl -c cookies.txt -X POST 'https://host:port/xyzsecret/login' \
  -d 'username=admin&password=secret'
# If 2FA enabled: add -d 'twoFactorCode=123456'
```

**Session cookie.** On success the panel sets a cookie literally named **`3x-ui`** (verified in `web/web.go`: `engine.Use(sessions.Sessions("3x-ui", store))`). It is `HttpOnly`, `SameSite=Lax`, `Path=basePath`. The `_xui_session` name seen in some 2026 bug reports and the generic `session` label in tutorials are NOT what the shipped code emits — use `3x-ui`. Cookie expiry is governed by the `SessionMaxAge` setting (in minutes; code converts to seconds as `sessionMaxAge*60`). If `SessionMaxAge <= 0` no MaxAge is set (browser-session cookie). Re-login when the cookie expires or when a request returns 401/the HTML login page.

**API Token (Bearer) — preferred for automation.** v3.x adds Settings → Security → API Token. All `/panel/api/*` endpoints honor both cookie auth and `Authorization: Bearer <token>`. Bearer skips CSRF and avoids session-expiry churn — recommended for a backend service. Built-in Swagger lives at `{webBasePath}/panel/api-docs` and OpenAPI JSON at `{webBasePath}/panel/api/openapi.json`.

**API route table** (base `{webBasePath}/panel/api/inbounds`):
| Method | Path | Action |
|---|---|---|
| GET | `/list` | List all inbounds |
| GET | `/get/:id` | Get inbound by id |
| GET | `/getClientTraffics/:email` | Client traffic by email |
| GET | `/getClientTrafficsById/:id` | Client traffic by UUID |
| POST | `/add` | Add inbound |
| POST | `/del/:id` | Delete inbound |
| POST | `/update/:id` | Update inbound |
| POST | `/addClient` | Add client to inbound |
| POST | `/:id/delClient/:clientId` | Delete client by clientId (UUID) |
| POST | `/updateClient/:clientId` | Update client by clientId (UUID) |
| POST | `/:id/resetClientTraffic/:email` | Reset one client's traffic |
| POST | `/clientIps/:email` | Get client IPs |
| POST | `/clearClientIps/:email` | Clear client IPs |
| POST | `/resetAllTraffics` | Reset all inbound traffics |

**Standard response envelope** (all `/panel/api/*` handlers return `entity.Msg`):
```go
type Msg struct {
    Success bool   `json:"success"`
    Msg     string `json:"msg"`
    Obj     any    `json:"obj"`
}
```

**Add client — exact payload.** `POST {webBasePath}/panel/api/inbounds/addClient`, `Content-Type: application/json`. The `settings` field is an **escaped JSON string** (NOT a nested object) containing the `clients` array. Sending clients as a raw nested object causes the classic `"unexpected end of JSON input"` error.
```json
{
  "id": 1,
  "settings": "{\"clients\":[{\"id\":\"95e4e7bb-7f3e-4a1e-9d6a-0b2c3d4e5f60\",\"email\":\"user_ab12cd\",\"flow\":\"xtls-rprx-vision\",\"enable\":true,\"expiryTime\":1767225600000,\"limitIp\":2,\"totalGB\":107374182400,\"tgId\":\"\",\"subId\":\"sub_ab12cd\",\"reset\":0}]}"
}
```
Field notes for each client object (from `database/model` `Client`): `id` = the VLESS UUID; `email` = unique identifier (any unique string, not a real email); `flow` = `xtls-rprx-vision` for VLESS Reality Vision (empty string for others); `enable` bool; `expiryTime` = **epoch milliseconds** (0 = never; negative values are used for "duration from first use" semantics); `limitIp` = max concurrent IPs (0 = unlimited); `totalGB` = **bytes** (0 = unlimited; 107374182400 = 100 GiB); `tgId` = Telegram id string; `subId` = subscription group id; `reset` = traffic reset period in days (0 = never).

**Update client.** `POST {webBasePath}/panel/api/inbounds/updateClient/{uuid}` where `{uuid}` is the client's existing UUID. Payload is identical in shape to addClient (`id` = inbound id, `settings` = escaped JSON string with the full updated client object):
```json
{
  "id": 1,
  "settings": "{\"clients\":[{\"id\":\"95e4e7bb-7f3e-4a1e-9d6a-0b2c3d4e5f60\",\"email\":\"user_ab12cd\",\"flow\":\"xtls-rprx-vision\",\"enable\":true,\"expiryTime\":1769817600000,\"limitIp\":2,\"totalGB\":214748364800,\"tgId\":\"\",\"subId\":\"sub_ab12cd\",\"reset\":0}]}"
}
```

**Delete client.** `POST {webBasePath}/panel/api/inbounds/{inboundId}/delClient/{clientId}` where `{clientId}` is the client UUID (for VLESS/VMess) — confirmed path pattern `/:id/delClient/:clientId`. No body required.

**Per-client traffic stats.** `GET {webBasePath}/panel/api/inbounds/getClientTraffics/{email}` or `.../getClientTrafficsById/{uuid}`. Returns the envelope with `obj` populated from `xray.ClientTraffic`:
```go
type ClientTraffic struct {
    Id         int    `json:"id"`
    InboundId  int    `json:"inboundId"`
    Enable     bool   `json:"enable"`
    Email      string `json:"email"`
    Up         int64  `json:"up"`         // bytes uploaded
    Down       int64  `json:"down"`       // bytes downloaded
    Total      int64  `json:"total"`      // byte quota (0 = unlimited)
    ExpiryTime int64  `json:"expiryTime"` // epoch ms
    Reset      int    `json:"reset"`
    // v3.x also exposes UUID, SubId (gorm:"-"), AllTime, LastOnline
}
```
Example response:
```json
{"success":true,"msg":"","obj":{"id":1,"inboundId":1,"enable":true,"email":"user_ab12cd","up":524288000,"down":1048576000,"total":107374182400,"expiryTime":1767225600000,"reset":0}}
```
Note `getClientTrafficsById` may return an array in `obj` (a client UUID can exist across multiple inbounds).

**Inbound list.** `GET {webBasePath}/panel/api/inbounds/list` returns `obj` as an array of inbounds; each inbound's `settings` and `clientStats` (array of `ClientTraffic`) let you enumerate clients.

**Gotchas summary.** (a) Always include the `webBasePath` prefix. (b) Prefer Bearer token to avoid cookie expiry. (c) `settings` is a stringified JSON, not an object. (d) `Content-Type: application/json` for the `addClient`/`updateClient` POSTs. (e) `expiryTime` and `totalGB` are in ms and bytes respectively. (f) Disabling a client via API may require an Xray restart for active sessions to drop.

---

### 2. Hysteria2 Server Native Authentication (app/v2.10.0)

Full `auth:` block from the official server config docs:
```yaml
auth:
  type: password | userpass | http | command   # type selector
  password: your_password                       # for type: password
  userpass:                                     # for type: userpass
    user1: pass1
    user2: pass2
    user3: pass3
  http:                                         # for type: http
    url: http://your.backend.com/auth
    insecure: false
  command: /etc/some_command                    # for type: command
```

**Which type supports MULTIPLE distinct per-user credentials natively without an external service?** Only **`type: userpass`**. It is a YAML map of `username: password` pairs — each user gets distinct credentials, enforced natively by the server with no external dependency. (The client must supply `auth: username:password` in that combined form; and in a `hysteria2://` URI the userinfo is `username:password`.)

- **`type: password`**: a single shared secret across all clients — NOT per-user. Suitable only if you differentiate users elsewhere.
- **`type: http`**: delegates to an external HTTP endpoint (see below) — supports arbitrary per-user logic but requires you to run the external service.
- **`type: command`**: runs an external command; the command prints the client's unique id to stdout and exits 0 to allow.

**HTTP auth request/response contract.** When `type: http`, the server sends a `POST` to `url` with JSON body on each connection attempt:
```json
{
  "addr": "123.123.123.123:44556",
  "auth": "the_client_supplied_auth_string",
  "tx": 123456
}
```
- `addr` = client IP:port; `auth` = the credential string the client sent; `tx` = client's declared tx (bandwidth) rate.
- The endpoint MUST return HTTP status **200** for success. Expected JSON response:
```json
{ "ok": true, "id": "unique_user_identifier" }
```
`ok` boolean = allow/deny; `id` = the unique identifier used for traffic stats/online tracking.

**Full minimal multi-user server config (recommended for this project):**
```yaml
listen: :8444          # UDP; keep off 443 if VLESS/other occupies it
tls:
  cert: /etc/hysteria/cert.pem
  key: /etc/hysteria/key.key
auth:
  type: userpass
  userpass:
    user_ab12cd: s3cretPass1
    user_ef34gh: s3cretPass2
masquerade:
  type: proxy
  proxy:
    url: https://news.ycombinator.com/
    rewriteHost: true
trafficStats:
  listen: 127.0.0.1:9999
  secret: some_strong_api_secret
```

**Traffic Stats / management API.** Enable `trafficStats.listen` + `secret`; attach the secret to the `Authorization` header. Endpoints let you query per-user traffic and kick users. Note: kicked clients auto-reconnect, so you must also remove/disable them in the auth backend (or regenerate `userpass`) to keep them out.

**Operational note for this project:** because the app manages the `userpass` map, changing users means rewriting `config.yaml` and reloading Hysteria2 (SIGHUP/service restart). Store the plaintext Hysteria2 password encrypted at rest (see §5) and regenerate the YAML on change.

---

### 3. Caddy v2 (v2.11.4) — Reverse Proxy on Port 8443 with DNS-01 Cloudflare

**Why DNS-01:** HTTP-01 needs port 80 externally reachable; TLS-ALPN-01 needs port 443 externally reachable. Since 443/tcp is occupied by VLESS Reality, use the **DNS-01 challenge**, which validates via a TXT record and needs no inbound 80/443. Caddy still terminates TLS and serves the API on 8443.

**Custom build is required** — standard Caddy does not include the Cloudflare DNS module. Two options:

Option A — build with xcaddy (Dockerfile, multi-stage):
```dockerfile
FROM caddy:2.11-builder AS builder
RUN xcaddy build --with github.com/caddy-dns/cloudflare

FROM caddy:2.11-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

Option B — use a prebuilt image such as `ghcr.io/caddybuilds/caddy-cloudflare:latest` or `ghcr.io/iarekylew00t/caddy-cloudflare:latest` (both are the official Caddy image with only the `caddy` binary replaced to include `caddy-dns/cloudflare`).

**Caddyfile** (site on 8443, reverse_proxy to the Go backend container `api:8080`, DNS-01 via Cloudflare):
```caddyfile
{
    email ops@videcdn.net
}

api.videcdn.net:8443 {
    reverse_proxy api:8080
    tls {
        dns cloudflare {env.CF_API_TOKEN}
        resolvers 1.1.1.1
    }
    encode zstd gzip
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
    }
}
```
Notes:
- Specifying the port explicitly in the site address (`:8443`) is fully supported; Caddy still runs Automatic HTTPS and obtains a real cert for `api.videcdn.net` because a valid domain name is present. The `tls { dns ... }` block forces the DNS-01 challenge, so occupied 80/443 is irrelevant.
- `{env.CF_API_TOKEN}` reads the token from the environment; set it in the container.
- Do NOT add www. or a scheme; `api.videcdn.net:8443` is the correct site key.

**docker-compose service** (using the prebuilt Cloudflare image):
```yaml
services:
  caddy:
    image: ghcr.io/iarekylew00t/caddy-cloudflare:latest
    restart: unless-stopped
    ports:
      - "8443:8443"
    environment:
      - CF_API_TOKEN=${CF_API_TOKEN}
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config
volumes:
  caddy_data:
  caddy_config:
```
(If you use `caddybuilds/caddy-cloudflare`, the token env var it documents is `CLOUDFLARE_API_TOKEN` — match the Caddyfile placeholder accordingly.)

**Cloudflare API token scope.** Create a Custom Token with **Zone → DNS → Edit** permission, plus **Zone → Zone → Read**, scoped to the `videcdn.net` zone. That is the minimum for the DNS-01 challenge to create/cleanup the `_acme-challenge` TXT record. The A record for `api.videcdn.net` must point to the host (92.60.75.196); with DNS-01 you may keep it DNS-only (grey cloud) to avoid Cloudflare proxying the non-standard 8443 port.

---

### 4. goose Migrations (pressly/goose v3)

**Directory layout:**
```
/migrations
  00001_init.sql
  00002_add_clients.sql
```

**SQL migration file format:**
```sql
-- +goose Up
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- +goose Down
DROP TABLE users;
```
Exactly one `-- +goose Up` is required; `-- +goose Down` optional but recommended. For PL/pgSQL blocks use `-- +goose StatementBegin` / `-- +goose StatementEnd`. For non-transactional DDL add `-- +goose NO TRANSACTION` at the top.

**CLI in Docker (env-driven):**
```bash
export GOOSE_DRIVER=postgres
export GOOSE_DBSTRING="postgres://user:pass@db:5432/vpn?sslmode=disable"
export GOOSE_MIGRATION_DIR=./migrations
goose up          # apply all
goose status      # show applied vs pending
goose down        # roll back one
```
Install: `go install github.com/pressly/goose/v3/cmd/goose@latest`.

**Embedding into the Go binary** (recommended — no separate migration files shipped), using the pgx v5 stdlib driver:
```go
package database

import (
    "database/sql"
    "embed"
    "fmt"

    _ "github.com/jackc/pgx/v5/stdlib"
    "github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

func MigrateDatabase(dbURL string) error {
    db, err := sql.Open("pgx", dbURL)
    if err != nil {
        return fmt.Errorf("open db: %w", err)
    }
    defer db.Close()

    goose.SetBaseFS(embedMigrations)
    if err := goose.SetDialect("postgres"); err != nil {
        return fmt.Errorf("set dialect: %w", err)
    }
    if err := goose.Up(db, "migrations"); err != nil {
        return fmt.Errorf("migrate: %w", err)
    }
    return nil
}
```
`goose.SetBaseFS` points goose at the embedded FS; pass `"migrations"` (the embedded subdir) as the dir argument. Note `create`/`fix` still need the real filesystem since `embed.FS` is read-only.

---

### 5. Go Security / Session Specifics (Go stable, 2026)

**Password hashing — argon2id.** Use `github.com/alexedwards/argon2id`, a thin, well-maintained wrapper over the standard `golang.org/x/crypto/argon2` that enforces the Argon2id variant and secure random salts, and encodes params+salt in the standard PHC string (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`).
```go
import "github.com/alexedwards/argon2id"

// Production params (tune to the 1 GB RAM box — see caveat)
params := &argon2id.Params{
    Memory:      64 * 1024, // KiB = 64 MiB
    Iterations:  3,
    Parallelism: 2,
    SaltLength:  16,
    KeyLength:   32,
}
hash, err := argon2id.CreateHash(plaintextPassword, params)
// ...store hash...
match, err := argon2id.ComparePasswordAndHash(plaintextPassword, hash)
```
`DefaultParams` (Memory 64 MiB, Iterations 1, Parallelism = NumCPU) is documented as suitable for dev/testing; set explicit params for production.

**Application-level encryption at rest (VLESS UUID / Hysteria2 password columns).** The idiomatic standard-library approach is **AES-256-GCM** via `crypto/aes` + `crypto/cipher`, with a 32-byte key loaded from an environment variable. GCM provides both confidentiality and integrity (authentication tag) and needs no padding.
```go
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "errors"
    "io"
)

// key: 32 bytes (AES-256), from env (e.g. base64/hex-decoded APP_ENC_KEY)
func Encrypt(key, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil { return nil, err }
    gcm, err := cipher.NewGCM(block)
    if err != nil { return nil, err }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return nil, err }
    // prepend nonce to ciphertext
    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(key, ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil { return nil, err }
    gcm, err := cipher.NewGCM(block)
    if err != nil { return nil, err }
    ns := gcm.NonceSize()
    if len(ciphertext) < ns { return nil, errors.New("ciphertext too short") }
    nonce, ct := ciphertext[:ns], ciphertext[ns:]
    return gcm.Open(nil, nonce, ct, nil)
}
```
Key rules: generate a random 32-byte key once, store it out of band (env var / secrets manager), never in the DB. Use a fresh random nonce per encryption (prepend it to the ciphertext as shown; the nonce is not secret). A single AES-256-GCM key must not encrypt more than 2^32 messages with random nonces. If you want a batteries-included helper, `github.com/gtank/cryptopasta` (Google-authored reference patterns) or Google's `tink-go` are well-regarded, but the standard library above is sufficient and idiomatic. If deriving the key from a passphrase, run it through a KDF (Argon2/scrypt) first rather than using the passphrase bytes directly.

## Recommendations
1. **3X-UI integration:** Build the Go client around the Bearer API Token (Settings → Security → API Token), not cookie login, to avoid session-expiry handling. Hard-fail startup if `XUI_BASE_URL` lacks the `webBasePath`. Always send `settings` as a marshaled JSON string. Treat `expiryTime` as epoch-ms and `totalGB` as bytes throughout the domain model.
2. **Hysteria2:** Use `auth.type: userpass` for native per-user credentials (no external auth service needed for Phase 1). Manage the `userpass` map by regenerating `config.yaml` from the DB on user changes and reloading the service. Enable `trafficStats` with a secret for usage accounting.
3. **Caddy:** Build/pull a Cloudflare-enabled Caddy image; serve `api.videcdn.net:8443`; use DNS-01 with a Cloudflare token scoped to Zone:DNS:Edit + Zone:Zone:Read on `videcdn.net`. Keep the A record DNS-only (grey cloud) since 8443 is non-standard.
4. **Migrations:** Embed migrations via `embed.FS` + `goose.SetBaseFS`, run `goose.Up` at service startup using the pgx v5 stdlib driver, and keep a CI `goose status` check.
5. **Security:** argon2id for user passwords; AES-256-GCM (key from env) for the secret columns. On the 1 GB RAM host, cap Argon2 memory (see caveat) to avoid OOM under concurrent logins.

**Thresholds that change the plan:** if 3X-UI's API token feature is disabled on your panel build, fall back to cookie login and add re-auth-on-401 logic. If Cloudflare is not the DNS provider for `videcdn.net`, swap the `caddy-dns` module accordingly. If you later need per-user Hysteria2 logic beyond static credentials (quotas enforced at auth time), migrate from `userpass` to `type: http` pointing at your Go service.

## Caveats
- **Memory pressure (1 GB RAM):** Argon2id at 64 MiB/thread can exhaust RAM under concurrent logins on a 1 vCPU / 1 GB box also running Postgres, Xray, Hysteria2, and Caddy. Consider Memory 32–46 MiB, Iterations 3–4, Parallelism 1, and rate-limit the login endpoint. Benchmark before production.
- **3X-UI `SessionMaxAge` default:** the exact numeric default (minutes) was not confirmed in the routing/session source; it is user-configurable and its default lives in the settings service. Don't hard-code an assumption — read it or use Bearer tokens.
- **3X-UI is "personal use" software:** the MHSanaei/3x-ui README/Wiki states verbatim: "This project is intended for personal use only. Please do not use it for illegal purposes or in a production environment." For a commercial service, treat the panel API as an unstable dependency, pin the image by digest, and add integration tests against your pinned version (the client/settings JSON shape has shifted across versions).
- **Hysteria2 stats/online-tracking** have had bugs in some integrations (e.g., users showing offline while traffic flows) tied to bundled Xray-core versions — validate on your exact version.
- **Cloudflare token env var naming** differs between prebuilt images (`CF_API_TOKEN` vs `CLOUDFLARE_API_TOKEN`); match it to your Caddyfile placeholder.
- **Caddy 2.11.x CVEs:** several route/auth-bypass and TLS client-auth fail-open CVEs (CVE-2026-27585..27590) were fixed in 2.11.1, and three more v2.11.3 vulnerabilities (GHSA-j8px-rmrx-76h9) were fixed in v2.11.4 — always run the latest patch (v2.11.4+).
- All version numbers reflect the state as of July 19, 2026 and should be re-verified at implementation time. Several code structs (`LoginForm`, `Msg`, `ClientTraffic`) are quoted from pkg.go.dev and the 3x-ui source tree; confirm against your pinned panel version before wiring the client.