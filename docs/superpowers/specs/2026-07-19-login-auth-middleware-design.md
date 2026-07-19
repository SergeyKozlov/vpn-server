# Login / auth middleware for the admin API — design

Date: 2026-07-19
Status: approved

## Context

`api/internal/clients.Service.Create` and `POST /clients` exist and work, but the
route is completely open — no login exists anywhere in the service yet, even
though `password` (argon2id) has been implemented since an earlier session
specifically for panel logins. The `users` table (migration `00001_create_users.sql`)
already has the shape needed (`username`, `password_hash`) but has zero rows.

This spec covers closing that gap: a login endpoint, a session mechanism, and
middleware that protects `POST /clients` (and any future mutating routes).

## Decisions

- **Session mechanism: stateless signed cookie.** No session table in Postgres.
  A cookie carries `userID` + `expiresAt`, HMAC-SHA256 signed with a server
  secret. Chosen over a DB-backed session table for simplicity (no migration,
  no cleanup job) and over a static Bearer admin token because it ties access
  to real per-admin credentials backed by the `users` table that already exists.
  Trade-off accepted: no server-side logout/revocation before expiry — a leaked
  cookie is valid until its TTL runs out (24h, see below). Acceptable for a
  single-admin, Phase 1, access-management-only tool.
- **Session TTL: 24 hours.**
- **First admin creation: dedicated CLI command**, not a public registration
  endpoint. Run once, manually, on the server.
- **Login rate limiting: yes, simple in-memory limiter**, scoped to Phase 1
  (single process, restart resets it, no external dependency). Closes the gap
  explicitly deferred in an earlier session's notes ("rate-limiting the login
  endpoint... belongs with the future login HTTP handler").
- **CSRF: `SameSite=Strict` only.** No CSRF token scheme. Accepted gap, same
  posture as other documented Phase 1 shortcuts (e.g. the Hysteria2 reload
  best-effort rollback) — revisit if/when a real browser-based frontend for
  the web panel is built.
- **Login failure responses are generic.** Unknown username and wrong
  password both return the same `401` with no distinguishing detail (no user
  enumeration).

## Architecture

### `api/internal/session` (new package)

- `NewSigner(key []byte) (*Signer, error)` — validates key length (≥32 bytes),
  mirrors the `crypto.NewAESGCM` constructor shape.
- `(*Signer) Sign(userID int64) (token string, expiresAt time.Time)` — encodes
  `userID` + `expiresAt` (24h from now) into a payload, HMAC-SHA256 signs it,
  returns a single opaque string suitable for a cookie value.
- `(*Signer) Verify(token string) (userID int64, err error)` — recomputes and
  compares the signature (constant-time), then checks `expiresAt` against
  `time.Now()`. Returns a single generic error type on any failure (bad
  signature, malformed token, or expired) — callers don't need to distinguish.

### `api/internal/auth` (new package)

- `Service.Login(ctx, username, password string) (token string, expiresAt time.Time, err error)`:
  1. Look up user by `username` in `users`.
  2. If not found: still run `password.Verify` against a fixed dummy hash to
     keep response timing similar between "unknown user" and "wrong password"
     (cheap and avoids an obvious timing side-channel), then return
     `ErrInvalidCredentials`.
  3. If found: `password.Verify(password, storedHash)`. On mismatch, return
     `ErrInvalidCredentials`.
  4. On success: `session.Signer.Sign(user.ID)`, return the token + expiry.
- `ErrInvalidCredentials` is the only auth-failure error this package exposes
  to its caller — the HTTP layer maps it to 401 without further detail.
- A simple in-memory rate limiter (fixed-window counter keyed by client IP,
  e.g. 5 attempts/minute, `sync.Mutex`-protected map) lives here or in
  `internal/api` — whichever keeps `Service.Login` easiest to unit test
  without HTTP concerns. Decision: put the limiter in `internal/api` as
  middleware-like logic specific to the `/login` route, so `auth.Service`
  stays pure business logic (mirrors how `clients.Service` stays free of
  HTTP concerns today).

### `api/internal/api` (existing package, additions)

- `login.go`: `POST /login` handler. Parses `{username, password}` JSON body,
  checks the rate limiter first (429 if exceeded), calls `auth.Service.Login`,
  on success sets `Set-Cookie` (`HttpOnly`, `Secure`, `SameSite=Strict`,
  `Path=/`, `Max-Age` = 24h) with the signed token, `204` response. On
  `ErrInvalidCredentials` → `401`. Malformed JSON → `400` (same
  `errors.Is(err, io.EOF)`-tolerant pattern already used in `clients.go` isn't
  applicable here since username/password are required, not optional).
- `logout.go`: `POST /logout` — overwrites the cookie with `Max-Age=-1`
  (expired), `204`. No server-side state to clear (stateless sessions).
- `middleware.go`: `RequireAuth(signer *session.Signer) func(http.Handler) http.Handler`.
  Reads the cookie, calls `signer.Verify`, on any error → `401` with no body
  detail. On success, stores `userID` in request context via a typed context
  key (not currently consumed by anything downstream, but present for future
  audit logging / per-admin ownership).
- `router.go`: restructure so `POST /clients` is mounted inside a
  `r.Group` (or sub-router) wrapped with `RequireAuth`; `/healthz`, `/login`,
  `/logout` stay outside it.

### `api/cmd/createadmin/main.go` (new command)

- Flags: `-u` (username, required), `-p` (password, required).
- Connects using the same `DATABASE_URL` config pattern as `cmd/api`.
- Hashes the password with `password.Hash`, `INSERT INTO users (username, password_hash) VALUES (...)`.
- On unique-constraint violation, prints a clear "user already exists" error
  and exits non-zero — no upsert, no "update password" mode (out of scope;
  re-running against an empty table or restoring the DB are the only expected
  uses for now).

## Config changes

- New required env var `SESSION_SIGNING_KEY` (base64-encoded, ≥32 bytes
  decoded) — hard-fail at startup in `config.Config`, same pattern as
  `APP_ENC_KEY`/`DATABASE_URL`. Add to `.env` (generate a real value) and
  `.env.example` (placeholder).
- No new migration — `users` table already has the required columns.

## Error handling summary

| Condition | Response |
|---|---|
| Unknown username or wrong password | `401`, generic body |
| Rate limit exceeded on `/login` | `429` |
| Malformed `/login` JSON body | `400` |
| Missing/expired/tampered session cookie on a protected route | `401`, generic body |
| Successful login | `204` + `Set-Cookie` |
| Successful logout | `204` + expired `Set-Cookie` |

## Testing plan

- `internal/session`: unit tests — sign/verify round trip, expired token
  rejected, tampered signature rejected, wrong signing key rejected, key
  length validation.
- `internal/auth`: integration tests against real Postgres (same pattern as
  `internal/clients/service_test.go`, skipped via `t.Skip` if `DATABASE_URL`
  unset) — successful login, wrong password, unknown username (both give
  `ErrInvalidCredentials`), rate limiter trips after N attempts.
- `internal/api`: `RequireAuth` middleware tests (no cookie, malformed cookie,
  expired cookie → 401; valid cookie → request reaches the wrapped handler).
  Update existing `clients_test.go` to log in first and attach the resulting
  cookie, since `POST /clients` is now protected.
- `cmd/createadmin`: manual verification (create an admin against the real
  `vpn-postgres` container, confirm login works end-to-end via `/login`) —
  not a priority for automated coverage since it's a one-shot operational
  tool, not a code path exercised by the running service.

## Out of scope (explicitly deferred)

- Multi-admin ownership / audit trail beyond storing `userID` in context.
- Server-side session revocation before TTL expiry.
- CSRF tokens (relying on `SameSite=Strict` only).
- Password reset / change-password flow.
- Persisting rate-limiter state across restarts or across multiple API
  instances (Phase 1 is single-instance).
