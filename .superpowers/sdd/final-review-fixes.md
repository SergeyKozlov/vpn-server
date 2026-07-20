# Final review fixes — feature/login-auth-middleware

## What changed

1. **Cap request body size on JSON-decoding handlers (MUST-FIX).**
   - `api/internal/api/login.go`: `loginHandler` now sets
     `r.Body = http.MaxBytesReader(w, r.Body, 4096)` right after the
     rate-limit check, before `json.NewDecoder(r.Body).Decode(&req)`.
   - `api/internal/api/clients.go`: `createClientHandler` now sets
     `r.Body = http.MaxBytesReader(w, r.Body, 4096)` before its
     `json.NewDecoder(r.Body).Decode(&req)` call. The existing
     `errors.Is(err, io.EOF)` tolerance for an empty body is preserved —
     `MaxBytesReader` on an empty body still yields `io.EOF`, so no other
     change was needed there.
   - Added `TestLoginBodyTooLarge` to `api/internal/api/login_test.go`:
     POSTs a ~1MB JSON body to `/login` and asserts `http.StatusBadRequest`
     (the decoder errors out once `MaxBytesReader` trips, and the handler
     maps decode errors to 400).

2. **TODO comment on the proxy integration seam.**
   - `api/internal/api/ratelimit.go`: added a doc comment on `clientIP`
     noting that once the API sits behind the planned Caddy reverse proxy,
     `RemoteAddr` will always be the proxy, and the function will need to
     switch to trusting `X-Forwarded-For` from the local proxy hop only —
     otherwise every internet client shares one rate-limit bucket. Function
     body unchanged.

3. **Guard test for the timing-equalization dummy hash.**
   - Added `TestDummyHashIsValid` to `api/internal/auth/auth_test.go`. It
     calls `password.Verify("any-password", dummyHash)` directly (no DB
     pool, no `testPool` call) and asserts the hash is well-formed (no
     error) and does not match an arbitrary password. This protects the
     unknown-username timing-equalization path from silently degrading if
     `dummyHash` is ever edited to something malformed.

## Test commands and actual output

```
$ cd /root/vpn/api && go build ./... && go vet ./...
BUILD_VET_OK
```

```
$ cd /root/vpn/api && DATABASE_URL=$(grep DATABASE_URL /root/vpn/.env | cut -d= -f2-) \
    go test ./internal/api/... ./internal/auth/... -count=1
ok  	vpn-api/internal/api	3.133s
ok  	vpn-api/internal/auth	1.588s
```

```
$ cd /root/vpn/api && DATABASE_URL=$(grep DATABASE_URL /root/vpn/.env | cut -d= -f2-) \
    go test ./internal/api/... ./internal/auth/... -run 'TestLoginBodyTooLarge|TestDummyHashIsValid' -v -count=1
=== RUN   TestLoginBodyTooLarge
--- PASS: TestLoginBodyTooLarge (0.04s)
PASS
ok  	vpn-api/internal/api	0.054s
=== RUN   TestDummyHashIsValid
--- PASS: TestDummyHashIsValid (0.27s)
PASS
ok  	vpn-api/internal/auth	0.280s
```

## Files touched

- `api/internal/api/login.go`
- `api/internal/api/clients.go`
- `api/internal/api/ratelimit.go`
- `api/internal/api/login_test.go`
- `api/internal/auth/auth_test.go`
- `.superpowers/sdd/final-review-fixes.md` (this file)
