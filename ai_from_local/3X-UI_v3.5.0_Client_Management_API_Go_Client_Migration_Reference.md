# 3X-UI (mhsanaei/3x-ui) HTTP API — Current Client-Management Route Reference for a Go Client Spec

## TL;DR
- The latest stable release is **v3.5.0** (published ~July 14, 2026 per GitHub Container Registry — "latest v3.5.0 3.5.0 · Published 7 days ago"; v3.4.2 was published ~July 1, 2026). Your `:latest` deployment auto-updated into the **v3.5.x line**, which shipped a major backend refactor: clients are now **standalone entities** (backed by a `client_records` table) served by a dedicated `ClientController` mounted at **`/panel/api/clients`**, replacing the old inbound-embedded `/panel/api/inbounds/*Client` routes.
- The response envelope is **unchanged** — still `{"success": bool, "msg": string, "obj": ...}` — and **Bearer API-token auth still works** exactly the same way (Settings → Security → API Token → `Authorization: Bearer <token>`), now additionally guarded by a CSRF middleware that Bearer requests bypass.
- The old `/panel/api/inbounds/addClient`, `/updateClient/:id`, `/:id/delClient/:clientId` routes are **removed** in your build (hence the 404s), so your Go `internal/xui` package must be re-pointed to the new `/panel/api/clients/*` namespace and switched from the old escaped-`settings`-string payload to the new flat client-record JSON body.

## Key Findings

### 1. Latest version
- `ghcr.io/mhsanaei/3x-ui:v3.5.0` is the latest stable tag. Per the GitHub Container Registry package page: "latest v3.5.0 3.5.0 · Published 7 days ago" (≈ July 14, 2026), "v3.4.2 3.4.2 · Published 20 days ago" (≈ July 1), "v3.4.1 · 24 days ago", "v3.4.0 · 27 days ago", "v3.3.1 · about 1 month ago".
- A rolling per-commit `dev-latest` channel also exists: GitHub Releases lists "Dev build 16b2bcf9 Pre-release" with metadata `commit=16b2bcf9aa8ce20c5c2b66ec055cd19ddc262110 built=2026-07-18T11:10:02Z · Automated per-commit build from main. Not a stable release.` Stable deployments stay on the release channel unless explicitly switched.
- The Go module is now **`github.com/mhsanaei/3x-ui/v3`** (bumped from v2), confirmed verbatim in the import paths of `web/controller/api.go` on `main`.

### 2. Architectural change (the "why" and "when")
- Historically, clients were embedded as a JSON `clients[]` array inside each inbound's `settings` string; the API lived at `/panel/api/inbounds/addClient`, `/panel/api/inbounds/updateClient/:clientId`, `/panel/api/inbounds/:id/delClient/:clientId`, `/panel/api/inbounds/:id/resetClientTraffic/:email`, etc.
- In the v3.5.x line, clients became **first-class standalone records**. DeepWiki's Client Management page (indexed against the current tree) states: "clients are managed as standalone entities via `ClientService` and `ClientController`, independent of specific inbounds. This allows a single client record to be attached to or detached from multiple inbounds while maintaining unified traffic statistics, subscription IDs, and settings … Clients are stored in the `client_records` table." That decoupling from inbounds is precisely what moved the routes to a new top-level `/panel/api/clients` resource.
- Verbatim from `web/controller/api.go` (`main`, module v3, release ref `b2948dd37c9b5a96f7c9a44c4c750021035ea1d8`), the API group is built as:
  ```go
  api := g.Group("/panel/api")
  api.Use(a.checkAPIAuth)
  api.Use(middleware.CSRFMiddleware())

  inbounds := api.Group("/inbounds")
  a.inboundController = NewInboundController(inbounds)

  clients := api.Group("/clients")
  NewClientController(clients)
  NewGroupController(clients)
  // ... server, nodes, custom-geo, setting, xray, /backuptotgbot
  ```
  So **all client routes are children of `/panel/api/clients`**, and a second controller (`NewGroupController`) also mounts group-related routes under the same prefix.
- Related earlier breaking move: v3.3.0 shipped `refactor(api)!: move /panel/setting and /panel/xray under /panel/api` — settings and Xray-config endpoints now live at `/panel/api/setting/*` and `/panel/api/xray/*` and are driven by the same API token.
- The old routes are **fully removed** (not deprecated-but-present) in v3.5.x; `web/web.go` installs `engine.NoRoute(...) → 404`, which is why your probes of the old paths return clean 404s.

### 3. Confirmed new route set under `/panel/api/clients/*`
Your live evidence — binary-strings extraction of `/add`, `/update/`, `/del/`, `/get/`, `/list`, `/traffic/`, plus a confirmed HTTP 200 on `GET /panel/api/clients/list?inboundId=1` — matches the controller's registrations. The trailing slashes on `update/`, `del/`, `get/`, `traffic/` indicate a Gin path parameter (`:id`) follows; `/add` and `/list` take a body/query only. Core reconstructed route table:

| Method | Path | Purpose |
|---|---|---|
| GET | `/panel/api/clients/list` | List clients (supports `?inboundId=` filter) — **confirmed HTTP 200 live** |
| GET | `/panel/api/clients/list/paged` | Paged list for large deployments (used by the `ClientsPage` UI) |
| POST | `/panel/api/clients/add` | Create a client (flat JSON body) |
| POST | `/panel/api/clients/update/:id` | Update a client by record id |
| POST | `/panel/api/clients/del/:id` | Delete a client by record id |
| GET | `/panel/api/clients/get/:id` | Get one client by record id |
| GET | `/panel/api/clients/traffic/:id` | Get client traffic stats by id |

Additional routes implied by the standalone-client architecture (verify exact spellings on your panel — see below):
- **Bulk operations** — `bulkCreate`, `bulkAdjust`, `bulkAttach`, `bulkDetach`. DeepWiki notes the bulk UI "allows administrators to generate up to 500 clients in a single operation … five generation modes including random strings, prefixed numbering, and postfixes."
- **Attach/detach** a client to/from inbounds (`AttachByEmail` / `DetachByEmail`).
- **Reset traffic** and **IP-limit management** (list IPs / clear IPs).
- **`onlines`** (online-client list; now sourced from Xray's online-stats API).
- **Group routes** mounted under `/panel/api/clients` via `NewGroupController`.

**Authoritative source of truth for YOUR build:** the panel's built-in OpenAPI/Swagger UI at **`{webBasePath}/panel/api-docs`**, rendered from `frontend/public/openapi.json`. Per DeepWiki, the spec's "components, schemas, and response examples [are] generated directly from the Go structs," Gin `:id` paths are converted to OpenAPI `{id}` braces, and a Go test (`api_docs_test.go`) scans every `g.GET(...)`/`g.POST(...)` registration and asserts it is documented — so the api-docs page is guaranteed in sync with the running binary. Read the exact secondary paths and the `add` request schema from there before freezing your Go structs.

### 4. Payload shape for `add` / `update` (changed to flat JSON)
- v3.5.0's "Typed API & OpenAPI" work generates request/response schemas directly from the Go structs, and the standalone client entity is the **`ClientRecord`** model (DeepWiki: the api-docs tool "generates Zod schemas (e.g., `ClientRecordSchema`) from Go models"). The new `/panel/api/clients/add` and `/update/:id` endpoints therefore take a **flat JSON client object** — **NOT** the old nested escaped-`settings`-string-containing-a-`clients`-array pattern.
- Client fields (from the Go client model, JSON tags shown):
  - `id` (string) — UUID for VMess/VLESS; for Trojan/Shadowsocks the credential is `password`
  - `email` (string) — unique across the whole panel; primary identifier
  - `enable` (bool)
  - `flow` (string) — e.g. `xtls-rprx-vision`
  - `limitIp` (int)
  - `totalGB` (int64, bytes; `0` = unlimited)
  - `expiryTime` (int64, ms epoch; negative value = "days until activation on first use")
  - `tgId` (**int64** — see the migration caveat below)
  - `subId` (string)
  - `comment` (string)
  - `reset` (int) — auto-renewal period in days
  - inbound association field(s) — the exact JSON key linking a client to inbound(s) should be read off the `add` schema in your panel's api-docs
- The legacy escaped-`settings` string format now applies only to the removed `/panel/api/inbounds/*Client` endpoints.

Illustrative `add` request body (confirm field names against `/panel/api-docs`):
```json
{
  "id": "6309b9e8-cfc9-42f8-9957-c214704bdd1d",
  "email": "user_12345",
  "enable": true,
  "flow": "",
  "limitIp": 0,
  "totalGB": 0,
  "expiryTime": 0,
  "tgId": 0,
  "subId": "hbwj7dcw19gh66dkobpm",
  "comment": "",
  "reset": 0
}
```

### 5. Response envelope (unchanged)
```json
{ "success": true, "msg": "", "obj": { } }
```
On error: `{"success": false, "msg": "<reason>", "obj": null}`. This is the standard `ApiResponse` struct: `Success bool json:"success"`, `Msg string json:"msg"`, `Obj json.RawMessage json:"obj"`. No change in v3.

### 6. Authentication (mechanism unchanged; CSRF added)
- Verbatim from `web/controller/api.go`, `checkAPIAuth`:
  ```go
  auth := c.GetHeader("Authorization")
  if after, ok := strings.CutPrefix(auth, "Bearer "); ok {
      tok := after
      if a.apiTokenService.Match(tok) {
          if u, err := a.userService.GetFirstUser(); err == nil {
              session.SetAPIAuthUser(c, u)
          }
          c.Set("api_authed", true)
          c.Next(); return
      }
  }
  if !session.IsLogin(c) {
      if c.GetHeader("X-Requested-With") == "XMLHttpRequest" {
          c.AbortWithStatus(http.StatusUnauthorized)   // 401
      } else {
          c.AbortWithStatus(http.StatusNotFound)        // 404 to hide endpoints
      }
      return
  }
  c.Next()
  ```
  So a valid `Authorization: Bearer <token>` authenticates as the first user; an unauthenticated `/panel/api/*` request returns **404** (to hide endpoint existence) unless `X-Requested-With: XMLHttpRequest` is present, in which case **401**.
- All `/panel/api/*` routes (including `/panel/api/clients/*`) also pass through `middleware.CSRFMiddleware()`. DeepWiki confirms the two security schemes are `bearerAuth` (API tokens) and `cookieAuth` (session cookie). Bearer-token requests are the intended programmatic path and are not subject to the browser CSRF flow; only session-cookie clients performing state changes need to carry the CSRF token.
- Token creation is unchanged: **Settings → Security → API Token**. All endpoints under `/panel/api/*` honour both cookie and Bearer modes.

## Details
- **Full `/panel/api` wiring** (verbatim, `web/controller/api.go`, `main`): group `/panel/api` with `checkAPIAuth` + `CSRFMiddleware`; subgroups `/inbounds` (InboundController), `/clients` (ClientController + GroupController), `/server`, `/nodes`, `/custom-geo`; plus `NewSettingController(api)` and `NewXraySettingController(api)` giving `/panel/api/setting/*` and `/panel/api/xray/*`; plus `POST /panel/api/backuptotgbot`.
- **Other v3.x changes relevant to a Go backend integration:**
  - `tgId` is now `int64`. Databases created on 2.x with `tgId: ""` throw `json: cannot unmarshal string into Go struct field Client.tgId of type int64` when the client is edited (GitHub issue #5934, upgrade 2.9.4 → 3.5.0). Always send `tgId` as a number, and be aware legacy records may need repair.
  - Inbound-management endpoints (`/panel/api/inbounds/*`) still exist; `GetInbounds` returns full client detail while `GetInboundsSlim` strips per-client fields for dashboard payload size — use the slim variant for cheap inbound lists.
  - Online tracking and per-client IP limits now read from Xray's online-stats API rather than parsing `access.log` (v3.3.1+); v3.5.0 batched ip-limit lookups and disables depleted clients by id (scale-tested to 500,000 clients).
  - v3.5.0 also: MTProto inbounds became natively multi-client (legacy single-secret inbounds auto-migrate to the clients model); bundled Xray-core bumped to v26.7.11; a DB migration drops the legacy UNIQUE constraint on `inbounds.port` and repairs overflowed traffic counters; frontend rewritten (React Hook Form, Fetch API, uPlot).

## Recommendations
1. **Re-point `internal/xui`** to the new namespace:
   - `AddClient` → `POST {base}/panel/api/clients/add` with the flat client JSON body.
   - `UpdateClient` → `POST {base}/panel/api/clients/update/{id}`.
   - `DeleteClient` → `POST {base}/panel/api/clients/del/{id}`.
   - `GetClientTraffics` → `GET {base}/panel/api/clients/traffic/{id}` (or via the email/uuid lookup routes).
   - client list → `GET {base}/panel/api/clients/list?inboundId={n}`.
   - inbound list stays on `/panel/api/inbounds/list`.
2. **Verify exact paths and the `add`/`update` schema against your own panel** at `{webBasePath}/panel/api-docs` (and the raw `openapi.json` it serves) before finalizing Go structs. This is the source of truth generated from the running binary; it will resolve (a) whether `:id` is the numeric `client_records` id vs email/uuid, and (b) the exact inbound-association field name — the two items I could not line-verify.
3. **Update payload marshalling**: drop the escaped-`settings` string wrapper; marshal a flat client object. Keep `tgId` numeric (int64), never an empty string.
4. **Keep Bearer auth**: send `Authorization: Bearer <token>`; treat a 404 on `/panel/api/*` as "unauthenticated or wrong path," not necessarily "resource absent." Add `X-Requested-With: XMLHttpRequest` if you prefer a 401 signal on auth failure.
5. **Version-gate the client**: query the panel's reported version at startup. If `< v3.5.0`, keep the old `/panel/api/inbounds/*Client` code path; if `≥ v3.5.0`, use `/panel/api/clients/*`. This is the threshold that flips the whole integration — pin your Docker tag (avoid `:latest`) so the API surface can't shift under you again.

## Caveats
- I could not fetch the raw `web/controller/client.go` line-by-line (GitHub raw/blob for that file did not surface in fetchable results), so the six core routes above are corroborated by (a) the verbatim `/panel/api/clients` mounting in `api.go`, (b) your own binary-strings + live-200 evidence, and (c) DeepWiki's `/list/paged` and bulk references — but the exact spelling of the secondary routes (bulk, attach/detach, reset, IP management, onlines) and whether `:id` is the numeric record id vs email/uuid are reconstructed rather than quoted from that file. Confirm on `/panel/api-docs`.
- DeepWiki's newest index cites the controller path as `internal/web/controller/client.go`, while the live `main` tree fetched today shows `web/controller/`. A directory move may be in flight; this affects source navigation only, not the HTTP paths (which are `/panel/api/clients/*` regardless).
- The `add` payload example uses field names confirmed from the Go client model; the exact inbound-linkage key is the one field you must read from your panel's api-docs before shipping.
- Release/publish dates are from the GitHub Container Registry "Published N days ago" relative labels as of July 21, 2026, so they are approximate to within ~a day.