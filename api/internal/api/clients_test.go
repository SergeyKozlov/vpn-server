package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/auth"
	"vpn-api/internal/clients"
	appcrypto "vpn-api/internal/crypto"
	"vpn-api/internal/password"
	"vpn-api/internal/provisioner"
	"vpn-api/internal/session"
	"vpn-api/internal/testutil"
	"vpn-api/internal/users"
	"vpn-api/internal/xui"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	testutil.LoadEnv()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect pool: %v", err)
	}
	t.Cleanup(pool.Close)

	clean := func() {
		if _, err := pool.Exec(context.Background(), "DELETE FROM legacy_clients_phase1"); err != nil {
			t.Fatalf("clean legacy_clients_phase1 table: %v", err)
		}
		if _, err := pool.Exec(context.Background(), "DELETE FROM admin_sessions"); err != nil {
			t.Fatalf("clean admin_sessions table: %v", err)
		}
		if _, err := pool.Exec(context.Background(), "DELETE FROM sessions"); err != nil {
			t.Fatalf("clean sessions table: %v", err)
		}
		if _, err := pool.Exec(context.Background(), "DELETE FROM admins"); err != nil {
			t.Fatalf("clean admins table: %v", err)
		}
		if _, err := pool.Exec(context.Background(), "DELETE FROM users"); err != nil {
			t.Fatalf("clean users table: %v", err)
		}
	}
	clean()
	t.Cleanup(clean)

	return pool
}

func testRouter(t *testing.T) (http.Handler, *http.Cookie, *pgxpool.Pool) {
	t.Helper()

	pool := testPool(t)

	key := make([]byte, appcrypto.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cryptor, err := appcrypto.NewAESGCM(key)
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("auth:\n  type: userpass\n  userpass: {}\n"), 0o600); err != nil {
		t.Fatalf("write hysteria config: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	t.Cleanup(srv.Close)

	panel, err := xui.NewPanel(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewPanel: %v", err)
	}

	vlessProvisioner := provisioner.NewThreeXUIProvisioner(panel, 1)
	h2Provisioner := provisioner.NewHysteria2Provisioner(configPath, "true")
	clientsSvc := clients.NewService(pool, vlessProvisioner, h2Provisioner, cryptor, 1)

	adminSessions := session.NewSessionManager(pool, "admin_sessions")
	authSvc := auth.NewService(pool, adminSessions)

	hash, err := password.Hash("correct-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admins (username, password_hash) VALUES ($1, $2)`, "admin", hash); err != nil {
		t.Fatalf("insert test admin: %v", err)
	}

	token, expiresAt, err := authSvc.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	cookie := &http.Cookie{Name: sessionCookieName, Value: token, Expires: expiresAt}

	userSessions := session.NewSessionManager(pool, "sessions")
	usersSvc := users.NewService(pool, userSessions)

	return NewRouter(pool, clientsSvc, authSvc, adminSessions, usersSvc, userSessions), cookie, pool
}

// testClientCookie registers and logs in a fresh client user against
// router's users service, returning a valid vpn_user_session cookie —
// used by the cross-circuit test to prove a client cookie can't
// authenticate an admin route.
func testClientCookie(t *testing.T, pool *pgxpool.Pool) *http.Cookie {
	t.Helper()

	userSessions := session.NewSessionManager(pool, "sessions")
	usersSvc := users.NewService(pool, userSessions)

	if _, err := usersSvc.Register(context.Background(), "cross-circuit@example.com", "correct-password"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	token, expiresAt, err := usersSvc.Login(context.Background(), "cross-circuit@example.com", "correct-password")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	return &http.Cookie{Name: clientSessionCookieName, Value: token, Expires: expiresAt}
}

func TestCreateClientEndpointSuccess(t *testing.T) {
	router, cookie, _ := testRouter(t)

	body := bytes.NewBufferString(`{"traffic_limit_bytes": 1073741824, "limit_ip": 3}`)
	req := httptest.NewRequest(http.MethodPost, "/clients", body)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	for _, field := range []string{"id", "email", "vless_uuid", "hysteria2_username", "hysteria2_password", "sub_id"} {
		if _, ok := resp[field]; !ok {
			t.Errorf("response missing field %q: %v", field, resp)
		}
	}
	if resp["limit_ip"].(float64) != 3 {
		t.Errorf("limit_ip = %v, want 3", resp["limit_ip"])
	}
}

func TestCreateClientEndpointEmptyBodyUsesDefaults(t *testing.T) {
	router, cookie, _ := testRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/clients", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
}

func TestCreateClientEndpointInvalidJSON(t *testing.T) {
	router, cookie, _ := testRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/clients", bytes.NewBufferString(`{not json`))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCreateClientEndpointNegativeTrafficLimit(t *testing.T) {
	router, cookie, _ := testRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/clients", bytes.NewBufferString(`{"traffic_limit_bytes": -1}`))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCreateClientEndpointRequiresAuth(t *testing.T) {
	router, _, _ := testRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/clients", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestCreateClientEndpointRejectsClientCookie is TZ P2.3 acceptance row 10:
// a client (vpn_user_session) cookie must not authenticate the admin
// POST /clients route — the two circuits are independent.
func TestCreateClientEndpointRejectsClientCookie(t *testing.T) {
	router, _, pool := testRouter(t)
	clientCookie := testClientCookie(t, pool)

	req := httptest.NewRequest(http.MethodPost, "/clients", bytes.NewBufferString(`{}`))
	req.AddCookie(clientCookie)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
