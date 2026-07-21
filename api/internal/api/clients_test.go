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
	"vpn-api/internal/xui"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
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
		if _, err := pool.Exec(context.Background(), "DELETE FROM sessions"); err != nil {
			t.Fatalf("clean sessions table: %v", err)
		}
		if _, err := pool.Exec(context.Background(), "DELETE FROM admins"); err != nil {
			t.Fatalf("clean admins table: %v", err)
		}
	}
	clean()
	t.Cleanup(clean)

	return pool
}

func testRouter(t *testing.T) (http.Handler, *http.Cookie) {
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

	sm := session.NewManager(pool)
	authSvc := auth.NewService(pool, sm)

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

	return NewRouter(pool, clientsSvc, authSvc, sm), cookie
}

func TestCreateClientEndpointSuccess(t *testing.T) {
	router, cookie := testRouter(t)

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
	router, cookie := testRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/clients", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
}

func TestCreateClientEndpointInvalidJSON(t *testing.T) {
	router, cookie := testRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/clients", bytes.NewBufferString(`{not json`))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCreateClientEndpointNegativeTrafficLimit(t *testing.T) {
	router, cookie := testRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/clients", bytes.NewBufferString(`{"traffic_limit_bytes": -1}`))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCreateClientEndpointRequiresAuth(t *testing.T) {
	router, _ := testRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/clients", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
