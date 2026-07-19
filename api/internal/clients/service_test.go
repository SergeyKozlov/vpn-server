package clients

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/crypto"
	"vpn-api/internal/hysteria"
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
		if _, err := pool.Exec(context.Background(), "DELETE FROM clients"); err != nil {
			t.Fatalf("clean clients table: %v", err)
		}
	}
	clean()
	t.Cleanup(clean)

	return pool
}

func testCryptor(t *testing.T) *crypto.AESGCM {
	t.Helper()
	key := make([]byte, crypto.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	c, err := crypto.NewAESGCM(key)
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	return c
}

func testHysteriaConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "listen: :8444\nauth:\n  type: userpass\n  userpass: {}\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write hysteria config: %v", err)
	}
	return path
}

func newMockXUIServer(t *testing.T, handler http.HandlerFunc) *xui.Panel {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	panel, err := xui.NewPanel(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewPanel: %v", err)
	}
	return panel
}

func alwaysSuccess(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func TestCreateSuccess(t *testing.T) {
	pool := testPool(t)
	cryptor := testCryptor(t)
	configPath := testHysteriaConfig(t)

	var calls []string
	var addClientBody []byte
	panel := newMockXUIServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if strings.Contains(r.URL.Path, "addClient") {
			addClientBody, _ = io.ReadAll(r.Body)
		}
		alwaysSuccess(w, r)
	})

	svc := NewService(pool, panel, cryptor, 1, configPath, "true")

	expires := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Millisecond)
	c, err := svc.Create(context.Background(), CreateParams{
		ExpiresAt:         &expires,
		TrafficLimitBytes: 107374182400,
		LimitIP:           2,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if c.ID == 0 {
		t.Errorf("ID not set")
	}
	if c.VlessUUID == "" || c.Hysteria2Username == "" || c.Hysteria2Password == "" || c.SubID == "" || c.Email == "" {
		t.Errorf("missing generated identifiers: %+v", c)
	}

	if len(calls) != 1 || calls[0] != "POST /panel/api/inbounds/addClient" {
		t.Errorf("unexpected xui calls: %v", calls)
	}

	// The exact payload xui.AddClient sent must reflect the generated
	// identity and requested limits.
	var reqBody struct {
		ID       int    `json:"id"`
		Settings string `json:"settings"`
	}
	if err := json.Unmarshal(addClientBody, &reqBody); err != nil {
		t.Fatalf("unmarshal addClient request: %v", err)
	}
	if reqBody.ID != 1 {
		t.Errorf("addClient inbound id = %d, want 1", reqBody.ID)
	}
	var settings struct {
		Clients []struct {
			ID         string `json:"id"`
			Email      string `json:"email"`
			Flow       string `json:"flow"`
			Enable     bool   `json:"enable"`
			ExpiryTime int64  `json:"expiryTime"`
			LimitIP    int    `json:"limitIp"`
			TotalGB    int64  `json:"totalGB"`
			SubID      string `json:"subId"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(reqBody.Settings), &settings); err != nil {
		t.Fatalf("unmarshal addClient settings: %v", err)
	}
	if len(settings.Clients) != 1 {
		t.Fatalf("settings.clients = %+v, want 1 entry", settings.Clients)
	}
	got := settings.Clients[0]
	if got.ID != c.VlessUUID {
		t.Errorf("client id = %q, want %q", got.ID, c.VlessUUID)
	}
	if got.Email != c.Email {
		t.Errorf("client email = %q, want %q", got.Email, c.Email)
	}
	if got.Flow != vlessFlow {
		t.Errorf("client flow = %q, want %q", got.Flow, vlessFlow)
	}
	if !got.Enable {
		t.Errorf("client enable = false, want true")
	}
	if got.ExpiryTime != expires.UnixMilli() {
		t.Errorf("client expiryTime = %d, want %d", got.ExpiryTime, expires.UnixMilli())
	}
	if got.LimitIP != 2 {
		t.Errorf("client limitIp = %d, want 2", got.LimitIP)
	}
	if got.TotalGB != 107374182400 {
		t.Errorf("client totalGB = %d, want 107374182400", got.TotalGB)
	}
	if got.SubID != c.SubID {
		t.Errorf("client subId = %q, want %q", got.SubID, c.SubID)
	}

	// DB row exists and matches.
	var email, hyUsername string
	var enabled bool
	err = pool.QueryRow(context.Background(), "SELECT email, hysteria2_username, enabled FROM clients WHERE id = $1", c.ID).
		Scan(&email, &hyUsername, &enabled)
	if err != nil {
		t.Fatalf("query inserted row: %v", err)
	}
	if email != c.Email || hyUsername != c.Hysteria2Username || !enabled {
		t.Errorf("db row mismatch: email=%s hyUsername=%s enabled=%v", email, hyUsername, enabled)
	}

	// Hysteria config now contains the new user, in plaintext.
	cfg, err := hysteria.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Auth.UserPass[c.Hysteria2Username] != c.Hysteria2Password {
		t.Errorf("hysteria config missing new user: %+v", cfg.Auth.UserPass)
	}
}

func TestCreateDefaultsWhenExpiryNil(t *testing.T) {
	pool := testPool(t)
	cryptor := testCryptor(t)
	configPath := testHysteriaConfig(t)

	panel := newMockXUIServer(t, alwaysSuccess)
	svc := NewService(pool, panel, cryptor, 1, configPath, "true")

	c, err := svc.Create(context.Background(), CreateParams{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if c.ExpiresAt != nil {
		t.Errorf("ExpiresAt = %v, want nil", c.ExpiresAt)
	}
}

func TestCreatePreservesExistingHysteriaUsers(t *testing.T) {
	pool := testPool(t)
	cryptor := testCryptor(t)
	configPath := testHysteriaConfig(t)

	panel := newMockXUIServer(t, alwaysSuccess)
	svc := NewService(pool, panel, cryptor, 1, configPath, "true")

	c1, err := svc.Create(context.Background(), CreateParams{})
	if err != nil {
		t.Fatalf("Create 1: %v", err)
	}
	c2, err := svc.Create(context.Background(), CreateParams{})
	if err != nil {
		t.Fatalf("Create 2: %v", err)
	}

	cfg, err := hysteria.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Auth.UserPass) != 2 {
		t.Fatalf("userpass map = %v, want 2 entries", cfg.Auth.UserPass)
	}
	if cfg.Auth.UserPass[c1.Hysteria2Username] != c1.Hysteria2Password {
		t.Errorf("client 1 missing from userpass map after client 2 was created")
	}
	if cfg.Auth.UserPass[c2.Hysteria2Username] != c2.Hysteria2Password {
		t.Errorf("client 2 missing from userpass map")
	}
}

func TestCreateRollsBackOnXUIFailure(t *testing.T) {
	pool := testPool(t)
	cryptor := testCryptor(t)
	configPath := testHysteriaConfig(t)

	panel := newMockXUIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"success": false, "msg": "boom"})
	})

	svc := NewService(pool, panel, cryptor, 1, configPath, "true")

	if _, err := svc.Create(context.Background(), CreateParams{}); err == nil {
		t.Fatalf("expected error")
	}

	var count int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM clients").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("expected client row to be rolled back, found %d rows", count)
	}

	cfg, err := hysteria.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Auth.UserPass) != 0 {
		t.Errorf("hysteria config should be untouched, got %v", cfg.Auth.UserPass)
	}
}

func TestCreateRollsBackOnHysteriaFailure(t *testing.T) {
	pool := testPool(t)
	cryptor := testCryptor(t)
	configPath := testHysteriaConfig(t)

	var deleteCalled bool
	panel := newMockXUIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "delClient") {
			deleteCalled = true
		}
		alwaysSuccess(w, r)
	})

	svc := NewService(pool, panel, cryptor, 1, configPath, "exit 1")

	if _, err := svc.Create(context.Background(), CreateParams{}); err == nil {
		t.Fatalf("expected error")
	}

	if !deleteCalled {
		t.Errorf("expected xui DeleteClient rollback to be called")
	}

	var count int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM clients").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("expected client row to be rolled back, found %d rows", count)
	}
}

func TestCreateValidatesParams(t *testing.T) {
	pool := testPool(t)
	cryptor := testCryptor(t)
	configPath := testHysteriaConfig(t)
	panel := newMockXUIServer(t, alwaysSuccess)
	svc := NewService(pool, panel, cryptor, 1, configPath, "true")

	if _, err := svc.Create(context.Background(), CreateParams{TrafficLimitBytes: -1}); !errors.Is(err, ErrInvalidParams) {
		t.Errorf("TrafficLimitBytes=-1: got err %v, want ErrInvalidParams", err)
	}
	if _, err := svc.Create(context.Background(), CreateParams{LimitIP: -1}); !errors.Is(err, ErrInvalidParams) {
		t.Errorf("LimitIP=-1: got err %v, want ErrInvalidParams", err)
	}
}
