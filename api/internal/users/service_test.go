package users

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/session"
	"vpn-api/internal/testutil"
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
		if _, err := pool.Exec(context.Background(), "DELETE FROM sessions"); err != nil {
			t.Fatalf("clean sessions table: %v", err)
		}
		if _, err := pool.Exec(context.Background(), "DELETE FROM users"); err != nil {
			t.Fatalf("clean users table: %v", err)
		}
	}
	clean()
	t.Cleanup(clean)

	return pool
}

func testService(pool *pgxpool.Pool) *Service {
	return NewService(pool, session.NewSessionManager(pool, "sessions"))
}

func TestRegisterSuccess(t *testing.T) {
	pool := testPool(t)
	svc := testService(pool)

	before := time.Now().UTC()
	u, err := svc.Register(context.Background(), "trial@example.com", "correct-password")
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if u.Status != "trial" {
		t.Errorf("status = %q, want %q", u.Status, "trial")
	}
	if u.TrialEndsAt == nil {
		t.Fatal("trial_ends_at is nil")
	}
	wantFrom := before.Add(TrialDuration)
	wantTo := after.Add(TrialDuration)
	if u.TrialEndsAt.Before(wantFrom) || u.TrialEndsAt.After(wantTo) {
		t.Errorf("trial_ends_at = %v, want between %v and %v", u.TrialEndsAt, wantFrom, wantTo)
	}

	var hash string
	err = pool.QueryRow(context.Background(), "SELECT password_hash FROM users WHERE id = $1", u.ID).Scan(&hash)
	if err != nil {
		t.Fatalf("query password_hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("password_hash = %q, want $argon2id$ prefix", hash)
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	pool := testPool(t)
	svc := testService(pool)

	if _, err := svc.Register(context.Background(), "dup@example.com", "correct-password"); err != nil {
		t.Fatalf("Register 1: %v", err)
	}
	if _, err := svc.Register(context.Background(), "dup@example.com", "another-password"); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("Register 2: err = %v, want %v", err, ErrEmailTaken)
	}
}

func TestRegisterInvalidEmail(t *testing.T) {
	pool := testPool(t)
	svc := testService(pool)

	for _, email := range []string{"", "not-an-email", strings.Repeat("a", 321) + "@example.com"} {
		if _, err := svc.Register(context.Background(), email, "correct-password"); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Register(%q): err = %v, want %v", email, err, ErrInvalidInput)
		}
	}
}

func TestRegisterShortPassword(t *testing.T) {
	pool := testPool(t)
	svc := testService(pool)

	if _, err := svc.Register(context.Background(), "short@example.com", "short"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v, want %v", err, ErrInvalidInput)
	}
}

func TestLoginSuccess(t *testing.T) {
	pool := testPool(t)
	svc := testService(pool)

	u, err := svc.Register(context.Background(), "login@example.com", "correct-password")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, expiresAt, err := svc.Login(context.Background(), "login@example.com", "correct-password")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if expiresAt.Before(time.Now()) {
		t.Fatalf("expiresAt = %v, want a future time", expiresAt)
	}

	var count int
	err = pool.QueryRow(context.Background(), "SELECT count(*) FROM sessions WHERE user_id = $1", u.ID).Scan(&count)
	if err != nil {
		t.Fatalf("query session: %v", err)
	}
	if count != 1 {
		t.Fatalf("sessions rows for user = %d, want 1", count)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	pool := testPool(t)
	svc := testService(pool)

	if _, err := svc.Register(context.Background(), "wrongpass@example.com", "correct-password"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, _, err := svc.Login(context.Background(), "wrongpass@example.com", "wrong-password")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want %v", err, ErrInvalidCredentials)
	}
}

func TestLoginUnknownEmail(t *testing.T) {
	pool := testPool(t)
	svc := testService(pool)

	_, _, err := svc.Login(context.Background(), "ghost@example.com", "whatever")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want %v", err, ErrInvalidCredentials)
	}
}

func TestGetByIDLazyExpiry(t *testing.T) {
	pool := testPool(t)
	svc := testService(pool)

	u, err := svc.Register(context.Background(), "expiring@example.com", "correct-password")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := pool.Exec(context.Background(),
		"UPDATE users SET trial_ends_at = now() - interval '1 day' WHERE id = $1", u.ID); err != nil {
		t.Fatalf("update trial_ends_at: %v", err)
	}

	got, err := svc.GetByID(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != "trial" {
		t.Errorf("stored status = %q, want %q (lazy model never flips the DB column)", got.Status, "trial")
	}
	if effective := got.EffectiveStatus(time.Now().UTC()); effective != "expired" {
		t.Errorf("EffectiveStatus = %q, want %q", effective, "expired")
	}
}
