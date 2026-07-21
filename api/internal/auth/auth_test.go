package auth

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/password"
	"vpn-api/internal/session"
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

func testSessionManager(pool *pgxpool.Pool) *session.SessionManager {
	return session.NewManager(pool)
}

func createUser(t *testing.T, pool *pgxpool.Pool, username, plaintextPassword string) uuid.UUID {
	t.Helper()
	hash, err := password.Hash(plaintextPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	var id uuid.UUID
	err = pool.QueryRow(context.Background(),
		`INSERT INTO admins (username, password_hash) VALUES ($1, $2) RETURNING id`,
		username, hash).Scan(&id)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return id
}

func TestDummyHashIsValid(t *testing.T) {
	// The unknown-username path relies on dummyHash being a well-formed
	// argon2id hash so password.Verify burns full verification time. A
	// malformed constant would fail fast and reopen the timing side-channel.
	match, err := password.Verify("any-password", dummyHash)
	if err != nil {
		t.Fatalf("dummyHash is malformed: %v", err)
	}
	if match {
		t.Fatal("dummyHash unexpectedly matches an arbitrary password")
	}
}

func TestLoginSuccess(t *testing.T) {
	pool := testPool(t)
	wantID := createUser(t, pool, "admin", "correct-password")

	sm := testSessionManager(pool)
	svc := NewService(pool, sm)

	token, expiresAt, err := svc.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if expiresAt.Before(time.Now()) {
		t.Fatalf("expiresAt = %v, want a future time", expiresAt)
	}

	gotID, err := sm.GetUserFromToken(context.Background(), token)
	if err != nil {
		t.Fatalf("GetUserFromToken: %v", err)
	}
	if *gotID != wantID {
		t.Fatalf("userID = %v, want %v", *gotID, wantID)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	pool := testPool(t)
	createUser(t, pool, "admin", "correct-password")
	svc := NewService(pool, testSessionManager(pool))

	_, _, err := svc.Login(context.Background(), "admin", "wrong-password")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want %v", err, ErrInvalidCredentials)
	}
}

func TestLoginUnknownUsername(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool, testSessionManager(pool))

	_, _, err := svc.Login(context.Background(), "ghost", "whatever")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want %v", err, ErrInvalidCredentials)
	}
}

func TestLogout(t *testing.T) {
	pool := testPool(t)
	createUser(t, pool, "admin", "correct-password")

	sm := testSessionManager(pool)
	svc := NewService(pool, sm)

	token, _, err := svc.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if err := svc.Logout(context.Background(), token); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	if _, err := sm.ValidateToken(context.Background(), token); err != session.ErrInvalidToken {
		t.Fatalf("ValidateToken after logout: err = %v, want %v", err, session.ErrInvalidToken)
	}
}

func TestLogoutIsIdempotent(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool, testSessionManager(pool))

	if err := svc.Logout(context.Background(), "deadbeef"); err != nil {
		t.Fatalf("Logout on unknown token: %v", err)
	}
}
