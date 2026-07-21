package session

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
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

// testUserID inserts a throwaway admin row so sessions.user_id's FK is
// satisfiable, and returns its generated UUID.
func testUserID(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO admins (username, password_hash) VALUES ($1, 'x') RETURNING id`,
		uuid.NewString()).Scan(&id)
	if err != nil {
		t.Fatalf("insert test admin: %v", err)
	}
	return id
}

func TestCreateAndValidateRoundTrip(t *testing.T) {
	pool := testPool(t)
	sm := NewManager(pool)
	userID := testUserID(t, pool)

	token, err := sm.CreateSession(context.Background(), userID, DefaultTTL)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if token.Value == "" {
		t.Fatal("expected non-empty token")
	}

	sess, err := sm.ValidateToken(context.Background(), token.Value)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if sess.UserID != userID {
		t.Fatalf("UserID = %v, want %v", sess.UserID, userID)
	}
}

func TestTokenHashStoredNotRawToken(t *testing.T) {
	pool := testPool(t)
	sm := NewManager(pool)
	userID := testUserID(t, pool)

	token, err := sm.CreateSession(context.Background(), userID, DefaultTTL)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	var storedHash string
	err = pool.QueryRow(context.Background(),
		`SELECT token_hash FROM sessions WHERE user_id = $1`, userID).Scan(&storedHash)
	if err != nil {
		t.Fatalf("query token_hash: %v", err)
	}
	if storedHash == token.Value {
		t.Fatal("token_hash column stores the raw token, not a hash")
	}
	if storedHash == "" {
		t.Fatal("token_hash is empty")
	}
}

func TestValidateTokenRejectsUnknownToken(t *testing.T) {
	pool := testPool(t)
	sm := NewManager(pool)

	if _, err := sm.ValidateToken(context.Background(), "deadbeef"); err != ErrInvalidToken {
		t.Fatalf("err = %v, want %v", err, ErrInvalidToken)
	}
}

func TestValidateTokenRejectsMalformedToken(t *testing.T) {
	pool := testPool(t)
	sm := NewManager(pool)

	for _, bad := range []string{"", "not-hex!!", "zz"} {
		if _, err := sm.ValidateToken(context.Background(), bad); err != ErrInvalidToken {
			t.Fatalf("ValidateToken(%q) err = %v, want %v", bad, err, ErrInvalidToken)
		}
	}
}

func TestValidateTokenRejectsExpiredToken(t *testing.T) {
	pool := testPool(t)
	sm := NewManager(pool)
	userID := testUserID(t, pool)

	token, err := sm.CreateSession(context.Background(), userID, -time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if _, err := sm.ValidateToken(context.Background(), token.Value); err != ErrInvalidToken {
		t.Fatalf("err = %v, want %v", err, ErrInvalidToken)
	}
}

func TestGetUserFromToken(t *testing.T) {
	pool := testPool(t)
	sm := NewManager(pool)
	userID := testUserID(t, pool)

	token, err := sm.CreateSession(context.Background(), userID, DefaultTTL)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := sm.GetUserFromToken(context.Background(), token.Value)
	if err != nil {
		t.Fatalf("GetUserFromToken: %v", err)
	}
	if *got != userID {
		t.Fatalf("userID = %v, want %v", *got, userID)
	}
}

func TestDestroySessionByID(t *testing.T) {
	pool := testPool(t)
	sm := NewManager(pool)
	userID := testUserID(t, pool)

	token, err := sm.CreateSession(context.Background(), userID, DefaultTTL)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sess, err := sm.ValidateToken(context.Background(), token.Value)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	if err := sm.DestroySession(context.Background(), sess.ID); err != nil {
		t.Fatalf("DestroySession: %v", err)
	}
	if _, err := sm.ValidateToken(context.Background(), token.Value); err != ErrInvalidToken {
		t.Fatalf("err after destroy = %v, want %v", err, ErrInvalidToken)
	}
}

func TestDestroySessionIsIdempotent(t *testing.T) {
	pool := testPool(t)
	sm := NewManager(pool)

	if err := sm.DestroySession(context.Background(), uuid.New()); err != nil {
		t.Fatalf("DestroySession on unknown id: %v", err)
	}
}

func TestDestroySessionByToken(t *testing.T) {
	pool := testPool(t)
	sm := NewManager(pool)
	userID := testUserID(t, pool)

	token, err := sm.CreateSession(context.Background(), userID, DefaultTTL)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if err := sm.DestroySessionByToken(context.Background(), token.Value); err != nil {
		t.Fatalf("DestroySessionByToken: %v", err)
	}
	if _, err := sm.ValidateToken(context.Background(), token.Value); err != ErrInvalidToken {
		t.Fatalf("err after destroy = %v, want %v", err, ErrInvalidToken)
	}
}

func TestDestroySessionByTokenIsIdempotent(t *testing.T) {
	pool := testPool(t)
	sm := NewManager(pool)

	if err := sm.DestroySessionByToken(context.Background(), "deadbeef"); err != nil {
		t.Fatalf("DestroySessionByToken on unknown token: %v", err)
	}
	if err := sm.DestroySessionByToken(context.Background(), "not-hex!!"); err != nil {
		t.Fatalf("DestroySessionByToken on malformed token: %v", err)
	}
}
