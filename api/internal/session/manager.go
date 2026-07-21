// Package session implements serverside sessions: an opaque random token is
// handed to the client, and only its SHA-256 hash is stored in a sessions
// table (AC-6.9) — never the token itself. Validating a request means
// hashing the presented token and looking it up, so a session can be
// revoked instantly by deleting its row, unlike a stateless signed cookie.
// SessionManager is generic over which table it uses, since admins and
// end-customer users each get their own independent session store
// (admin_sessions, sessions) — see NewSessionManager.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TokenSize is the number of random bytes a token is generated from.
const TokenSize = 32

// DefaultTTL is how long a session remains valid after CreateSession.
const DefaultTTL = 24 * time.Hour

// ErrInvalidToken covers every verification failure — malformed token, no
// matching row, or an expired one — callers don't need to distinguish which.
var ErrInvalidToken = errors.New("invalid or expired session token")

// allowedTables is the set of tables SessionManager may be constructed
// against. The table name is interpolated into SQL via fmt.Sprintf (never
// user input), but this allowlist guards against future misuse.
var allowedTables = map[string]bool{"sessions": true, "admin_sessions": true}

// SessionManager manages serverside sessions backed by a sessions-shaped
// table (sessions for clients, admin_sessions for panel admins).
type SessionManager struct {
	pool  *pgxpool.Pool
	table string
}

// Session is a row from the sessions table.
type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Token is what's handed to the client (cookie value). Value is the raw
// token — never store this anywhere, only its hash.
type Token struct {
	Value     string
	ExpiresAt time.Time
}

// NewSessionManager constructs a SessionManager backed by table. table must
// be one of allowedTables; any other value panics — this isn't reachable
// with user input, but catches a wiring mistake immediately instead of
// silently querying the wrong table.
func NewSessionManager(pool *pgxpool.Pool, table string) *SessionManager {
	if !allowedTables[table] {
		panic(fmt.Sprintf("session: table %q is not in the allowlist", table))
	}
	return &SessionManager{pool: pool, table: table}
}

// CreateSession generates a new random token, stores its hash, and returns
// the original token for the caller to send to the client.
func (sm *SessionManager) CreateSession(ctx context.Context, userID uuid.UUID, ttl time.Duration) (*Token, error) {
	raw := make([]byte, TokenSize)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	token := hex.EncodeToString(raw)
	hash := hashToken(raw)
	expiresAt := time.Now().UTC().Add(ttl)

	_, err := sm.pool.Exec(ctx,
		fmt.Sprintf(`INSERT INTO %s (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`, sm.table),
		userID, hash, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("insert session: %w", err)
	}

	return &Token{Value: token, ExpiresAt: expiresAt}, nil
}

// ValidateToken hashes the presented token and looks up a non-expired
// session for it.
func (sm *SessionManager) ValidateToken(ctx context.Context, token string) (*Session, error) {
	raw, err := hex.DecodeString(token)
	if err != nil {
		return nil, ErrInvalidToken
	}
	hash := hashToken(raw)

	var s Session
	err = sm.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT id, user_id, token_hash, expires_at, created_at
		   FROM %s
		  WHERE token_hash = $1 AND expires_at > now()`, sm.table),
		hash).Scan(&s.ID, &s.UserID, &s.TokenHash, &s.ExpiresAt, &s.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, fmt.Errorf("query session: %w", err)
	}

	return &s, nil
}

// GetUserFromToken validates token and returns the owning user's ID.
func (sm *SessionManager) GetUserFromToken(ctx context.Context, token string) (*uuid.UUID, error) {
	s, err := sm.ValidateToken(ctx, token)
	if err != nil {
		return nil, err
	}
	return &s.UserID, nil
}

// DestroySession deletes a session by ID. Idempotent: deleting an
// already-gone session is not an error.
func (sm *SessionManager) DestroySession(ctx context.Context, sessionID uuid.UUID) error {
	_, err := sm.pool.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, sm.table), sessionID)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// DestroySessionByToken deletes the session matching token's hash, without
// regard to expiry. Idempotent: an unknown or already-expired token is not
// an error — logout on a dead session is still a successful logout.
func (sm *SessionManager) DestroySessionByToken(ctx context.Context, token string) error {
	raw, err := hex.DecodeString(token)
	if err != nil {
		return nil
	}
	hash := hashToken(raw)

	_, err = sm.pool.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE token_hash = $1`, sm.table), hash)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func hashToken(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
