// Package auth authenticates panel admins against the users table and
// issues signed session tokens. HTTP concerns (cookies, rate limiting) live
// in internal/api; this package is pure business logic.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/password"
	"vpn-api/internal/session"
)

// ErrInvalidCredentials covers both an unknown username and a wrong
// password — callers must not distinguish the two in responses (no user
// enumeration).
var ErrInvalidCredentials = errors.New("invalid username or password")

// dummyHash is a real Argon2id hash of an unrelated, fixed password. It's
// compared against on an unknown username so Login takes roughly the same
// time whether the username exists or not.
const dummyHash = "$argon2id$v=19$m=32768,t=3,p=1$j/NqoamR1wG3VSwtXr1Afw$XlfEmrHn0bJqxkmu693XxeGqnoOrFd0/K/XqRgxRiE0"

type Service struct {
	pool   *pgxpool.Pool
	signer *session.Signer
}

func NewService(pool *pgxpool.Pool, signer *session.Signer) *Service {
	return &Service{pool: pool, signer: signer}
}

func (s *Service) Login(ctx context.Context, username, plaintextPassword string) (token string, expiresAt time.Time, err error) {
	var userID int64
	var hash string
	err = s.pool.QueryRow(ctx, `SELECT id, password_hash FROM users WHERE username = $1`, username).Scan(&userID, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		_, _ = password.Verify(plaintextPassword, dummyHash)
		return "", time.Time{}, ErrInvalidCredentials
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("query user: %w", err)
	}

	ok, err := password.Verify(plaintextPassword, hash)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return "", time.Time{}, ErrInvalidCredentials
	}

	token, expiresAt = s.signer.Sign(userID)
	return token, expiresAt, nil
}
