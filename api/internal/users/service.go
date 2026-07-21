// Package users implements client (end-customer) self-registration and
// login (AC-6.9, AC-6.6). It is the client-facing counterpart to
// internal/auth, which authenticates panel admins — the two are kept
// separate so the admin and client session circuits never share code paths.
package users

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/domain"
	"vpn-api/internal/password"
	"vpn-api/internal/session"
)

// TrialDuration is how long a newly registered user's trial lasts (TZ
// P2.3 §1.1: time-based only, no traffic accounting).
const TrialDuration = 5 * 24 * time.Hour

const maxEmailLength = 320

// ErrInvalidInput covers a malformed email or too-short password on
// Register.
var ErrInvalidInput = errors.New("invalid email or password")

// ErrEmailTaken means a live (non-soft-deleted) user already owns this
// email.
var ErrEmailTaken = errors.New("email already registered")

// ErrInvalidCredentials covers both an unknown email and a wrong password
// on Login — callers must not distinguish the two in responses (no user
// enumeration).
var ErrInvalidCredentials = errors.New("invalid email or password")

// ErrNotFound means GetByID found no live user for the given ID — only
// reachable if the user was soft-deleted after their session was created.
var ErrNotFound = errors.New("user not found")

// dummyHash is a real Argon2id hash of an unrelated, fixed password. It's
// compared against on an unknown email so Login takes roughly the same
// time whether the email exists or not — same technique as internal/auth.
const dummyHash = "$argon2id$v=19$m=32768,t=3,p=1$j/NqoamR1wG3VSwtXr1Afw$XlfEmrHn0bJqxkmu693XxeGqnoOrFd0/K/XqRgxRiE0"

type Service struct {
	pool     *pgxpool.Pool
	sessions *session.SessionManager
}

func NewService(pool *pgxpool.Pool, sessions *session.SessionManager) *Service {
	return &Service{pool: pool, sessions: sessions}
}

// Register creates a new trial user. Tunnel credentials are not issued
// here — that's P2.4's bootstrap flow; this only creates the users row.
func (s *Service) Register(ctx context.Context, email, plaintextPassword string) (*domain.User, error) {
	if !validEmail(email) || len(plaintextPassword) < 8 {
		return nil, ErrInvalidInput
	}

	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND deleted_at IS NULL)`, email).Scan(&exists)
	if err != nil {
		return nil, fmt.Errorf("check email uniqueness: %w", err)
	}
	if exists {
		return nil, ErrEmailTaken
	}

	hash, err := password.Hash(plaintextPassword)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	u := &domain.User{Email: email, Status: "trial"}
	err = s.pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, status, trial_ends_at)
		 VALUES ($1, $2, 'trial', now() + interval '5 days')
		 RETURNING id, status, trial_ends_at, created_at, updated_at`,
		email, hash).Scan(&u.ID, &u.Status, &u.TrialEndsAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrEmailTaken
		}
		return nil, fmt.Errorf("insert user: %w", err)
	}

	return u, nil
}

// Login authenticates a client by email and password and, on success,
// starts a new session in the sessions table (client circuit — never
// admin_sessions).
func (s *Service) Login(ctx context.Context, email, plaintextPassword string) (token string, expiresAt time.Time, err error) {
	var userID uuid.UUID
	var hash string
	err = s.pool.QueryRow(ctx,
		`SELECT id, password_hash FROM users WHERE email = $1 AND deleted_at IS NULL`, email).
		Scan(&userID, &hash)
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

	tok, err := s.sessions.CreateSession(ctx, userID, session.DefaultTTL)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("create session: %w", err)
	}
	return tok.Value, tok.ExpiresAt, nil
}

// Logout destroys the session backing token. Idempotent: an unknown or
// already-expired token is not an error.
func (s *Service) Logout(ctx context.Context, token string) error {
	return s.sessions.DestroySessionByToken(ctx, token)
}

// GetByID fetches a live (non-soft-deleted) user by ID, for GET /auth/me.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	u := &domain.User{ID: id}
	err := s.pool.QueryRow(ctx,
		`SELECT email, status, trial_ends_at FROM users WHERE id = $1 AND deleted_at IS NULL`, id).
		Scan(&u.Email, &u.Status, &u.TrialEndsAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query user: %w", err)
	}
	return u, nil
}

func validEmail(email string) bool {
	return email != "" && len(email) <= maxEmailLength && strings.Contains(email, "@")
}
