// Package session implements stateless, HMAC-signed session tokens carried
// in a cookie: no session table, no server-side revocation before expiry.
package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const KeySize = 32

// TTL is how long a signed token remains valid after Sign.
const TTL = 24 * time.Hour

// ErrInvalidToken covers every verification failure — malformed token, bad
// signature, or expiry — callers don't need to distinguish which.
var ErrInvalidToken = errors.New("invalid or expired session token")

type Signer struct {
	key []byte
}

func NewSigner(key []byte) (*Signer, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", KeySize, len(key))
	}
	return &Signer{key: key}, nil
}

// Sign returns an opaque token string encoding userID and an expiry TTL from
// now, plus that same expiry for the caller to use as the cookie's Expires.
func (s *Signer) Sign(userID int64) (token string, expiresAt time.Time) {
	expiresAt = time.Now().Add(TTL)
	payload := encodePayload(userID, expiresAt)
	return encodeToken(payload, s.sign(payload)), expiresAt
}

// Verify checks the token's signature and expiry, returning the embedded
// userID on success.
func (s *Signer) Verify(token string) (int64, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return 0, ErrInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, ErrInvalidToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, ErrInvalidToken
	}

	if !hmac.Equal(sig, s.sign(payload)) {
		return 0, ErrInvalidToken
	}

	userID, expiresAt, err := decodePayload(payload)
	if err != nil {
		return 0, ErrInvalidToken
	}
	if time.Now().After(expiresAt) {
		return 0, ErrInvalidToken
	}

	return userID, nil
}

func (s *Signer) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write(payload)
	return mac.Sum(nil)
}

func encodeToken(payload, sig []byte) string {
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// encodePayload packs userID and expiresAt (unix seconds) as two
// big-endian int64s.
func encodePayload(userID int64, expiresAt time.Time) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], uint64(userID))
	binary.BigEndian.PutUint64(buf[8:16], uint64(expiresAt.Unix()))
	return buf
}

func decodePayload(payload []byte) (userID int64, expiresAt time.Time, err error) {
	if len(payload) != 16 {
		return 0, time.Time{}, errors.New("malformed payload")
	}
	userID = int64(binary.BigEndian.Uint64(payload[0:8]))
	expiresAt = time.Unix(int64(binary.BigEndian.Uint64(payload[8:16])), 0)
	return userID, expiresAt, nil
}

// DecodeKey decodes a base64-encoded signing key, e.g. from the
// SESSION_SIGNING_KEY environment variable.
func DecodeKey(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must decode to %d bytes, got %d", KeySize, len(key))
	}
	return key, nil
}
