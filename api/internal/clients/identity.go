package clients

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

// randomSuffix returns enough entropy (16 hex chars = 64 bits) that
// collisions across the unique email/hysteria2_username/sub_id columns are
// astronomically unlikely; a collision simply surfaces as a unique
// constraint violation from the INSERT, with no retry loop.
func randomSuffix() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random suffix: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func randomPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomVlessUUID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate vless uuid: %w", err)
	}
	return id.String(), nil
}
