// Package crypto provides AES-256-GCM encryption for secret columns at rest
// (VLESS UUIDs, Hysteria2 passwords).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const KeySize = 32

// AESGCM encrypts and decrypts data with a fixed 32-byte key. The nonce is
// generated fresh per call and prepended to the returned ciphertext.
type AESGCM struct {
	gcm cipher.AEAD
}

func NewAESGCM(key []byte) (*AESGCM, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", KeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	return &AESGCM{gcm: gcm}, nil
}

func (a *AESGCM) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, a.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	return a.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (a *AESGCM) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := a.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return a.gcm.Open(nil, nonce, ct, nil)
}

// DecodeKey decodes a base64-encoded 32-byte AES-256 key, e.g. from the
// APP_ENC_KEY environment variable.
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
