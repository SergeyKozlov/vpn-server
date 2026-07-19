package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	a, err := NewAESGCM(testKey(t))
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}

	plaintext := []byte("95e4e7bb-7f3e-4a1e-9d6a-0b2c3d4e5f60")

	ciphertext, err := a.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Contains(ciphertext, plaintext) {
		t.Fatalf("ciphertext contains plaintext verbatim")
	}

	got, err := a.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestEncryptNonceIsRandom(t *testing.T) {
	a, err := NewAESGCM(testKey(t))
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}

	plaintext := []byte("same plaintext")

	c1, err := a.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	c2, err := a.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(c1, c2) {
		t.Fatalf("two encryptions of the same plaintext produced identical ciphertext")
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	a1, err := NewAESGCM(testKey(t))
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}
	a2, err := NewAESGCM(testKey(t))
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}

	ciphertext, err := a1.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := a2.Decrypt(ciphertext); err == nil {
		t.Fatalf("expected error decrypting with the wrong key, got nil")
	}
}

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	a, err := NewAESGCM(testKey(t))
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}

	ciphertext, err := a.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tampered := bytes.Clone(ciphertext)
	tampered[len(tampered)-1] ^= 0xFF

	if _, err := a.Decrypt(tampered); err == nil {
		t.Fatalf("expected error decrypting tampered ciphertext, got nil")
	}
}

func TestDecryptTooShortFails(t *testing.T) {
	a, err := NewAESGCM(testKey(t))
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}

	if _, err := a.Decrypt([]byte("short")); err == nil {
		t.Fatalf("expected error decrypting too-short ciphertext, got nil")
	}
}

func TestNewAESGCMRejectsWrongKeySize(t *testing.T) {
	cases := []int{0, 15, 16, 24, 31, 33, 64}
	for _, n := range cases {
		if _, err := NewAESGCM(make([]byte, n)); err == nil {
			t.Errorf("expected error for key size %d, got nil", n)
		}
	}
}

func TestDecodeKey(t *testing.T) {
	key := testKey(t)
	encoded := base64.StdEncoding.EncodeToString(key)

	got, err := DecodeKey(encoded)
	if err != nil {
		t.Fatalf("DecodeKey: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("DecodeKey mismatch")
	}
}

func TestDecodeKeyRejectsInvalidInput(t *testing.T) {
	if _, err := DecodeKey("not-valid-base64!!"); err == nil {
		t.Fatalf("expected error for invalid base64, got nil")
	}
	if _, err := DecodeKey(base64.StdEncoding.EncodeToString([]byte("too-short"))); err == nil {
		t.Fatalf("expected error for wrong decoded length, got nil")
	}
}
