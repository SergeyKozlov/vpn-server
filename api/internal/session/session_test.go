package session

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"
)

func testKey() []byte {
	return bytes.Repeat([]byte("k"), KeySize)
}

func TestSignVerifyRoundTrip(t *testing.T) {
	signer, err := NewSigner(testKey())
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	token, expiresAt := signer.Sign(42)
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	if time.Until(expiresAt) > TTL || time.Until(expiresAt) < TTL-time.Second {
		t.Fatalf("expiresAt = %v, want ~%v from now", expiresAt, TTL)
	}

	userID, err := signer.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if userID != 42 {
		t.Fatalf("userID = %d, want 42", userID)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	signer, err := NewSigner(testKey())
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	token, _ := signer.Sign(42)
	tampered := token[:len(token)-1] + "x"

	if _, err := signer.Verify(tampered); err != ErrInvalidToken {
		t.Fatalf("Verify(tampered) err = %v, want %v", err, ErrInvalidToken)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	signerA, err := NewSigner(testKey())
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	signerB, err := NewSigner(bytes.Repeat([]byte("z"), KeySize))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	token, _ := signerA.Sign(42)

	if _, err := signerB.Verify(token); err != ErrInvalidToken {
		t.Fatalf("Verify with wrong key err = %v, want %v", err, ErrInvalidToken)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	signer, err := NewSigner(testKey())
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	payload := encodePayload(42, time.Now().Add(-time.Minute))
	token := encodeToken(payload, signer.sign(payload))

	if _, err := signer.Verify(token); err != ErrInvalidToken {
		t.Fatalf("Verify(expired) err = %v, want %v", err, ErrInvalidToken)
	}
}

func TestVerifyRejectsMalformedToken(t *testing.T) {
	signer, err := NewSigner(testKey())
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	for _, bad := range []string{"", "no-dot-here", "a.b.c", "!!!.!!!"} {
		if _, err := signer.Verify(bad); err != ErrInvalidToken {
			t.Fatalf("Verify(%q) err = %v, want %v", bad, err, ErrInvalidToken)
		}
	}
}

func TestNewSignerRejectsBadKeyLength(t *testing.T) {
	if _, err := NewSigner([]byte("too-short")); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestDecodeKeyRoundTrip(t *testing.T) {
	// Any 32-byte key round-trips through DecodeKey after being base64-encoded.
	key := testKey()
	encoded := base64.StdEncoding.EncodeToString(key)

	decoded, err := DecodeKey(encoded)
	if err != nil {
		t.Fatalf("DecodeKey: %v", err)
	}
	if !bytes.Equal(decoded, key) {
		t.Fatalf("decoded = %v, want %v", decoded, key)
	}
}
