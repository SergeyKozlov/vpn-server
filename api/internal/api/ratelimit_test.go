package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoginRateLimiterAllowsWithinLimit(t *testing.T) {
	limiter := newLoginRateLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !limiter.allow("1.2.3.4") {
			t.Fatalf("attempt %d: expected allow", i+1)
		}
	}
}

func TestLoginRateLimiterBlocksOverLimit(t *testing.T) {
	limiter := newLoginRateLimiter(2, time.Minute)

	limiter.allow("1.2.3.4")
	limiter.allow("1.2.3.4")
	if limiter.allow("1.2.3.4") {
		t.Fatal("expected block on 3rd attempt")
	}
}

func TestLoginRateLimiterTracksKeysIndependently(t *testing.T) {
	limiter := newLoginRateLimiter(1, time.Minute)

	if !limiter.allow("1.2.3.4") {
		t.Fatal("expected allow for first key")
	}
	if !limiter.allow("5.6.7.8") {
		t.Fatal("expected allow for a different key")
	}
}

func TestLoginRateLimiterResetsAfterWindow(t *testing.T) {
	limiter := newLoginRateLimiter(1, 10*time.Millisecond)

	if !limiter.allow("1.2.3.4") {
		t.Fatal("expected allow for first attempt")
	}
	time.Sleep(20 * time.Millisecond)
	if !limiter.allow("1.2.3.4") {
		t.Fatal("expected allow after window reset")
	}
}

func TestLoginRateLimiterEvictsStaleEntries(t *testing.T) {
	limiter := newLoginRateLimiter(1, 10*time.Millisecond)

	limiter.allow("1.2.3.4")
	time.Sleep(20 * time.Millisecond)
	limiter.allow("5.6.7.8")

	limiter.mu.Lock()
	_, stale := limiter.attempts["1.2.3.4"]
	limiter.mu.Unlock()
	if stale {
		t.Fatal("expected stale entry for 1.2.3.4 to be evicted")
	}
}

func TestClientIPSplitsPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:54321"

	if got := clientIP(req); got != "203.0.113.5" {
		t.Fatalf("clientIP = %q, want %q", got, "203.0.113.5")
	}
}
