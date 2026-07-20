package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// loginRateLimiter is a simple fixed-window counter keyed by client IP,
// scoped to the /login route. It's in-memory only — state resets on
// process restart and isn't shared across multiple API instances, which is
// fine for Phase 1's single-instance deployment.
type loginRateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	attempts map[string]*attemptWindow
}

type attemptWindow struct {
	count      int
	windowFrom time.Time
}

func newLoginRateLimiter(limit int, window time.Duration) *loginRateLimiter {
	return &loginRateLimiter{
		limit:    limit,
		window:   window,
		attempts: make(map[string]*attemptWindow),
	}
}

// allow reports whether key (the client IP) may make another attempt right
// now, incrementing its counter if so.
func (l *loginRateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	// Prune expired entries opportunistically while holding the mutex.
	for ip, w := range l.attempts {
		if now.Sub(w.windowFrom) > l.window {
			delete(l.attempts, ip)
		}
	}

	w, ok := l.attempts[key]
	if !ok || now.Sub(w.windowFrom) > l.window {
		l.attempts[key] = &attemptWindow{count: 1, windowFrom: now}
		return true
	}

	if w.count >= l.limit {
		return false
	}
	w.count++
	return true
}

// clientIP returns the request's network peer address. TODO: once the API
// sits behind the planned Caddy reverse proxy, RemoteAddr is always the
// proxy — switch to X-Forwarded-For (trusting only the local proxy hop),
// or every internet client will share one rate-limit bucket.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
