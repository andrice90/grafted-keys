package auth

import (
	"sync"
	"time"
)

// Limiter throttles failed unlock attempts. It enforces BOTH a per-IP lockout
// and a global lockout — the global one cannot be bypassed by rotating source
// IPs (e.g. via spoofed X-Forwarded-For), which is the real backstop for a
// single-user vault.
type Limiter struct {
	mu sync.Mutex

	perIP   map[string]*bucket
	global  bucket
	maxIP   int
	maxAll  int
	window  time.Duration // failures older than this decay
	lockout time.Duration
}

type bucket struct {
	fails int
	first time.Time
	until time.Time // locked until
}

func NewLimiter() *Limiter {
	return &Limiter{
		perIP:   make(map[string]*bucket),
		maxIP:   5,
		maxAll:  20,
		window:  10 * time.Minute,
		lockout: 15 * time.Minute,
	}
}

// Allowed reports whether an unlock attempt from ip may proceed now.
func (l *Limiter) Allowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Before(l.global.until) {
		return false
	}
	if b, ok := l.perIP[ip]; ok && now.Before(b.until) {
		return false
	}
	return true
}

// Fail records a failed attempt and applies lockouts when thresholds are hit.
func (l *Limiter) Fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	b := l.perIP[ip]
	if b == nil || now.Sub(b.first) > l.window {
		b = &bucket{first: now}
		l.perIP[ip] = b
	}
	b.fails++
	if b.fails >= l.maxIP {
		b.until = now.Add(l.lockout)
	}

	if now.Sub(l.global.first) > l.window {
		l.global = bucket{first: now}
	}
	l.global.fails++
	if l.global.fails >= l.maxAll {
		l.global.until = now.Add(l.lockout)
	}
}

// Reset clears an IP's failure count after a successful unlock.
func (l *Limiter) Reset(ip string) {
	l.mu.Lock()
	delete(l.perIP, ip)
	l.mu.Unlock()
}

// Sweep drops decayed per-IP buckets so the map cannot grow unbounded. Call it
// periodically.
func (l *Limiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for ip, b := range l.perIP {
		if now.After(b.until) && now.Sub(b.first) > l.window {
			delete(l.perIP, ip)
		}
	}
}

// RetryAfter reports how long until attempts from ip are allowed again.
func (l *Limiter) RetryAfter(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	until := l.global.until
	if b, ok := l.perIP[ip]; ok && b.until.After(until) {
		until = b.until
	}
	if d := time.Until(until); d > 0 {
		return d
	}
	return 0
}
