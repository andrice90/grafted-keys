// Package auth owns session/DEK custody and login throttling. The decrypted data
// key lives only here, in process memory, and is zeroized on lock/expiry.
package auth

import (
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/andrew/grafted-secrets/internal/crypto"
)

// Session holds per-login state. DEK is nil for a pre-auth (login-form) session.
// Pending marks a session whose passphrase verified but whose TOTP is still
// outstanding: the DEK exists in RAM (it had to decrypt the TOTP secret) but the
// vault is NOT usable until TOTP passes.
type Session struct {
	ID       string
	DEK      []byte
	CSRF     string
	Pending  bool
	created  time.Time
	lastSeen time.Time
}

func (s *Session) Unlocked() bool { return s != nil && s.DEK != nil && !s.Pending }

// pendingTTL bounds how long a passphrase-verified, TOTP-outstanding session
// (which holds the DEK in RAM) may live before it is scrubbed.
const pendingTTL = 2 * time.Minute

type Sessions struct {
	mu        sync.Mutex
	m         map[string]*Session
	idle, max time.Duration
}

// expired reports whether sess has timed out (caller holds the lock). Pending
// sessions get a short fixed TTL and do not have their idle timer refreshed.
func (s *Sessions) expired(sess *Session, now time.Time) bool {
	if sess.Pending {
		return now.Sub(sess.created) > pendingTTL
	}
	return now.Sub(sess.lastSeen) > s.idle || now.Sub(sess.created) > s.max
}

func NewSessions(idle, max time.Duration) *Sessions {
	return &Sessions{m: make(map[string]*Session), idle: idle, max: max}
}

// New creates a session with a fresh CSPRNG id and CSRF token. dek may be nil
// (pre-auth); pending marks a TOTP-outstanding session. The returned Session
// must be treated as read-only by callers.
func (s *Sessions) New(dek []byte, pending bool) *Session {
	now := time.Now()
	sess := &Session{ID: token(), DEK: dek, CSRF: token(), Pending: pending, created: now, lastSeen: now}
	s.mu.Lock()
	s.m[sess.ID] = sess
	s.mu.Unlock()
	return sess
}

// Get returns a live session, refreshing its idle timer. Expired sessions are
// evicted (DEK zeroized) and reported missing.
func (s *Sessions) Get(id string) (*Session, bool) {
	if id == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return nil, false
	}
	now := time.Now()
	if s.expired(sess, now) {
		s.evict(id)
		return nil, false
	}
	if !sess.Pending {
		sess.lastSeen = now // pending sessions cannot extend their grace window
	}
	return sess, true
}

// Promote rotates a pending session into a fully-unlocked one: a fresh id and
// CSRF token (defeating fixation) while transferring the existing DEK (not
// zeroized). Returns nil if the id is unknown.
func (s *Sessions) Promote(id string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return nil
	}
	delete(s.m, id)
	now := time.Now()
	sess.ID = token()
	sess.CSRF = token()
	sess.Pending = false
	sess.created = now
	sess.lastSeen = now
	s.m[sess.ID] = sess
	return sess
}

// Delete locks/destroys a session, zeroizing its DEK.
func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	s.evict(id)
	s.mu.Unlock()
}

// SetDEK replaces a session's data key (used after a DEK rotation), zeroizing
// the old one.
func (s *Sessions) SetDEK(id string, dek []byte) {
	s.mu.Lock()
	if sess, ok := s.m[id]; ok {
		crypto.Zero(sess.DEK)
		sess.DEK = dek
	}
	s.mu.Unlock()
}

// EvictExpired scrubs all timed-out sessions; call periodically so keys don't
// linger in RAM after idle even without a triggering request.
func (s *Sessions) EvictExpired() {
	now := time.Now()
	s.mu.Lock()
	for id, sess := range s.m {
		if s.expired(sess, now) {
			s.evict(id)
		}
	}
	s.mu.Unlock()
}

// evict requires s.mu held.
func (s *Sessions) evict(id string) {
	if sess, ok := s.m[id]; ok {
		crypto.Zero(sess.DEK)
		delete(s.m, id)
	}
}

func token() string {
	b, err := crypto.RandBytes(32)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ClientIP returns the throttling key. With trustProxy it uses the rightmost
// X-Forwarded-For entry (the address our single trusted proxy observed),
// otherwise the direct peer. TRUST_PROXY must only be set behind exactly one
// trusted proxy.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
