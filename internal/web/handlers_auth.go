package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/andrew/grafted-secrets/internal/auth"
	"github.com/andrew/grafted-secrets/internal/crypto"
	"github.com/andrew/grafted-secrets/internal/vault"
)

func retryAfterSecs(d time.Duration) string {
	secs := int(d.Seconds())
	if secs < 1 {
		secs = 1
	}
	return fmt.Sprintf("%d", secs)
}

const minPassphrase = 8

type authView struct {
	Base
	Error string
	Stage string // "passphrase" or "totp" (unlock page only)
}

// preauth returns the current session, creating a pre-auth (DEK-less) session
// with a cookie if none exists - so login forms can carry a CSRF token.
func (s *Server) preauth(w http.ResponseWriter, r *http.Request) *auth.Session {
	if sess := sessionFrom(r.Context()); sess != nil {
		return sess
	}
	sess := s.sessions.New(nil, false)
	s.setSessionCookie(w, sess.ID)
	return sess
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, dest string) {
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", dest)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// ---- setup ----

func (s *Server) getSetup(w http.ResponseWriter, r *http.Request) {
	if init, _ := s.vault.Initialized(); init {
		http.Redirect(w, r, "/unlock", http.StatusSeeOther)
		return
	}
	sess := s.preauth(w, r)
	s.rd.Page(w, r, "setup", authView{Base: s.authBase(r, sess)})
}

func (s *Server) postSetup(w http.ResponseWriter, r *http.Request) {
	sess := s.preauth(w, r)
	pass := r.FormValue("passphrase")
	confirm := r.FormValue("confirm")

	render := func(msg string) {
		s.rd.Page(w, r, "setup", authView{Base: s.authBase(r, sess), Error: msg})
	}
	if len([]rune(pass)) < minPassphrase {
		render("Passphrase must be at least 8 characters.")
		return
	}
	if pass != confirm {
		render("Passphrases do not match.")
		return
	}

	pb := []byte(pass)
	dek, err := s.vault.Setup(pb)
	crypto.Zero(pb)
	if err != nil {
		if errors.Is(err, vault.ErrAlreadyInit) {
			http.Redirect(w, r, "/unlock", http.StatusSeeOther)
			return
		}
		render("Could not initialize vault: " + err.Error())
		return
	}
	s.sessions.Delete(sess.ID)
	newSess := s.sessions.New(dek, false)
	s.setSessionCookie(w, newSess.ID)
	s.redirect(w, r, "/")
}

// ---- unlock ----

func (s *Server) getUnlock(w http.ResponseWriter, r *http.Request) {
	if init, _ := s.vault.Initialized(); !init {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if sess := sessionFrom(r.Context()); sess.Unlocked() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	sess := s.preauth(w, r)
	s.rd.Page(w, r, "unlock", authView{Base: s.authBase(r, sess), Stage: "passphrase"})
}

func (s *Server) postUnlock(w http.ResponseWriter, r *http.Request) {
	sess := s.preauth(w, r)
	ip := auth.ClientIP(r, s.cfg.TrustProxy)

	render := func(stage, msg string) {
		s.rd.Page(w, r, "unlock", authView{Base: s.authBase(r, sess), Stage: stage, Error: msg})
	}
	if !s.limiter.Allowed(ip) {
		w.Header().Set("Retry-After", retryAfterSecs(s.limiter.RetryAfter(ip)))
		w.WriteHeader(http.StatusTooManyRequests)
		render("passphrase", "Too many attempts. Try again later.")
		return
	}

	pb := []byte(r.FormValue("passphrase"))
	dek, err := s.vault.Unlock(pb)
	crypto.Zero(pb)
	if errors.Is(err, vault.ErrNotInit) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.limiter.Fail(ip)
		render("passphrase", "Incorrect passphrase.")
		return
	}

	if enabled, _ := s.vault.TOTPEnabled(); enabled {
		// Hold the DEK in a pending session; the vault is not usable until TOTP.
		s.sessions.Delete(sess.ID)
		pending := s.sessions.New(dek, true)
		s.setSessionCookie(w, pending.ID)
		s.rd.Page(w, r, "unlock", authView{Base: s.authBase(r, pending), Stage: "totp"})
		return
	}

	s.limiter.Reset(ip)
	s.sessions.Delete(sess.ID)
	full := s.sessions.New(dek, false)
	s.setSessionCookie(w, full.ID)
	s.redirect(w, r, "/")
}

func (s *Server) postUnlockTOTP(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	if sess == nil || sess.DEK == nil || !sess.Pending {
		http.Redirect(w, r, "/unlock", http.StatusSeeOther)
		return
	}
	ip := auth.ClientIP(r, s.cfg.TrustProxy)
	render := func(msg string) {
		s.rd.Page(w, r, "unlock", authView{Base: s.authBase(r, sess), Stage: "totp", Error: msg})
	}
	if !s.limiter.Allowed(ip) {
		w.Header().Set("Retry-After", retryAfterSecs(s.limiter.RetryAfter(ip)))
		w.WriteHeader(http.StatusTooManyRequests)
		render("Too many attempts. Try again later.")
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))
	ok, err := s.vault.VerifyLoginTOTP(sess.DEK, code)
	if err != nil || !ok {
		s.limiter.Fail(ip)
		render("Incorrect code.")
		return
	}

	s.limiter.Reset(ip)
	full := s.sessions.Promote(sess.ID) // rotates id+csrf, keeps DEK
	if full == nil {
		http.Redirect(w, r, "/unlock", http.StatusSeeOther)
		return
	}
	s.setSessionCookie(w, full.ID)
	s.redirect(w, r, "/")
}

func (s *Server) postLock(w http.ResponseWriter, r *http.Request) {
	if sess := sessionFrom(r.Context()); sess != nil {
		s.sessions.Delete(sess.ID)
	}
	s.clearSessionCookie(w)
	s.redirect(w, r, "/unlock")
}
