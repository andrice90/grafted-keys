package web

import (
	"net/http"
	"strings"

	"github.com/andrew/grafted-secrets/internal/auth"
	"github.com/andrew/grafted-secrets/internal/crypto"
)

type settingsView struct {
	Base
	TOTPEnabled bool
	Message     string
	Error       string
}

type totpEnrollView struct {
	Secret string
	URI    string
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, sess *auth.Session, msg, errMsg string) {
	enabled, _ := s.vault.TOTPEnabled()
	b := s.base(r, sess)
	b.TOTPEnabled = enabled
	s.rd.Page(w, r, "settings", settingsView{Base: b, TOTPEnabled: enabled, Message: msg, Error: errMsg})
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	s.renderSettings(w, r, sess, "", "")
}

func (s *Server) changePassphrase(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	ip := auth.ClientIP(r, s.cfg.TrustProxy)
	if !s.limiter.Allowed(ip) {
		w.Header().Set("Retry-After", retryAfterSecs(s.limiter.RetryAfter(ip)))
		w.WriteHeader(http.StatusTooManyRequests)
		s.renderSettings(w, r, sess, "", "Too many attempts. Try again later.")
		return
	}
	newPass := r.FormValue("new")
	confirm := r.FormValue("confirm")
	if len([]rune(newPass)) < minPassphrase {
		s.renderSettings(w, r, sess, "", "New passphrase must be at least 8 characters.")
		return
	}
	if newPass != confirm {
		s.renderSettings(w, r, sess, "", "New passphrases do not match.")
		return
	}

	// Re-verify the current passphrase and use the DEK it yields (never a
	// possibly-stale session DEK) for the re-wrap.
	current := []byte(r.FormValue("current"))
	verifyDEK, err := s.vault.Unlock(current)
	crypto.Zero(current)
	if err != nil {
		s.limiter.Fail(ip)
		s.renderSettings(w, r, sess, "", "Current passphrase is incorrect.")
		return
	}
	s.limiter.Reset(ip)

	np := []byte(newPass)
	err = s.vault.ChangePassphrase(verifyDEK, np)
	crypto.Zero(np)
	crypto.Zero(verifyDEK)
	if err != nil {
		s.renderSettings(w, r, sess, "", "Could not change passphrase.")
		return
	}
	s.renderSettings(w, r, sess, "Passphrase changed.", "")
}

func (s *Server) rekey(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	ip := auth.ClientIP(r, s.cfg.TrustProxy)
	if !s.limiter.Allowed(ip) {
		w.Header().Set("Retry-After", retryAfterSecs(s.limiter.RetryAfter(ip)))
		w.WriteHeader(http.StatusTooManyRequests)
		s.renderSettings(w, r, sess, "", "Too many attempts. Try again later.")
		return
	}
	pass := []byte(r.FormValue("passphrase"))
	newDEK, err := s.vault.Rekey(pass)
	crypto.Zero(pass)
	if err != nil {
		s.limiter.Fail(ip)
		s.renderSettings(w, r, sess, "", "Re-key failed (check passphrase).")
		return
	}
	s.limiter.Reset(ip)
	s.sessions.SetDEK(sess.ID, newDEK) // session now uses the new key
	s.renderSettings(w, r, sess, "Data key rotated; all secrets re-encrypted.", "")
}

func (s *Server) totpBegin(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	secret, uri, err := crypto.NewTOTPSecret("grafted")
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "totpEnroll", totpEnrollView{Secret: secret, URI: uri})
}

func (s *Server) totpConfirm(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	secret := r.FormValue("secret")
	code := strings.TrimSpace(r.FormValue("code"))
	ok, err := s.vault.ConfirmTOTP(dek, secret, code)
	if err != nil || !ok {
		s.renderSettings(w, r, sess, "", "Code did not verify. Two-factor not enabled.")
		return
	}
	s.renderSettings(w, r, sess, "Two-factor authentication enabled.", "")
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	if err := s.vault.DisableTOTP(); err != nil {
		s.fail(w, err)
		return
	}
	s.renderSettings(w, r, sess, "Two-factor authentication disabled.", "")
}

func (s *Server) backupNow(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	if s.snapshot == nil {
		s.renderSettings(w, r, sess, "", "Backups are not configured.")
		return
	}
	if _, err := s.snapshot(); err != nil {
		s.renderSettings(w, r, sess, "", "Backup failed: "+err.Error())
		return
	}
	s.renderSettings(w, r, sess, "Backup created.", "")
}
