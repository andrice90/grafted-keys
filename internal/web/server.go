// Package web wires the HTTP surface: router, hardened middleware, and handlers.
package web

import (
	"context"
	"io/fs"
	"log"
	"net/http"
	"net/url"

	"github.com/andrew/grafted-secrets/internal/auth"
	"github.com/andrew/grafted-secrets/internal/config"
	"github.com/andrew/grafted-secrets/internal/crypto"
	"github.com/andrew/grafted-secrets/internal/vault"
)

type Server struct {
	cfg      config.Config
	vault    *vault.Service
	sessions *auth.Sessions
	limiter  *auth.Limiter
	rd       *Renderer
	static   http.Handler
	mux      http.Handler

	// snapshot triggers a manual backup (wired from the backup scheduler).
	snapshot func() (string, error)
}

func NewServer(cfg config.Config, v *vault.Service, sessions *auth.Sessions, limiter *auth.Limiter,
	snapshot func() (string, error), assets fs.FS) (*Server, error) {
	rd, err := NewRenderer(assets)
	if err != nil {
		return nil, err
	}
	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, vault: v, sessions: sessions, limiter: limiter,
		rd: rd, static: http.FileServerFS(staticFS), snapshot: snapshot,
	}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	mux := http.NewServeMux()

	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(s.static)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok"))
	})

	// Auth surface (no DEK required).
	mux.HandleFunc("GET /setup", s.getSetup)
	mux.HandleFunc("POST /setup", s.postSetup)
	mux.HandleFunc("GET /unlock", s.getUnlock)
	mux.HandleFunc("POST /unlock", s.postUnlock)
	mux.HandleFunc("POST /unlock/totp", s.postUnlockTOTP)
	mux.HandleFunc("POST /lock", s.postLock)

	// Navigation (gated). Home = project card grid; a project = the file-tree.
	mux.HandleFunc("GET /{$}", s.needDEK(s.home))
	mux.HandleFunc("GET /projects/{id}", s.needDEK(s.viewProject))
	mux.HandleFunc("GET /search", s.needDEK(s.search))

	// Projects (home grid).
	mux.HandleFunc("POST /projects", s.needDEK(s.createProject))
	mux.HandleFunc("GET /projects/{id}/edit", s.needDEK(s.editProjectForm))
	mux.HandleFunc("POST /projects/{id}", s.needDEK(s.renameProject))
	mux.HandleFunc("DELETE /projects/{id}", s.needDEK(s.deleteProject))

	// Environments (tree nodes).
	mux.HandleFunc("GET /projects/{id}/new-env", s.needDEK(s.newEnvForm))
	mux.HandleFunc("POST /environments", s.needDEK(s.createEnvironment))
	mux.HandleFunc("GET /environments/{id}/edit", s.needDEK(s.editEnvironmentForm))
	mux.HandleFunc("POST /environments/{id}", s.needDEK(s.renameEnvironment))
	mux.HandleFunc("DELETE /environments/{id}", s.needDEK(s.deleteEnvironment))

	// Folders (tree nodes).
	mux.HandleFunc("GET /environments/{id}/new-folder", s.needDEK(s.newFolderForm))
	mux.HandleFunc("POST /folders", s.needDEK(s.createFolder))
	mux.HandleFunc("GET /folders/{id}/edit", s.needDEK(s.editFolderForm))
	mux.HandleFunc("POST /folders/{id}", s.needDEK(s.renameFolder))
	mux.HandleFunc("DELETE /folders/{id}", s.needDEK(s.deleteFolder))

	// Secrets (tree leaf nodes).
	mux.HandleFunc("GET /folders/{id}/new-secret", s.needDEK(s.newSecretForm))
	mux.HandleFunc("POST /secrets", s.needDEK(s.createSecret))
	mux.HandleFunc("GET /secrets/{id}/edit", s.needDEK(s.editSecretForm))
	mux.HandleFunc("POST /secrets/{id}", s.needDEK(s.updateSecret))
	mux.HandleFunc("DELETE /secrets/{id}", s.needDEK(s.deleteSecret))
	mux.HandleFunc("GET /secrets/{id}/detail", s.needDEK(s.secretDetail))
	mux.HandleFunc("GET /secrets/{id}/reveal", s.needDEK(s.revealSecret))
	mux.HandleFunc("GET /secrets/{id}/mask", s.needDEK(s.maskSecret))
	mux.HandleFunc("GET /secrets/{id}/copy", s.needDEK(s.copySecret))
	mux.HandleFunc("POST /notes/preview", s.needDEK(s.previewNotes))

	// Settings (gated).
	mux.HandleFunc("GET /settings", s.needDEK(s.settings))
	mux.HandleFunc("POST /settings/passphrase", s.needDEK(s.changePassphrase))
	mux.HandleFunc("POST /settings/rekey", s.needDEK(s.rekey))
	mux.HandleFunc("POST /settings/totp/begin", s.needDEK(s.totpBegin))
	mux.HandleFunc("POST /settings/totp/confirm", s.needDEK(s.totpConfirm))
	mux.HandleFunc("POST /settings/totp/disable", s.needDEK(s.totpDisable))
	mux.HandleFunc("POST /settings/backup", s.needDEK(s.backupNow))

	s.mux = s.recoverMW(s.secureHeadersMW(s.sessionMW(s.csrfMW(mux))))
}

// ---- middleware ----

type ctxKey int

const sessionKey ctxKey = 0

func sessionFrom(ctx context.Context) *auth.Session {
	s, _ := ctx.Value(sessionKey).(*auth.Session)
	return s
}

func (s *Server) recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic: %v", rec)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) secureHeadersMW(next http.Handler) http.Handler {
	const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
		"font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; " +
		"frame-ancestors 'none'; manifest-src 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), usb=(), payment=(), browsing-topics=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cache-Control", "no-store") // static handler overrides this for assets
		if s.cfg.HSTS {
			h.Set("Strict-Transport-Security", "max-age=63072000")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) sessionMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sess *auth.Session
		if c, err := r.Cookie(s.cookieName()); err == nil {
			sess, _ = s.sessions.Get(c.Value)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey, sess)))
	})
}

// csrfMW enforces, for every state-changing request, a valid synchronizer token
// and a same-origin Origin (default-deny).
func (s *Server) csrfMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		// Reject only a real cross-origin request. A missing or opaque ("null")
		// Origin — which Safari sends on same-origin form POSTs reached via a
		// redirect — is treated as no signal; the synchronizer token below plus
		// the SameSite=Lax cookie are the actual CSRF protection.
		if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
			if u, err := url.Parse(origin); err != nil || u.Host != r.Host {
				http.Error(w, "bad origin", http.StatusForbidden)
				return
			}
		}
		// htmx requests carry the token in a header; plain forms in a hidden field.
		token := r.Header.Get("X-CSRF-Token")
		if token == "" {
			token = r.FormValue("_csrf")
		}
		sess := sessionFrom(r.Context())
		if sess == nil || !crypto.ConstEqual([]byte(sess.CSRF), []byte(token)) {
			http.Error(w, "csrf", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// needDEK wraps a handler that requires an unlocked vault, passing the session
// and its DEK. Locked/expired sessions are redirected to unlock (or setup).
func (s *Server) needDEK(fn func(http.ResponseWriter, *http.Request, *auth.Session, []byte)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFrom(r.Context())
		if !sess.Unlocked() {
			dest := "/unlock"
			if init, _ := s.vault.Initialized(); !init {
				dest = "/setup"
			}
			if isHTMX(r) {
				w.Header().Set("HX-Redirect", dest)
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Redirect(w, r, dest, http.StatusSeeOther)
			return
		}
		fn(w, r, sess, sess.DEK)
	}
}

// ---- cookies ----

func (s *Server) cookieName() string {
	if s.cfg.SecureCookie {
		return "__Host-gs_session" // requires Secure; only valid over HTTPS
	}
	return "gs_session"
}

func (s *Server) setSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: id, Path: "/",
		HttpOnly: true, Secure: s.cfg.SecureCookie, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.SecureCookie, SameSite: http.SameSiteLaxMode,
	})
}

func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(w, r)
	})
}
