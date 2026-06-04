package web

import (
	"net/http"

	"github.com/andrew/grafted-secrets/internal/auth"
	"github.com/andrew/grafted-secrets/internal/vault"
)

// Base carries layout-level data present on every full page.
type Base struct {
	CSRF        string
	Theme       string // "light", "dark", or "" (follow system)
	Chrome      bool   // render the app header/bottom-bar (false on auth pages)
	Asset       string // cache-busting version token for css/js
	TOTPEnabled bool
}

func theme(r *http.Request) string {
	if c, err := r.Cookie("gs_theme"); err == nil && (c.Value == "light" || c.Value == "dark") {
		return c.Value
	}
	return ""
}

func (s *Server) base(r *http.Request, sess *auth.Session) Base {
	return Base{CSRF: sess.CSRF, Theme: theme(r), Chrome: true, Asset: s.assetVer}
}

// authBase is the chrome-less base for setup/unlock pages.
func (s *Server) authBase(r *http.Request, sess *auth.Session) Base {
	return Base{CSRF: sess.CSRF, Theme: theme(r), Chrome: false, Asset: s.assetVer}
}

// projCard is the home grid card, with cascade counts for delete confirmations.
type projCard struct {
	ID, Name string
	Envs     int
	Secrets  int
}

type homeView struct {
	Base
	Projects []projCard
}
type projectTreeView struct {
	Base
	Project vault.Project
	Envs    []vault.TreeEnv
}
type searchView struct {
	Base
	Query string
	Hits  []vault.SearchHit
}

// ---- renderers ----

func (s *Server) renderHome(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	projects, err := s.vault.Projects(dek)
	if err != nil {
		s.fail(w, err)
		return
	}
	cards := make([]projCard, 0, len(projects))
	for _, p := range projects {
		envs, secrets, _ := s.vault.CountsForProject(p.ID)
		cards = append(cards, projCard{ID: p.ID, Name: p.Name, Envs: envs, Secrets: secrets})
	}
	s.rd.Page(w, r, "home", homeView{Base: s.base(r, sess), Projects: cards})
}

func (s *Server) renderProject(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte, id string) {
	project, err := s.vault.GetProject(dek, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	envs, err := s.vault.Tree(dek, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Page(w, r, "project", projectTreeView{Base: s.base(r, sess), Project: project, Envs: envs})
}

// ---- navigation handlers ----

func (s *Server) home(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	s.renderHome(w, r, sess, dek)
}
func (s *Server) viewProject(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	s.renderProject(w, r, sess, dek, r.PathValue("id"))
}

func (s *Server) search(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	q := r.URL.Query().Get("q")
	hits, err := s.vault.Search(dek, q)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Page(w, r, "search", searchView{Base: s.base(r, sess), Query: q, Hits: hits})
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	http.Error(w, "error", http.StatusInternalServerError)
}
