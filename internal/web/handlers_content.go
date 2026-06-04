package web

import (
	"net/http"
	"strings"

	"github.com/andrew/grafted-secrets/internal/auth"
)

func formName(r *http.Request) string { return strings.TrimSpace(r.FormValue("name")) }

func (s *Server) empty(w http.ResponseWriter) { w.WriteHeader(http.StatusOK) }

// nameForm is the context for the create/rename dialog fragment.
type nameForm struct {
	Title       string
	Method      string // "post" | "put"
	Action      string
	Name        string
	ParentField string
	ParentID    string
}

// ---- projects ----

func (s *Server) createProject(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	if name := formName(r); name != "" {
		if _, err := s.vault.CreateProject(dek, name); err != nil {
			s.fail(w, err)
			return
		}
	}
	s.renderHome(w, r, sess, dek)
}

func (s *Server) editProjectForm(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	p, err := s.vault.GetProject(dek, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "nameForm", nameForm{Title: "Rename project", Method: "put",
		Action: "/projects/" + p.ID, Name: p.Name})
}

func (s *Server) renameProject(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	if err := s.vault.RenameProject(dek, r.PathValue("id"), formName(r)); err != nil {
		s.fail(w, err)
		return
	}
	s.renderHome(w, r, sess, dek)
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	if err := s.vault.DeleteProject(r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	s.empty(w)
}

// ---- environments ----

func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	pid := r.FormValue("project_id")
	if name := formName(r); name != "" {
		if _, err := s.vault.CreateEnvironment(dek, pid, name); err != nil {
			s.fail(w, err)
			return
		}
	}
	s.renderProject(w, r, sess, dek, pid)
}

func (s *Server) editEnvironmentForm(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	e, err := s.vault.GetEnvironment(dek, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "nameForm", nameForm{Title: "Rename environment", Method: "put",
		Action: "/environments/" + e.ID, Name: e.Name})
}

func (s *Server) renameEnvironment(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	id := r.PathValue("id")
	e, err := s.vault.GetEnvironment(dek, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.vault.RenameEnvironment(dek, id, formName(r)); err != nil {
		s.fail(w, err)
		return
	}
	s.renderProject(w, r, sess, dek, e.ProjectID)
}

func (s *Server) deleteEnvironment(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	if err := s.vault.DeleteEnvironment(r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	s.empty(w)
}

// ---- folders ----

func (s *Server) createFolder(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	eid := r.FormValue("environment_id")
	if name := formName(r); name != "" {
		if _, err := s.vault.CreateFolder(dek, eid, name); err != nil {
			s.fail(w, err)
			return
		}
	}
	s.renderEnvironment(w, r, sess, dek, eid)
}

func (s *Server) editFolderForm(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	f, err := s.vault.GetFolder(dek, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "nameForm", nameForm{Title: "Rename folder", Method: "put",
		Action: "/folders/" + f.ID, Name: f.Name})
}

func (s *Server) renameFolder(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	id := r.PathValue("id")
	f, err := s.vault.GetFolder(dek, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.vault.RenameFolder(dek, id, formName(r)); err != nil {
		s.fail(w, err)
		return
	}
	s.renderEnvironment(w, r, sess, dek, f.EnvironmentID)
}

func (s *Server) deleteFolder(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	if err := s.vault.DeleteFolder(r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	s.empty(w)
}
