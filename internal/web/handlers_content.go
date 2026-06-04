package web

import (
	"net/http"
	"strings"

	"github.com/andrew/grafted-secrets/internal/auth"
	"github.com/andrew/grafted-secrets/internal/vault"
)

func formName(r *http.Request) string { return strings.TrimSpace(r.FormValue("name")) }

func (s *Server) empty(w http.ResponseWriter) { w.WriteHeader(http.StatusOK) }

// nameForm drives the create/rename dialog fragment. Target/Swap let the same
// form append a new node or replace a node's name.
type nameForm struct {
	Title       string
	Action      string
	Target      string
	Swap        string
	Name        string
	ParentField string
	ParentID    string
}

// nodeName is the swap result of a rename (just the node's name label).
type nodeName struct {
	Type string // "env" | "folder"
	ID   string
	Name string
}

// ---- projects (home card grid) ----

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
	s.rd.Frag(w, "nameForm", nameForm{Title: "Rename project", Action: "/projects/" + p.ID,
		Target: "#main", Swap: "innerHTML", Name: p.Name})
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

// ---- environments (tree nodes) ----

func (s *Server) newEnvForm(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	s.rd.Frag(w, "nameForm", nameForm{Title: "New environment", Action: "/environments",
		Target: "#tree", Swap: "beforeend", ParentField: "project_id", ParentID: r.PathValue("id")})
}

func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	pid := r.FormValue("project_id")
	name := formName(r)
	if name == "" {
		s.empty(w)
		return
	}
	id, err := s.vault.CreateEnvironment(dek, pid, name)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "envNode", vault.TreeEnv{Environment: vault.Environment{ID: id, ProjectID: pid, Name: name}})
}

func (s *Server) editEnvironmentForm(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	e, err := s.vault.GetEnvironment(dek, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "nameForm", nameForm{Title: "Rename environment", Action: "/environments/" + e.ID,
		Target: "#name-env-" + e.ID, Swap: "outerHTML", Name: e.Name})
}

func (s *Server) renameEnvironment(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	id := r.PathValue("id")
	name := formName(r)
	if err := s.vault.RenameEnvironment(dek, id, name); err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "nodeName", nodeName{Type: "env", ID: id, Name: name})
}

func (s *Server) deleteEnvironment(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	if err := s.vault.DeleteEnvironment(r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	s.empty(w)
}

// ---- folders (tree nodes) ----

func (s *Server) newFolderForm(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	eid := r.PathValue("id")
	s.rd.Frag(w, "nameForm", nameForm{Title: "New folder", Action: "/folders",
		Target: "#folders-env-" + eid, Swap: "beforeend", ParentField: "environment_id", ParentID: eid})
}

func (s *Server) createFolder(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	eid := r.FormValue("environment_id")
	name := formName(r)
	if name == "" {
		s.empty(w)
		return
	}
	id, err := s.vault.CreateFolder(dek, eid, name)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "folderNode", vault.TreeFolder{Folder: vault.Folder{ID: id, EnvironmentID: eid, Name: name}})
}

func (s *Server) editFolderForm(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	f, err := s.vault.GetFolder(dek, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "nameForm", nameForm{Title: "Rename folder", Action: "/folders/" + f.ID,
		Target: "#name-folder-" + f.ID, Swap: "outerHTML", Name: f.Name})
}

func (s *Server) renameFolder(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	id := r.PathValue("id")
	name := formName(r)
	if err := s.vault.RenameFolder(dek, id, name); err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "nodeName", nodeName{Type: "folder", ID: id, Name: name})
}

func (s *Server) deleteFolder(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	if err := s.vault.DeleteFolder(r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	s.empty(w)
}
