package web

import (
	"net/http"
	"strings"

	"github.com/andrew/grafted-secrets/internal/auth"
	"github.com/andrew/grafted-secrets/internal/vault"
)

// valueView drives the reveal/mask value control. Value is set only when revealed.
type valueView struct {
	ID       string
	Value    string
	Revealed bool
}

// valueCtl builds a masked control (template helper).
func valueCtl(id string) valueView { return valueView{ID: id} }

type secretFormView struct {
	Action   string
	Target   string
	Swap     string
	FolderID string
	ID       string
	Name     string
	Value    string
	Notes    string
}

type secretDetailView struct {
	ID    string
	Notes string
}

type notesFullView struct {
	Name  string
	Notes string
}

func (s *Server) newSecretForm(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	fid := r.PathValue("id")
	s.rd.Frag(w, "secretForm", secretFormView{
		Action: "/secrets", Target: "#secrets-folder-" + fid, Swap: "beforeend", FolderID: fid,
	})
}

func (s *Server) createSecret(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	fid := r.FormValue("folder_id")
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.empty(w)
		return
	}
	notes := r.FormValue("notes")
	id, err := s.vault.CreateSecret(dek, fid, name, r.FormValue("value"), notes)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "secretNode", vault.SecretMeta{ID: id, FolderID: fid, Name: name, HasNotes: notes != ""})
}

func (s *Server) editSecretForm(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	full, err := s.vault.GetSecretFull(dek, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "secretForm", secretFormView{
		Action: "/secrets/" + full.ID, Target: "#secret-" + full.ID, Swap: "outerHTML",
		FolderID: full.FolderID, ID: full.ID, Name: full.Name, Value: full.Value, Notes: full.Notes,
	})
}

func (s *Server) updateSecret(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	id := r.PathValue("id")
	fid, err := s.vault.SecretFolder(id)
	if err != nil {
		s.fail(w, err)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	notes := r.FormValue("notes")
	if err := s.vault.UpdateSecret(dek, id, name, r.FormValue("value"), notes); err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "secretNode", vault.SecretMeta{ID: id, FolderID: fid, Name: name, HasNotes: notes != ""})
}

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	if err := s.vault.DeleteSecret(r.PathValue("id")); err != nil {
		s.fail(w, err)
		return
	}
	s.empty(w)
}

// secretDetail is the lazy-loaded expanded panel: masked value control + notes.
func (s *Server) secretDetail(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	full, err := s.vault.GetSecretFull(dek, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "secretDetail", secretDetailView{ID: full.ID, Notes: full.Notes})
}

// secretNotes returns the full rendered notes for the fullscreen dialog.
func (s *Server) secretNotes(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	full, err := s.vault.GetSecretFull(dek, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "notesFull", notesFullView{Name: full.Name, Notes: full.Notes})
}

// revealSecret returns the decrypted value (reveal-on-demand). Plaintext is never
// present in list/tree responses — only here, behind an explicit user action.
func (s *Server) revealSecret(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	id := r.PathValue("id")
	val, err := s.vault.SecretValue(dek, id)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "secretValue", valueView{ID: id, Value: val, Revealed: true})
}

func (s *Server) maskSecret(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	s.rd.Frag(w, "secretValue", valueView{ID: r.PathValue("id")})
}

// copySecret returns the raw value as text/plain for the clipboard helper.
func (s *Server) copySecret(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	val, err := s.vault.SecretValue(dek, r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(val))
}

func (s *Server) previewNotes(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	s.rd.Frag(w, "notesPreview", secretDetailView{Notes: r.FormValue("notes")})
}
