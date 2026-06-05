package vault

import (
	"strings"
	"time"

	"github.com/andrew/grafted-secrets/internal/crypto"
	"github.com/andrew/grafted-secrets/internal/store"
)

// ---- plaintext model ----

type Project struct {
	ID   string
	Name string
}

type Environment struct {
	ID        string
	ProjectID string
	Name      string
}

type Folder struct {
	ID            string
	EnvironmentID string
	Name          string
}

type SecretMeta struct {
	ID            string
	FolderID      string
	EnvironmentID string
	Name          string
	HasNotes      bool
	UpdatedAt     int64
}

type SecretFull struct {
	ID       string
	FolderID string
	Name     string
	Value    string
	Notes    string
}

// Crumb is the decrypted ancestor path of a folder.
type Crumb struct {
	Project     Project
	Environment Environment
	Folder      Folder
}

// Tree types: the fully-decrypted project subtree for the expandable file-tree UI.
type TreeFolder struct {
	Folder
	Secrets []SecretMeta
}
type TreeEnv struct {
	Environment
	Folders []TreeFolder
	Secrets []SecretMeta // uncategorized secrets attached directly to the environment
}

type SearchHit struct {
	SecretID    string
	Name        string
	ProjectID   string
	ProjectName string
	EnvID       string
	EnvName     string
	FolderID    string
	FolderName  string
}

// emptyCipherLen is nonce(12)+tag(16): any ciphertext longer than this wraps a
// non-empty plaintext. Used to flag "has notes" without decrypting notes.
const emptyCipherLen = 28

func (s *Service) seal(dek []byte, pt, entity, id, field string) ([]byte, error) {
	return crypto.Seal(dek, []byte(pt), fieldAAD(entity, id, field))
}

func (s *Service) field(dek, blob []byte, entity, id, field string) (string, error) {
	pt, err := crypto.Open(dek, blob, fieldAAD(entity, id, field))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// ---- projects ----

func (s *Service) Projects(dek []byte) ([]Project, error) {
	rows, err := s.db.ListProjects()
	if err != nil {
		return nil, err
	}
	out := make([]Project, 0, len(rows))
	for _, r := range rows {
		name, err := s.field(dek, r.NameEnc, "project", r.ID, "name")
		if err != nil {
			return nil, err
		}
		out = append(out, Project{ID: r.ID, Name: name})
	}
	return out, nil
}

func (s *Service) GetProject(dek []byte, id string) (Project, error) {
	r, err := s.db.GetProject(id)
	if err != nil {
		return Project{}, err
	}
	name, err := s.field(dek, r.NameEnc, "project", r.ID, "name")
	if err != nil {
		return Project{}, err
	}
	return Project{ID: r.ID, Name: name}, nil
}

func (s *Service) CreateProject(dek []byte, name string) (string, error) {
	id := crypto.RandID()
	enc, err := s.seal(dek, name, "project", id, "name")
	if err != nil {
		return "", err
	}
	return id, s.db.CreateProject(id, enc)
}

func (s *Service) RenameProject(dek []byte, id, name string) error {
	enc, err := s.seal(dek, name, "project", id, "name")
	if err != nil {
		return err
	}
	return s.db.UpdateProject(id, enc)
}

func (s *Service) DeleteProject(id string) error { return s.db.DeleteProject(id) }

// ---- environments ----

func (s *Service) Environments(dek []byte, projectID string) ([]Environment, error) {
	rows, err := s.db.ListEnvironments(projectID)
	if err != nil {
		return nil, err
	}
	out := make([]Environment, 0, len(rows))
	for _, r := range rows {
		name, err := s.field(dek, r.NameEnc, "environment", r.ID, "name")
		if err != nil {
			return nil, err
		}
		out = append(out, Environment{ID: r.ID, ProjectID: r.ProjectID, Name: name})
	}
	return out, nil
}

func (s *Service) GetEnvironment(dek []byte, id string) (Environment, error) {
	r, err := s.db.GetEnvironment(id)
	if err != nil {
		return Environment{}, err
	}
	name, err := s.field(dek, r.NameEnc, "environment", r.ID, "name")
	if err != nil {
		return Environment{}, err
	}
	return Environment{ID: r.ID, ProjectID: r.ProjectID, Name: name}, nil
}

func (s *Service) CreateEnvironment(dek []byte, projectID, name string) (string, error) {
	id := crypto.RandID()
	enc, err := s.seal(dek, name, "environment", id, "name")
	if err != nil {
		return "", err
	}
	return id, s.db.CreateEnvironment(id, projectID, enc)
}

func (s *Service) RenameEnvironment(dek []byte, id, name string) error {
	enc, err := s.seal(dek, name, "environment", id, "name")
	if err != nil {
		return err
	}
	return s.db.UpdateEnvironment(id, enc)
}

func (s *Service) DeleteEnvironment(id string) error { return s.db.DeleteEnvironment(id) }

// ---- folders ----

func (s *Service) Folders(dek []byte, envID string) ([]Folder, error) {
	rows, err := s.db.ListFolders(envID)
	if err != nil {
		return nil, err
	}
	out := make([]Folder, 0, len(rows))
	for _, r := range rows {
		name, err := s.field(dek, r.NameEnc, "folder", r.ID, "name")
		if err != nil {
			return nil, err
		}
		out = append(out, Folder{ID: r.ID, EnvironmentID: r.EnvironmentID, Name: name})
	}
	return out, nil
}

func (s *Service) GetFolder(dek []byte, id string) (Folder, error) {
	r, err := s.db.GetFolder(id)
	if err != nil {
		return Folder{}, err
	}
	name, err := s.field(dek, r.NameEnc, "folder", r.ID, "name")
	if err != nil {
		return Folder{}, err
	}
	return Folder{ID: r.ID, EnvironmentID: r.EnvironmentID, Name: name}, nil
}

func (s *Service) CreateFolder(dek []byte, envID, name string) (string, error) {
	id := crypto.RandID()
	enc, err := s.seal(dek, name, "folder", id, "name")
	if err != nil {
		return "", err
	}
	return id, s.db.CreateFolder(id, envID, enc)
}

func (s *Service) RenameFolder(dek []byte, id, name string) error {
	enc, err := s.seal(dek, name, "folder", id, "name")
	if err != nil {
		return err
	}
	return s.db.UpdateFolder(id, enc)
}

func (s *Service) DeleteFolder(id string) error { return s.db.DeleteFolder(id) }

// ---- cascade counts (for delete confirmations) ----

func (s *Service) CountsForProject(id string) (envs, secrets int, err error) {
	return s.db.ProjectCounts(id)
}
func (s *Service) CountsForEnv(id string) (folders, secrets int, err error) {
	return s.db.EnvCounts(id)
}
func (s *Service) CountsForFolder(id string) (secrets int, err error) {
	return s.db.FolderCounts(id)
}

// ---- secrets ----

// Secrets returns name-only metadata for a folder. Values and notes are NEVER
// decrypted here, so plaintext never reaches a list/search response.
func (s *Service) Secrets(dek []byte, folderID string) ([]SecretMeta, error) {
	rows, err := s.db.ListSecrets(folderID)
	if err != nil {
		return nil, err
	}
	out := make([]SecretMeta, 0, len(rows))
	for _, r := range rows {
		name, err := s.field(dek, r.NameEnc, "secret", r.ID, "name")
		if err != nil {
			return nil, err
		}
		out = append(out, SecretMeta{
			ID: r.ID, FolderID: r.FolderID, Name: name,
			HasNotes: len(r.NotesEnc) > emptyCipherLen, UpdatedAt: r.UpdatedAt,
		})
	}
	return out, nil
}

// SecretValue decrypts just the value (reveal-on-demand).
func (s *Service) SecretValue(dek []byte, id string) (string, error) {
	r, err := s.db.GetSecret(id)
	if err != nil {
		return "", err
	}
	return s.field(dek, r.ValueEnc, "secret", r.ID, "value")
}

// GetSecretFull decrypts all fields (edit form / notes view).
func (s *Service) GetSecretFull(dek []byte, id string) (SecretFull, error) {
	r, err := s.db.GetSecret(id)
	if err != nil {
		return SecretFull{}, err
	}
	name, err := s.field(dek, r.NameEnc, "secret", r.ID, "name")
	if err != nil {
		return SecretFull{}, err
	}
	value, err := s.field(dek, r.ValueEnc, "secret", r.ID, "value")
	if err != nil {
		return SecretFull{}, err
	}
	notes, err := s.field(dek, r.NotesEnc, "secret", r.ID, "notes")
	if err != nil {
		return SecretFull{}, err
	}
	return SecretFull{ID: r.ID, FolderID: r.FolderID, Name: name, Value: value, Notes: notes}, nil
}

func (s *Service) CreateSecret(dek []byte, folderID, name, value, notes string) (string, error) {
	id := crypto.RandID()
	rec, err := s.sealSecret(dek, id, name, value, notes)
	if err != nil {
		return "", err
	}
	rec.FolderID = folderID
	return id, s.db.CreateSecret(rec)
}

// CreateEnvSecret creates an uncategorized secret directly under an environment.
func (s *Service) CreateEnvSecret(dek []byte, envID, name, value, notes string) (string, error) {
	id := crypto.RandID()
	rec, err := s.sealSecret(dek, id, name, value, notes)
	if err != nil {
		return "", err
	}
	rec.EnvironmentID = envID
	return id, s.db.CreateSecret(rec)
}

func (s *Service) UpdateSecret(dek []byte, id, name, value, notes string) error {
	rec, err := s.sealSecret(dek, id, name, value, notes)
	if err != nil {
		return err
	}
	return s.db.UpdateSecret(rec)
}

func (s *Service) sealSecret(dek []byte, id, name, value, notes string) (store.Secret, error) {
	ne, err := s.seal(dek, name, "secret", id, "name")
	if err != nil {
		return store.Secret{}, err
	}
	ve, err := s.seal(dek, value, "secret", id, "value")
	if err != nil {
		return store.Secret{}, err
	}
	no, err := s.seal(dek, notes, "secret", id, "notes")
	if err != nil {
		return store.Secret{}, err
	}
	return store.Secret{ID: id, NameEnc: ne, ValueEnc: ve, NotesEnc: no}, nil
}

func (s *Service) DeleteSecret(id string) error { return s.db.DeleteSecret(id) }

// SecretFolder returns the folder id a secret belongs to (no decryption).
func (s *Service) SecretFolder(id string) (string, error) {
	r, err := s.db.GetSecret(id)
	if err != nil {
		return "", err
	}
	return r.FolderID, nil
}

// ---- navigation & search ----

// Tree returns the full decrypted environment→folder→secret subtree for a
// project (secret values are NOT decrypted - names/metadata only).
func (s *Service) Tree(dek []byte, projectID string) ([]TreeEnv, error) {
	envs, err := s.Environments(dek, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]TreeEnv, 0, len(envs))
	for _, e := range envs {
		folders, err := s.Folders(dek, e.ID)
		if err != nil {
			return nil, err
		}
		tfs := make([]TreeFolder, 0, len(folders))
		for _, f := range folders {
			secs, err := s.Secrets(dek, f.ID)
			if err != nil {
				return nil, err
			}
			tfs = append(tfs, TreeFolder{Folder: f, Secrets: secs})
		}
		loose, err := s.EnvSecrets(dek, e.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, TreeEnv{Environment: e, Folders: tfs, Secrets: loose})
	}
	return out, nil
}

// EnvSecrets returns the uncategorized secrets attached directly to an environment.
func (s *Service) EnvSecrets(dek []byte, envID string) ([]SecretMeta, error) {
	rows, err := s.db.ListEnvSecrets(envID)
	if err != nil {
		return nil, err
	}
	out := make([]SecretMeta, 0, len(rows))
	for _, r := range rows {
		name, err := s.field(dek, r.NameEnc, "secret", r.ID, "name")
		if err != nil {
			return nil, err
		}
		out = append(out, SecretMeta{
			ID: r.ID, EnvironmentID: r.EnvironmentID, Name: name,
			HasNotes: len(r.NotesEnc) > emptyCipherLen, UpdatedAt: r.UpdatedAt,
		})
	}
	return out, nil
}

// Breadcrumb decrypts the project/env/folder names above a folder.
func (s *Service) Breadcrumb(dek []byte, folderID string) (Crumb, error) {
	f, err := s.GetFolder(dek, folderID)
	if err != nil {
		return Crumb{}, err
	}
	e, err := s.GetEnvironment(dek, f.EnvironmentID)
	if err != nil {
		return Crumb{}, err
	}
	p, err := s.GetProject(dek, e.ProjectID)
	if err != nil {
		return Crumb{}, err
	}
	return Crumb{Project: p, Environment: e, Folder: f}, nil
}

// Search matches the query against secret names, notes, and ancestor (project/
// environment/folder) names - never against secret values. Results expose only
// names and the path, never any secret value.
func (s *Service) Search(dek []byte, query string) ([]SearchHit, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil, nil
	}
	rows, err := s.db.AllSecretsWithPath()
	if err != nil {
		return nil, err
	}
	const maxHits = 100
	var hits []SearchHit
	for _, r := range rows {
		name, err := s.field(dek, r.NameEnc, "secret", r.ID, "name")
		if err != nil {
			return nil, err
		}
		notes, err := s.field(dek, r.NotesEnc, "secret", r.ID, "notes")
		if err != nil {
			return nil, err
		}
		proj, err := s.field(dek, r.ProjectName, "project", r.ProjectID, "name")
		if err != nil {
			return nil, err
		}
		env, err := s.field(dek, r.EnvName, "environment", r.EnvID, "name")
		if err != nil {
			return nil, err
		}
		folder := "" // environment-level secrets have no folder
		if len(r.FolderName) > 0 {
			folder, err = s.field(dek, r.FolderName, "folder", r.FolderID, "name")
			if err != nil {
				return nil, err
			}
		}

		if contains(name, q) || contains(notes, q) || contains(folder, q) ||
			contains(env, q) || contains(proj, q) {
			hits = append(hits, SearchHit{
				SecretID: r.ID, Name: name,
				ProjectID: r.ProjectID, ProjectName: proj,
				EnvID: r.EnvID, EnvName: env,
				FolderID: r.FolderID, FolderName: folder,
			})
			if len(hits) >= maxHits {
				break
			}
		}
	}
	return hits, nil
}

func contains(haystack, needleLower string) bool {
	return strings.Contains(strings.ToLower(haystack), needleLower)
}

// ---- TOTP ----

func (s *Service) TOTPEnabled() (bool, error) {
	v, err := s.db.GetVault()
	if err != nil {
		return false, err
	}
	return len(v.TOTPEnc) > 0, nil
}

// ConfirmTOTP validates code against a freshly-generated secret and, on success,
// stores the secret encrypted under the DEK (enabling 2FA).
func (s *Service) ConfirmTOTP(dek []byte, secret, code string) (bool, error) {
	ok, step, err := crypto.ValidateTOTP(secret, code, time.Now(), -1)
	if err != nil || !ok {
		return false, err
	}
	enc, err := crypto.Seal(dek, []byte(secret), fieldAAD("vault", "1", "totp"))
	if err != nil {
		return false, err
	}
	// Record the consumed step so this enrollment code cannot be replayed at login.
	return true, s.db.SetTOTP(enc, step)
}

// VerifyLoginTOTP checks a login code with replay protection (rejects already-
// used time steps).
func (s *Service) VerifyLoginTOTP(dek []byte, code string) (bool, error) {
	v, err := s.db.GetVault()
	if err != nil {
		return false, err
	}
	secret, err := s.field(dek, v.TOTPEnc, "vault", "1", "totp")
	if err != nil {
		return false, err
	}
	ok, step, err := crypto.ValidateTOTP(secret, code, time.Now(), v.TOTPLast)
	if err != nil || !ok {
		return false, err
	}
	return true, s.db.UpdateTOTPLast(step)
}

func (s *Service) DisableTOTP() error { return s.db.ClearTOTP() }
