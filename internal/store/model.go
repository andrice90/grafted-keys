package store

import (
	"database/sql"
	"errors"
	"time"
)

type Project struct {
	ID        string
	NameEnc   []byte
	Sort      int
	CreatedAt int64
	UpdatedAt int64
}

type Environment struct {
	ID        string
	ProjectID string
	NameEnc   []byte
	Sort      int
}

type Folder struct {
	ID            string
	EnvironmentID string
	NameEnc       []byte
	Sort          int
}

type Secret struct {
	ID        string
	FolderID  string
	NameEnc   []byte
	ValueEnc  []byte
	NotesEnc  []byte
	Sort      int
	UpdatedAt int64
}

// SecretWithPath carries a secret plus its encrypted ancestor names, for search.
type SecretWithPath struct {
	Secret
	ProjectID   string
	ProjectName []byte
	EnvID       string
	EnvName     []byte
	FolderName  []byte
}

func now() int64 { return time.Now().Unix() }

// ---- projects ----

func (db *DB) CreateProject(id string, nameEnc []byte) error {
	t := now()
	_, err := db.sql.Exec(`INSERT INTO projects (id, name_enc, created_at, updated_at) VALUES (?,?,?,?)`,
		id, nameEnc, t, t)
	return err
}

func (db *DB) ListProjects() ([]Project, error) {
	rows, err := db.sql.Query(`SELECT id, name_enc, sort, created_at, updated_at FROM projects ORDER BY sort, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.NameEnc, &p.Sort, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (db *DB) GetProject(id string) (Project, error) {
	var p Project
	err := db.sql.QueryRow(`SELECT id, name_enc, sort, created_at, updated_at FROM projects WHERE id=?`, id).
		Scan(&p.ID, &p.NameEnc, &p.Sort, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

func (db *DB) UpdateProject(id string, nameEnc []byte) error {
	return db.exec1(`UPDATE projects SET name_enc=?, updated_at=? WHERE id=?`, nameEnc, now(), id)
}

func (db *DB) DeleteProject(id string) error {
	return db.exec1(`DELETE FROM projects WHERE id=?`, id)
}

// ---- environments ----

func (db *DB) CreateEnvironment(id, projectID string, nameEnc []byte) error {
	t := now()
	_, err := db.sql.Exec(`INSERT INTO environments (id, project_id, name_enc, created_at, updated_at) VALUES (?,?,?,?,?)`,
		id, projectID, nameEnc, t, t)
	return err
}

func (db *DB) ListEnvironments(projectID string) ([]Environment, error) {
	rows, err := db.sql.Query(`SELECT id, project_id, name_enc, sort FROM environments WHERE project_id=? ORDER BY sort, created_at`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Environment
	for rows.Next() {
		var e Environment
		if err := rows.Scan(&e.ID, &e.ProjectID, &e.NameEnc, &e.Sort); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (db *DB) GetEnvironment(id string) (Environment, error) {
	var e Environment
	err := db.sql.QueryRow(`SELECT id, project_id, name_enc, sort FROM environments WHERE id=?`, id).
		Scan(&e.ID, &e.ProjectID, &e.NameEnc, &e.Sort)
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

func (db *DB) UpdateEnvironment(id string, nameEnc []byte) error {
	return db.exec1(`UPDATE environments SET name_enc=?, updated_at=? WHERE id=?`, nameEnc, now(), id)
}

func (db *DB) DeleteEnvironment(id string) error {
	return db.exec1(`DELETE FROM environments WHERE id=?`, id)
}

// ---- folders ----

func (db *DB) CreateFolder(id, envID string, nameEnc []byte) error {
	t := now()
	_, err := db.sql.Exec(`INSERT INTO folders (id, environment_id, name_enc, created_at, updated_at) VALUES (?,?,?,?,?)`,
		id, envID, nameEnc, t, t)
	return err
}

func (db *DB) ListFolders(envID string) ([]Folder, error) {
	rows, err := db.sql.Query(`SELECT id, environment_id, name_enc, sort FROM folders WHERE environment_id=? ORDER BY sort, created_at`, envID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Folder
	for rows.Next() {
		var f Folder
		if err := rows.Scan(&f.ID, &f.EnvironmentID, &f.NameEnc, &f.Sort); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (db *DB) GetFolder(id string) (Folder, error) {
	var f Folder
	err := db.sql.QueryRow(`SELECT id, environment_id, name_enc, sort FROM folders WHERE id=?`, id).
		Scan(&f.ID, &f.EnvironmentID, &f.NameEnc, &f.Sort)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	return f, err
}

func (db *DB) UpdateFolder(id string, nameEnc []byte) error {
	return db.exec1(`UPDATE folders SET name_enc=?, updated_at=? WHERE id=?`, nameEnc, now(), id)
}

func (db *DB) DeleteFolder(id string) error {
	return db.exec1(`DELETE FROM folders WHERE id=?`, id)
}

// ---- secrets ----

func (db *DB) CreateSecret(s Secret) error {
	t := now()
	_, err := db.sql.Exec(`INSERT INTO secrets (id, folder_id, name_enc, value_enc, notes_enc, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?)`, s.ID, s.FolderID, s.NameEnc, s.ValueEnc, s.NotesEnc, t, t)
	return err
}

func (db *DB) ListSecrets(folderID string) ([]Secret, error) {
	rows, err := db.sql.Query(`SELECT id, folder_id, name_enc, value_enc, notes_enc, sort, updated_at
		FROM secrets WHERE folder_id=? ORDER BY sort, created_at`, folderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSecrets(rows)
}

func (db *DB) GetSecret(id string) (Secret, error) {
	var s Secret
	err := db.sql.QueryRow(`SELECT id, folder_id, name_enc, value_enc, notes_enc, sort, updated_at
		FROM secrets WHERE id=?`, id).
		Scan(&s.ID, &s.FolderID, &s.NameEnc, &s.ValueEnc, &s.NotesEnc, &s.Sort, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrNotFound
	}
	return s, err
}

func (db *DB) UpdateSecret(s Secret) error {
	return db.exec1(`UPDATE secrets SET name_enc=?, value_enc=?, notes_enc=?, updated_at=? WHERE id=?`,
		s.NameEnc, s.ValueEnc, s.NotesEnc, now(), s.ID)
}

func (db *DB) DeleteSecret(id string) error {
	return db.exec1(`DELETE FROM secrets WHERE id=?`, id)
}

// AllSecretsWithPath returns every secret joined to its ancestor names, for
// in-memory search after unlock.
func (db *DB) AllSecretsWithPath() ([]SecretWithPath, error) {
	rows, err := db.sql.Query(`
		SELECT s.id, s.folder_id, s.name_enc, s.value_enc, s.notes_enc, s.sort, s.updated_at,
		       p.id, p.name_enc, e.id, e.name_enc, f.name_enc
		FROM secrets s
		JOIN folders f      ON f.id = s.folder_id
		JOIN environments e ON e.id = f.environment_id
		JOIN projects p     ON p.id = e.project_id
		ORDER BY p.sort, e.sort, f.sort, s.sort`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecretWithPath
	for rows.Next() {
		var r SecretWithPath
		if err := rows.Scan(&r.ID, &r.FolderID, &r.NameEnc, &r.ValueEnc, &r.NotesEnc, &r.Sort, &r.UpdatedAt,
			&r.ProjectID, &r.ProjectName, &r.EnvID, &r.EnvName, &r.FolderName); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- cascade counts (for delete confirmations) ----

func (db *DB) ProjectCounts(id string) (envs, secrets int, err error) {
	err = db.sql.QueryRow(`SELECT
		(SELECT COUNT(*) FROM environments WHERE project_id=?),
		(SELECT COUNT(*) FROM secrets s JOIN folders f ON f.id=s.folder_id
		   JOIN environments e ON e.id=f.environment_id WHERE e.project_id=?)`,
		id, id).Scan(&envs, &secrets)
	return
}

func (db *DB) EnvCounts(id string) (folders, secrets int, err error) {
	err = db.sql.QueryRow(`SELECT
		(SELECT COUNT(*) FROM folders WHERE environment_id=?),
		(SELECT COUNT(*) FROM secrets s JOIN folders f ON f.id=s.folder_id WHERE f.environment_id=?)`,
		id, id).Scan(&folders, &secrets)
	return
}

func (db *DB) FolderCounts(id string) (secrets int, err error) {
	err = db.sql.QueryRow(`SELECT COUNT(*) FROM secrets WHERE folder_id=?`, id).Scan(&secrets)
	return
}

// ---- helpers ----

func scanSecrets(rows *sql.Rows) ([]Secret, error) {
	var out []Secret
	for rows.Next() {
		var s Secret
		if err := rows.Scan(&s.ID, &s.FolderID, &s.NameEnc, &s.ValueEnc, &s.NotesEnc, &s.Sort, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// exec1 runs a statement and maps "no rows affected" to ErrNotFound.
func (db *DB) exec1(q string, args ...any) error {
	res, err := db.sql.Exec(q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
