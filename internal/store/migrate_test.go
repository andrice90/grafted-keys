package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// TestMigrateV1ToV2 builds a v1 database (folder-only secrets) with data, then
// opens it through the store and confirms migration 2 preserves the secret and
// enables environment-level secrets.
func TestMigrateV1ToV2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.db")

	raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(migrations[0]); err != nil { // v1 schema only
		t.Fatal(err)
	}
	stmts := []string{
		`INSERT INTO projects (id,name_enc,created_at,updated_at) VALUES ('p',x'01',0,0)`,
		`INSERT INTO environments (id,project_id,name_enc,created_at,updated_at) VALUES ('e','p',x'01',0,0)`,
		`INSERT INTO folders (id,environment_id,name_enc,created_at,updated_at) VALUES ('f','e',x'01',0,0)`,
		`INSERT INTO secrets (id,folder_id,name_enc,value_enc,notes_enc,created_at,updated_at) VALUES ('s','f',x'0a',x'0b',x'0c',0,0)`,
		`PRAGMA user_version=1`,
	}
	for _, q := range stmts {
		if _, err := raw.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	raw.Close()

	db, err := Open(path) // runs migration 2
	if err != nil {
		t.Fatalf("open/migrate failed: %v", err)
	}
	defer db.Close()

	// existing folder secret survived with its ciphertext intact
	got, err := db.GetSecret("s")
	if err != nil || got.FolderID != "f" || got.EnvironmentID != "" || len(got.ValueEnc) != 1 || got.ValueEnc[0] != 0x0b {
		t.Fatalf("folder secret not preserved: %+v err=%v", got, err)
	}

	// environment-level (uncategorized) secrets now work
	if err := db.CreateSecret(Secret{ID: "s2", EnvironmentID: "e", NameEnc: []byte{1}, ValueEnc: []byte{2}, NotesEnc: []byte{3}}); err != nil {
		t.Fatalf("env secret insert: %v", err)
	}
	es, err := db.ListEnvSecrets("e")
	if err != nil || len(es) != 1 || es[0].ID != "s2" {
		t.Fatalf("env secrets: %+v err=%v", es, err)
	}
	// the XOR constraint rejects a secret with both parents
	if err := db.CreateSecret(Secret{ID: "bad", FolderID: "f", EnvironmentID: "e", NameEnc: []byte{1}, ValueEnc: []byte{2}, NotesEnc: []byte{3}}); err == nil {
		t.Fatal("expected CHECK constraint to reject a secret with both folder and environment")
	}
}
