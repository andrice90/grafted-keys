package store

import (
	"path/filepath"
	"testing"
)

func TestSettingsRoundTrip(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	got, err := db.Settings()
	if err != nil || len(got) != 0 {
		t.Fatalf("fresh db should have no settings: %v err=%v", got, err)
	}
	if err := db.SetSettings(map[string]string{"backup_at": "03:00", "backup_keep": "14"}); err != nil {
		t.Fatal(err)
	}
	// upsert: change one, add one
	if err := db.SetSettings(map[string]string{"backup_at": "04:30", "session_idle": "30m"}); err != nil {
		t.Fatal(err)
	}
	got, err = db.Settings()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"backup_at": "04:30", "backup_keep": "14", "session_idle": "30m"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestValidateVaultFile(t *testing.T) {
	dir := t.TempDir()

	// Missing file.
	if err := ValidateVaultFile(filepath.Join(dir, "nope.db")); err == nil {
		t.Error("missing file should not validate")
	}

	// A schema-correct DB with no vault row is rejected.
	empty := filepath.Join(dir, "empty.db")
	db, err := Open(empty)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateVaultFile(empty); err == nil {
		t.Error("db without a vault row should not validate")
	}

	// With an initialized vault row it validates.
	if _, err := db.Raw().Exec(`INSERT INTO vault
		(id, epoch, argon_time, argon_mem, argon_par, salt, wrapped_dek, created_at, updated_at)
		VALUES (1, 1, 3, 65536, 4, x'00', x'00', 0, 0)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := ValidateVaultFile(empty); err != nil {
		t.Errorf("initialized vault should validate: %v", err)
	}
}
