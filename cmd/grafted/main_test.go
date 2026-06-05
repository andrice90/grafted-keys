package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/andrew/grafted-secrets/internal/store"
)

// makeVault creates a valid, initialized vault DB at path with the given epoch
// (used as a content marker), then closes it.
func makeVault(t *testing.T, path string, epoch int) {
	t.Helper()
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Raw().Exec(`INSERT INTO vault
		(id, epoch, argon_time, argon_mem, argon_par, salt, wrapped_dek, created_at, updated_at)
		VALUES (1, ?, 3, 65536, 4, x'00', x'00', 0, 0)`, epoch); err != nil {
		t.Fatal(err)
	}
	db.Close()
}

func vaultEpoch(t *testing.T, path string) int {
	t.Helper()
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var e int
	if err := db.Raw().QueryRow(`SELECT epoch FROM vault WHERE id = 1`).Scan(&e); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestApplyPendingRestore_Swaps(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "grafted.db")
	pending := filepath.Join(dir, "restore-pending.db")

	makeVault(t, live, 1)     // current vault
	makeVault(t, pending, 42) // staged restore (distinct marker)
	// stale WAL/SHM sidecars from the live DB must be cleared
	os.WriteFile(live+"-wal", []byte("stale"), 0o600)
	os.WriteFile(live+"-shm", []byte("stale"), 0o600)

	if err := applyPendingRestore(dir); err != nil {
		t.Fatalf("applyPendingRestore: %v", err)
	}
	if _, err := os.Stat(pending); !os.IsNotExist(err) {
		t.Error("pending file should be consumed")
	}
	if _, err := os.Stat(live + "-wal"); !os.IsNotExist(err) {
		t.Error("stale -wal should be removed")
	}
	if got := vaultEpoch(t, live); got != 42 {
		t.Errorf("live vault epoch = %d, want 42 (restore not applied)", got)
	}
}

func TestApplyPendingRestore_RejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "grafted.db")
	pending := filepath.Join(dir, "restore-pending.db")

	makeVault(t, live, 7)
	os.WriteFile(pending, []byte("not a sqlite database"), 0o600) // garbage

	if err := applyPendingRestore(dir); err != nil {
		t.Fatalf("invalid pending should be discarded, not error: %v", err)
	}
	if _, err := os.Stat(pending); !os.IsNotExist(err) {
		t.Error("invalid pending file should be discarded")
	}
	if got := vaultEpoch(t, live); got != 7 {
		t.Errorf("live vault must be untouched, epoch = %d want 7", got)
	}
}

func TestApplyPendingRestore_Noop(t *testing.T) {
	dir := t.TempDir()
	if err := applyPendingRestore(dir); err != nil {
		t.Errorf("no staged file should be a no-op: %v", err)
	}
}
