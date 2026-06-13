package backup

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/andrew/grafted-secrets/internal/config"
	"github.com/andrew/grafted-secrets/internal/store"
	"github.com/andrew/grafted-secrets/internal/vault"
)

// A VACUUM-INTO snapshot copies the whole database, so an encrypted attachment
// must be present and decryptable in the backup with the same passphrase - this
// is what makes attachments part of the backup/restore flow for free.
func TestSnapshotCarriesEncryptedAttachment(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "grafted.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	argon := config.Argon{TimeT: 2, MemKiB: 19 * 1024, Par: 1}
	v := vault.New(db, argon)
	pass := []byte("passphrase-123")
	dek, err := v.Setup(pass)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := v.CreateProject(dek, "Acme")
	eid, _ := v.CreateEnvironment(dek, pid, "prod")
	fid, _ := v.CreateFolder(dek, eid, "files")
	sid, _ := v.CreateSecret(dek, fid, "K", "v", "")
	payload := []byte("\x00secret-attachment-bytes\xff")
	attID, err := v.AddAttachment(dek, sid, "kp.kdbx", payload)
	if err != nil {
		t.Fatal(err)
	}

	// Take a real snapshot.
	backupDir := filepath.Join(dir, "backups")
	s := New(db, backupDir, "", 14)
	snapPath, err := s.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := store.ValidateVaultFile(snapPath); err != nil {
		t.Fatalf("snapshot is not a valid vault: %v", err)
	}

	// Open the snapshot as an independent vault and confirm the attachment
	// decrypts from the backup copy with the original passphrase.
	rdb, err := store.Open(snapPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rdb.Close()
	rv := vault.New(rdb, argon)
	rdek, err := rv.Unlock(pass)
	if err != nil {
		t.Fatalf("unlock restored copy: %v", err)
	}
	got, err := rv.AttachmentData(rdek, attID)
	if err != nil {
		t.Fatalf("attachment missing from backup: %v", err)
	}
	if got.Name != "kp.kdbx" || !bytes.Equal(got.Data, payload) {
		t.Fatalf("attachment corrupted in backup: name=%q len=%d", got.Name, len(got.Data))
	}
}
