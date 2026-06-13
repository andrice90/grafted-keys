package vault

import (
	"bytes"
	"testing"
)

// seedSecret creates a project/env/folder/secret and returns the secret id.
func seedSecret(t *testing.T, v *Service, dek []byte) string {
	t.Helper()
	pid, _ := v.CreateProject(dek, "Acme")
	eid, _ := v.CreateEnvironment(dek, pid, "prod")
	fid, _ := v.CreateFolder(dek, eid, "files")
	sid, err := v.CreateSecret(dek, fid, "K", "v", "")
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

func TestAttachmentRoundTrip(t *testing.T) {
	v, _ := newTestVault(t)
	pass := []byte("passphrase-123")
	dek, _ := v.Setup(pass)
	sid := seedSecret(t, v, dek)

	payload := []byte("\x00\x01binary\xffcontent\n")
	id, err := v.AddAttachment(dek, sid, "report.pdf", "PDF Report", payload)
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	// Metadata listing must carry name + size but never the bytes.
	metas, err := v.Attachments(dek, sid)
	if err != nil || len(metas) != 1 {
		t.Fatalf("list: %v len=%d", err, len(metas))
	}
	if metas[0].Name != "report.pdf" || metas[0].DisplayName != "PDF Report" || metas[0].Size != int64(len(payload)) {
		t.Fatalf("bad meta: %+v", metas[0])
	}

	// Re-unlock with a fresh key and confirm the payload decrypts byte-for-byte.
	dek2, err := v.Unlock(pass)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.AttachmentData(dek2, id)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if got.Name != "report.pdf" || !bytes.Equal(got.Data, payload) {
		t.Fatalf("payload mismatch: name=%q len=%d", got.Name, len(got.Data))
	}
}

// A blob moved to a different attachment row must fail authentication: the AAD
// binds each ciphertext to its own attachment id, so substitution/rollback can
// never serve another file's bytes as this one.
func TestAttachmentDataIsAADBound(t *testing.T) {
	v, db := newTestVault(t)
	dek, _ := v.Setup([]byte("passphrase-123"))
	sid := seedSecret(t, v, dek)

	id1, _ := v.AddAttachment(dek, sid, "a.txt", "", []byte("alpha"))
	id2, _ := v.AddAttachment(dek, sid, "b.txt", "", []byte("bravo"))

	// Swap the two ciphertext payloads directly in the table.
	var b1, b2 []byte
	if err := db.Raw().QueryRow(`SELECT data_enc FROM attachments WHERE id=?`, id1).Scan(&b1); err != nil {
		t.Fatal(err)
	}
	if err := db.Raw().QueryRow(`SELECT data_enc FROM attachments WHERE id=?`, id2).Scan(&b2); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Raw().Exec(`UPDATE attachments SET data_enc=? WHERE id=?`, b2, id1); err != nil {
		t.Fatal(err)
	}

	if _, err := v.AttachmentData(dek, id1); err == nil {
		t.Fatal("expected AAD authentication failure after blob substitution")
	}
}

func TestRekeyReencryptsAttachments(t *testing.T) {
	v, _ := newTestVault(t)
	pass := []byte("rotate-me")
	dek, _ := v.Setup(pass)
	sid := seedSecret(t, v, dek)
	payload := []byte("attachment-bytes")
	id, _ := v.AddAttachment(dek, sid, "f.bin", "Rotated Display Name", payload)

	newDEK, err := v.Rekey(pass)
	if err != nil {
		t.Fatalf("rekey: %v", err)
	}
	// Old key can no longer decrypt the attachment.
	if _, err := v.AttachmentData(dek, id); err == nil {
		t.Fatal("old DEK should fail to read attachment after rekey")
	}
	// New key reads it unchanged.
	got, err := v.AttachmentData(newDEK, id)
	if err != nil || !bytes.Equal(got.Data, payload) || got.Name != "f.bin" {
		t.Fatalf("new DEK attachment mismatch: err=%v name=%q", err, got.Name)
	}
	metas, err := v.Attachments(newDEK, sid)
	if err != nil || len(metas) != 1 {
		t.Fatalf("attachments list: %v", err)
	}
	if metas[0].DisplayName != "Rotated Display Name" {
		t.Fatalf("display name not re-encrypted correctly: %q", metas[0].DisplayName)
	}
}

func TestDeleteSecretCascadesAttachments(t *testing.T) {
	v, _ := newTestVault(t)
	dek, _ := v.Setup([]byte("passphrase-123"))
	sid := seedSecret(t, v, dek)
	v.AddAttachment(dek, sid, "x", "", []byte("y"))

	if err := v.DeleteSecret(sid); err != nil {
		t.Fatal(err)
	}
	if n, _ := v.CountAttachments(sid); n != 0 {
		t.Fatalf("attachments should cascade-delete with the secret, got %d", n)
	}
}

func TestUpdateAttachmentDisplayName(t *testing.T) {
	v, _ := newTestVault(t)
	dek, _ := v.Setup([]byte("passphrase-123"))
	sid := seedSecret(t, v, dek)

	id, err := v.AddAttachment(dek, sid, "x.txt", "", []byte("content"))
	if err != nil {
		t.Fatal(err)
	}

	// Initial check: DisplayName should be empty
	meta, err := v.AttachmentMeta(dek, id)
	if err != nil || meta.DisplayName != "" {
		t.Fatalf("expected empty display name, got error=%v meta=%+v", err, meta)
	}

	// Update the display name
	if err := v.UpdateAttachmentDisplayName(dek, id, "Friendly Name"); err != nil {
		t.Fatal(err)
	}

	// Check updated value
	meta, err = v.AttachmentMeta(dek, id)
	if err != nil || meta.DisplayName != "Friendly Name" {
		t.Fatalf("expected Friendly Name, got error=%v meta=%+v", err, meta)
	}

	// Clear display name (set to empty)
	if err := v.UpdateAttachmentDisplayName(dek, id, ""); err != nil {
		t.Fatal(err)
	}

	meta, err = v.AttachmentMeta(dek, id)
	if err != nil || meta.DisplayName != "" {
		t.Fatalf("expected empty display name, got error=%v meta=%+v", err, meta)
	}
}
