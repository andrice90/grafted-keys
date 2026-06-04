package vault

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/andrew/grafted-secrets/internal/config"
	"github.com/andrew/grafted-secrets/internal/crypto"
	"github.com/andrew/grafted-secrets/internal/store"
	"github.com/pquerna/otp/totp"
)

func newTestVault(t *testing.T) (*Service, *store.DB) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	// fast KDF params for tests (floors are enforced at the config layer)
	return New(db, config.Argon{TimeT: 2, MemKiB: 19 * 1024, Par: 1}), db
}

func TestSetupUnlockRoundTrip(t *testing.T) {
	v, _ := newTestVault(t)
	pass := []byte("correct horse battery staple")

	dek, err := v.Setup(pass)
	if err != nil {
		t.Fatal(err)
	}

	pid, err := v.CreateProject(dek, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	eid, _ := v.CreateEnvironment(dek, pid, "production")
	fid, _ := v.CreateFolder(dek, eid, "API keys")
	sid, err := v.CreateSecret(dek, fid, "STRIPE_KEY", "sk_live_abc123", "rotate **monthly**")
	if err != nil {
		t.Fatal(err)
	}

	// Re-unlock with a fresh key and confirm everything decrypts.
	dek2, err := v.Unlock(pass)
	if err != nil {
		t.Fatalf("unlock failed: %v", err)
	}
	val, err := v.SecretValue(dek2, sid)
	if err != nil || val != "sk_live_abc123" {
		t.Fatalf("value mismatch: %q err=%v", val, err)
	}
	full, _ := v.GetSecretFull(dek2, sid)
	if full.Name != "STRIPE_KEY" || full.Notes != "rotate **monthly**" {
		t.Fatalf("full mismatch: %+v", full)
	}

	// list metadata must not require values and must flag notes
	metas, _ := v.Secrets(dek2, fid)
	if len(metas) != 1 || !metas[0].HasNotes {
		t.Fatalf("bad secret metadata: %+v", metas)
	}
}

func TestWrongPassphraseFails(t *testing.T) {
	v, _ := newTestVault(t)
	if _, err := v.Setup([]byte("right-passphrase")); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Unlock([]byte("wrong-passphrase")); err != ErrBadPassphrase {
		t.Fatalf("expected ErrBadPassphrase, got %v", err)
	}
}

func TestSearchMatchesNameAndFolderNotValue(t *testing.T) {
	v, _ := newTestVault(t)
	dek, _ := v.Setup([]byte("passphrase-123"))
	pid, _ := v.CreateProject(dek, "Acme")
	eid, _ := v.CreateEnvironment(dek, pid, "prod")
	fid, _ := v.CreateFolder(dek, eid, "Database")
	v.CreateSecret(dek, fid, "PG_PASSWORD", "uniquev4lue", "")

	if hits, _ := v.Search(dek, "pg_pass"); len(hits) != 1 {
		t.Fatalf("name search: want 1 hit, got %d", len(hits))
	}
	if hits, _ := v.Search(dek, "database"); len(hits) != 1 {
		t.Fatalf("folder search: want 1 hit, got %d", len(hits))
	}
	// values must NOT be searchable (no plaintext-value leakage into search)
	if hits, _ := v.Search(dek, "uniquev4lue"); len(hits) != 0 {
		t.Fatalf("value search must return 0, got %d", len(hits))
	}
}

func TestRekeyReencryptsAll(t *testing.T) {
	v, _ := newTestVault(t)
	pass := []byte("rotate-me-please")
	dek, _ := v.Setup(pass)
	pid, _ := v.CreateProject(dek, "Acme")
	eid, _ := v.CreateEnvironment(dek, pid, "prod")
	fid, _ := v.CreateFolder(dek, eid, "f")
	sid, _ := v.CreateSecret(dek, fid, "K", "v-secret", "n")

	newDEK, err := v.Rekey(pass)
	if err != nil {
		t.Fatalf("rekey: %v", err)
	}
	// old DEK can no longer decrypt
	if _, err := v.SecretValue(dek, sid); err == nil {
		t.Fatal("old DEK should fail after rekey")
	}
	// new DEK decrypts correctly
	if val, err := v.SecretValue(newDEK, sid); err != nil || val != "v-secret" {
		t.Fatalf("new DEK value mismatch: %q err=%v", val, err)
	}
	// passphrase still unlocks (re-wrapped)
	if _, err := v.Unlock(pass); err != nil {
		t.Fatalf("unlock after rekey: %v", err)
	}
}

func TestTOTPEnrollmentCodeNotReplayableAtLogin(t *testing.T) {
	v, _ := newTestVault(t)
	dek, _ := v.Setup([]byte("passphrase-123"))

	secret, _, err := crypto.NewTOTPSecret("test")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := v.ConfirmTOTP(dek, secret, code); err != nil || !ok {
		t.Fatalf("enrollment confirm failed: ok=%v err=%v", ok, err)
	}
	// The same code must NOT be replayable to satisfy the first login.
	if ok, _ := v.VerifyLoginTOTP(dek, code); ok {
		t.Fatal("enrollment code was replayable at login")
	}
}

func TestRefuseSetupWhenDataPresent(t *testing.T) {
	v, db := newTestVault(t)
	dek, _ := v.Setup([]byte("first-pass"))
	v.CreateProject(dek, "Acme")

	// Simulate vault-row loss with data still present.
	if _, err := db.Raw().Exec(`DELETE FROM vault`); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Setup([]byte("attacker-pass")); err != ErrOrphanData {
		t.Fatalf("expected ErrOrphanData, got %v", err)
	}
}
