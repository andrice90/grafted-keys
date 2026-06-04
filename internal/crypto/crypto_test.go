package crypto

import (
	"bytes"
	"testing"
	"time"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key, _ := RandBytes(KeyLen)
	aad := []byte("gs/secret/abc/value")
	pt := []byte("sk_live_supersecret")

	blob, err := Seal(key, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, blob, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip mismatch: %q", got)
	}
}

func TestAADMismatchFails(t *testing.T) {
	key, _ := RandBytes(KeyLen)
	blob, _ := Seal(key, []byte("v"), []byte("gs/secret/abc/value"))
	// substituting a different AAD (e.g. another column) must fail authentication.
	if _, err := Open(key, blob, []byte("gs/secret/abc/name")); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt on AAD mismatch, got %v", err)
	}
}

func TestWrongKeyFails(t *testing.T) {
	k1, _ := RandBytes(KeyLen)
	k2, _ := RandBytes(KeyLen)
	blob, _ := Seal(k1, []byte("v"), nil)
	if _, err := Open(k2, blob, nil); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt with wrong key, got %v", err)
	}
}

func TestTamperFails(t *testing.T) {
	key, _ := RandBytes(KeyLen)
	blob, _ := Seal(key, []byte("hello"), nil)
	blob[len(blob)-1] ^= 0xff
	if _, err := Open(key, blob, nil); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt on tamper, got %v", err)
	}
}

func TestNonceUnique(t *testing.T) {
	key, _ := RandBytes(KeyLen)
	a, _ := Seal(key, []byte("x"), nil)
	b, _ := Seal(key, []byte("x"), nil)
	if bytes.Equal(a[:nonceLen], b[:nonceLen]) {
		t.Fatal("nonces must differ per Seal")
	}
}

func TestTOTPValidateAndReplay(t *testing.T) {
	secret, _, err := NewTOTPSecret("test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	// generate the current code via the same internal path
	want, _ := totpCode(secret, now)
	ok, step, err := ValidateTOTP(secret, want, now, -1)
	if err != nil || !ok {
		t.Fatalf("valid code rejected: ok=%v err=%v", ok, err)
	}
	// replay of the same step must be rejected
	if ok2, _, _ := ValidateTOTP(secret, want, now, step); ok2 {
		t.Fatal("replayed code accepted")
	}
}
