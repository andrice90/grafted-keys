// Package crypto provides the zero-knowledge primitives: Argon2id key derivation,
// AES-256-GCM authenticated encryption with associated data (AAD), CSPRNG helpers,
// and explicit key zeroization. No key material is ever serialized as a string.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	KeyLen   = 32 // AES-256
	SaltLen  = 16
	nonceLen = 12 // GCM standard
)

var ErrDecrypt = errors.New("crypto: decryption failed")

// KDFParams are the Argon2id inputs persisted (in the clear) with the vault.
// They are bound into the wrapped-DEK AAD so tampering fails authentication.
type KDFParams struct {
	TimeT  uint32
	MemKiB uint32
	Par    uint8
	Salt   []byte
}

// DeriveKEK derives the key-encryption-key from the passphrase. The returned
// slice is sensitive; callers must Zero it after use.
func DeriveKEK(passphrase []byte, p KDFParams) []byte {
	return argon2.IDKey(passphrase, p.Salt, p.TimeT, p.MemKiB, p.Par, KeyLen)
}

// RandBytes returns n cryptographically-random bytes.
func RandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

var idEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// RandID returns a URL-safe random identifier (16 bytes → 26 base32 chars).
func RandID() string {
	b, err := RandBytes(16)
	if err != nil {
		panic(err) // a failing CSPRNG is unrecoverable
	}
	return idEnc.EncodeToString(b)
}

// Seal encrypts plaintext with key under AES-256-GCM, binding aad, and returns
// nonce || ciphertext || tag. aad is authenticated but not encrypted.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce, err := RandBytes(nonceLen)
	if err != nil {
		return nil, err
	}
	// dst = nonce, Seal appends ct||tag after it.
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// Open reverses Seal. It returns ErrDecrypt on any authentication failure
// (wrong key, tampered ciphertext, or mismatched aad).
func Open(key, blob, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < nonceLen {
		return nil, ErrDecrypt
	}
	nonce, ct := blob[:nonceLen], blob[nonceLen:]
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, errors.New("crypto: bad key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Zero overwrites b with zeros (best-effort scrub of key material).
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ConstEqual reports whether a and b are equal in constant time.
func ConstEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
