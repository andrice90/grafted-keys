// Package vault is the crypto-aware domain layer. It turns the ciphertext-only
// store into a plaintext API given a data key (DEK), and owns vault lifecycle:
// setup, unlock, passphrase change, and DEK rotation. AAD binds every ciphertext
// to its role so tampering or substitution fails authentication.
package vault

import (
	"errors"
	"fmt"

	"github.com/andrew/grafted-secrets/internal/config"
	"github.com/andrew/grafted-secrets/internal/crypto"
	"github.com/andrew/grafted-secrets/internal/store"
)

var (
	ErrNotInit       = errors.New("vault: not initialized")
	ErrAlreadyInit   = errors.New("vault: already initialized")
	ErrOrphanData    = errors.New("vault: encrypted data present but vault metadata missing - restore from backup")
	ErrBadPassphrase = errors.New("vault: incorrect passphrase")
)

type Service struct {
	db    *store.DB
	argon config.Argon // params for newly-created vaults
}

func New(db *store.DB, argon config.Argon) *Service { return &Service{db: db, argon: argon} }

func (s *Service) Initialized() (bool, error) { return s.db.VaultInitialized() }

// wrapAAD binds the KDF params + epoch to the wrapped DEK, so any downgrade or
// rollback of those plaintext fields fails the GCM authentication on unwrap.
func wrapAAD(epoch int64, p crypto.KDFParams) []byte {
	return []byte(fmt.Sprintf("gs-dek/v1/epoch=%d/t=%d/m=%d/p=%d/salt=%x",
		epoch, p.TimeT, p.MemKiB, p.Par, p.Salt))
}

// fieldAAD binds a field ciphertext to its entity/id/field role.
func fieldAAD(entity, id, field string) []byte {
	return []byte("gs/" + entity + "/" + id + "/" + field)
}

func (s *Service) params(salt []byte) crypto.KDFParams {
	return crypto.KDFParams{TimeT: s.argon.TimeT, MemKiB: s.argon.MemKiB, Par: s.argon.Par, Salt: salt}
}

// Setup creates a brand-new vault from passphrase and returns the freshly
// generated DEK (so the caller can open a session immediately). It refuses if a
// vault already exists or if encrypted data is present without vault metadata.
func (s *Service) Setup(passphrase []byte) ([]byte, error) {
	init, err := s.db.VaultInitialized()
	if err != nil {
		return nil, err
	}
	if init {
		return nil, ErrAlreadyInit
	}
	if data, err := s.db.HasData(); err != nil {
		return nil, err
	} else if data {
		return nil, ErrOrphanData
	}

	salt, err := crypto.RandBytes(crypto.SaltLen)
	if err != nil {
		return nil, err
	}
	dek, err := crypto.RandBytes(crypto.KeyLen)
	if err != nil {
		return nil, err
	}
	p := s.params(salt)
	kek := crypto.DeriveKEK(passphrase, p)
	defer crypto.Zero(kek)

	epoch := int64(1)
	aad := wrapAAD(epoch, p)
	wrapped, err := crypto.Seal(kek, dek, aad)
	if err != nil {
		crypto.Zero(dek)
		return nil, err
	}
	// Self-check: confirm the wrap round-trips before we persist it.
	if back, err := crypto.Open(kek, wrapped, aad); err != nil || !crypto.ConstEqual(back, dek) {
		crypto.Zero(dek)
		return nil, errors.New("vault: wrap self-check failed")
	} else {
		crypto.Zero(back)
	}

	row := &store.VaultRow{
		Epoch: epoch, ArgonTime: p.TimeT, ArgonMem: p.MemKiB, ArgonPar: p.Par,
		Salt: salt, WrappedDEK: wrapped,
	}
	if err := s.db.InitVault(row); err != nil {
		crypto.Zero(dek)
		return nil, err
	}
	return dek, nil
}

// Unlock derives the KEK from passphrase and returns the unwrapped DEK.
func (s *Service) Unlock(passphrase []byte) ([]byte, error) {
	v, err := s.db.GetVault()
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotInit
		}
		return nil, err
	}
	p := crypto.KDFParams{TimeT: v.ArgonTime, MemKiB: v.ArgonMem, Par: v.ArgonPar, Salt: v.Salt}
	kek := crypto.DeriveKEK(passphrase, p)
	defer crypto.Zero(kek)

	dek, err := crypto.Open(kek, v.WrappedDEK, wrapAAD(v.Epoch, p))
	if err != nil {
		return nil, ErrBadPassphrase
	}
	return dek, nil
}

// ChangePassphrase re-wraps the same DEK under a new passphrase (fresh salt).
func (s *Service) ChangePassphrase(dek, newPassphrase []byte) error {
	v, err := s.db.GetVault()
	if err != nil {
		return err
	}
	salt, err := crypto.RandBytes(crypto.SaltLen)
	if err != nil {
		return err
	}
	p := s.params(salt)
	kek := crypto.DeriveKEK(newPassphrase, p)
	defer crypto.Zero(kek)

	epoch := v.Epoch + 1
	aad := wrapAAD(epoch, p)
	wrapped, err := crypto.Seal(kek, dek, aad)
	if err != nil {
		return err
	}
	// Self-check: the new wrap must round-trip to exactly the supplied DEK before
	// we overwrite the only copy (guards against re-wrapping a stale/wrong key).
	if back, err := crypto.Open(kek, wrapped, aad); err != nil || !crypto.ConstEqual(back, dek) {
		return errors.New("vault: passphrase-change self-check failed")
	} else {
		crypto.Zero(back)
	}
	return s.db.UpdateVaultWrap(&store.VaultRow{
		Epoch: epoch, ArgonTime: p.TimeT, ArgonMem: p.MemKiB, ArgonPar: p.Par,
		Salt: salt, WrappedDEK: wrapped,
	})
}

// fieldRole maps a (table, column) back to the (entity, field) used to build the
// AAD, so rekey can re-bind ciphertext to the same role under the new key.
var tableEntity = map[string]string{
	"projects": "project", "environments": "environment",
	"folders": "folder", "secrets": "secret", "vault": "vault",
	"attachments": "attachment",
}
var columnField = map[string]string{
	"name_enc": "name", "value_enc": "value", "notes_enc": "notes", "totp_enc": "totp",
	"data_enc": "data",
}

// Rekey rotates the data key: it re-encrypts every field under a new DEK and
// re-wraps it under the passphrase, atomically in one transaction. Returns the
// new DEK on success.
func (s *Service) Rekey(passphrase []byte) ([]byte, error) {
	v, err := s.db.GetVault()
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotInit
		}
		return nil, err
	}
	oldDEK, err := s.Unlock(passphrase) // verifies the passphrase
	if err != nil {
		return nil, err
	}
	defer crypto.Zero(oldDEK)

	newDEK, err := crypto.RandBytes(crypto.KeyLen)
	if err != nil {
		return nil, err
	}

	// Derive the new wrap up front (Argon2) so the write transaction is short.
	salt, err := crypto.RandBytes(crypto.SaltLen)
	if err != nil {
		crypto.Zero(newDEK)
		return nil, err
	}
	p := s.params(salt)
	kek := crypto.DeriveKEK(passphrase, p)
	defer crypto.Zero(kek)
	epoch := v.Epoch + 1
	wrapped, err := crypto.Seal(kek, newDEK, wrapAAD(epoch, p))
	if err != nil {
		crypto.Zero(newDEK)
		return nil, err
	}
	row := &store.VaultRow{Epoch: epoch, ArgonTime: p.TimeT, ArgonMem: p.MemKiB,
		ArgonPar: p.Par, Salt: salt, WrappedDEK: wrapped}

	transform := func(table, column, id string, blob []byte) ([]byte, error) {
		aad := fieldAAD(tableEntity[table], id, columnField[column])
		pt, err := crypto.Open(oldDEK, blob, aad)
		if err != nil {
			return nil, err
		}
		nb, err := crypto.Seal(newDEK, pt, aad)
		crypto.Zero(pt)
		return nb, err
	}

	if err := s.db.RekeyTx(transform, row); err != nil {
		crypto.Zero(newDEK)
		return nil, err
	}
	return newDEK, nil
}
