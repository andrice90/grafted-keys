package store

import (
	"database/sql"
	"errors"
	"time"
)

// VaultRow is the single-row encrypted vault metadata (id = 1).
type VaultRow struct {
	Epoch      int64
	ArgonTime  uint32
	ArgonMem   uint32
	ArgonPar   uint8
	Salt       []byte
	WrappedDEK []byte
	TOTPEnc    []byte // nil when TOTP disabled
	TOTPLast   int64
}

// VaultInitialized reports whether the vault metadata row exists.
func (db *DB) VaultInitialized() (bool, error) {
	var n int
	err := db.sql.QueryRow(`SELECT COUNT(*) FROM vault WHERE id = 1`).Scan(&n)
	return n > 0, err
}

// HasData reports whether any encrypted content exists. Used to refuse re-setup
// (which would orphan/lose existing ciphertext) when the vault row is missing.
func (db *DB) HasData() (bool, error) {
	var n int
	err := db.sql.QueryRow(`SELECT COUNT(*) FROM projects`).Scan(&n)
	return n > 0, err
}

func (db *DB) GetVault() (*VaultRow, error) {
	v := &VaultRow{}
	var totp []byte
	err := db.sql.QueryRow(`SELECT epoch, argon_time, argon_mem, argon_par, salt,
		wrapped_dek, totp_enc, totp_last FROM vault WHERE id = 1`).
		Scan(&v.Epoch, &v.ArgonTime, &v.ArgonMem, &v.ArgonPar, &v.Salt,
			&v.WrappedDEK, &totp, &v.TOTPLast)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	v.TOTPEnc = totp
	return v, nil
}

// InitVault atomically inserts the vault metadata row. It fails if one exists.
func (db *DB) InitVault(v *VaultRow) error {
	now := time.Now().Unix()
	_, err := db.sql.Exec(`INSERT INTO vault
		(id, epoch, argon_time, argon_mem, argon_par, salt, wrapped_dek, totp_enc, totp_last, created_at, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, NULL, 0, ?, ?)`,
		v.Epoch, v.ArgonTime, v.ArgonMem, v.ArgonPar, v.Salt, v.WrappedDEK, now, now)
	return err
}

// UpdateVaultWrap replaces the KDF params + wrapped DEK (passphrase change / rekey).
func (db *DB) UpdateVaultWrap(v *VaultRow) error {
	_, err := db.sql.Exec(`UPDATE vault SET epoch=?, argon_time=?, argon_mem=?,
		argon_par=?, salt=?, wrapped_dek=?, updated_at=? WHERE id=1`,
		v.Epoch, v.ArgonTime, v.ArgonMem, v.ArgonPar, v.Salt, v.WrappedDEK, time.Now().Unix())
	return err
}

// SetTOTP enables TOTP and records lastStep as the already-consumed enrollment
// step, so that code cannot be replayed at the first login.
func (db *DB) SetTOTP(enc []byte, lastStep int64) error {
	_, err := db.sql.Exec(`UPDATE vault SET totp_enc=?, totp_last=?, updated_at=? WHERE id=1`,
		enc, lastStep, time.Now().Unix())
	return err
}

func (db *DB) ClearTOTP() error {
	_, err := db.sql.Exec(`UPDATE vault SET totp_enc=NULL, totp_last=0, updated_at=? WHERE id=1`,
		time.Now().Unix())
	return err
}

func (db *DB) UpdateTOTPLast(step int64) error {
	_, err := db.sql.Exec(`UPDATE vault SET totp_last=? WHERE id=1`, step)
	return err
}
