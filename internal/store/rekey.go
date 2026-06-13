package store

import "time"

// encryptedColumns enumerates every ciphertext column, by table. These are
// compile-time literals (never user input) so they are safe to interpolate.
var encryptedColumns = []struct {
	table   string
	columns []string
}{
	{"projects", []string{"name_enc"}},
	{"environments", []string{"name_enc"}},
	{"folders", []string{"name_enc"}},
	{"secrets", []string{"name_enc", "value_enc", "notes_enc"}},
	{"attachments", []string{"name_enc", "display_name_enc", "data_enc"}},
}

// RekeyTx re-encrypts every field and writes the new wrapped DEK in a single
// transaction. Because the pool is capped at one connection, holding this tx
// blocks all other writers for its (short) duration, so no record written
// concurrently can be lost. transform turns an old ciphertext into a new one.
func (db *DB) RekeyTx(transform func(table, column, id string, blob []byte) ([]byte, error), v *VaultRow) error {
	tx, err := db.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	type rec struct {
		table, column, id string
		blob              []byte
	}
	var recs []rec

	// Read every ciphertext value first (rows must be drained before issuing
	// writes on the same single connection).
	for _, t := range encryptedColumns {
		for _, col := range t.columns {
			rows, err := tx.Query("SELECT id, " + col + " FROM " + t.table)
			if err != nil {
				return err
			}
			for rows.Next() {
				var id string
				var b []byte
				if err := rows.Scan(&id, &b); err != nil {
					rows.Close()
					return err
				}
				if len(b) > 0 {
					recs = append(recs, rec{t.table, col, id, b})
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
		}
	}
	var totp []byte
	if err := tx.QueryRow(`SELECT totp_enc FROM vault WHERE id=1`).Scan(&totp); err != nil {
		return err
	}
	if len(totp) > 0 {
		recs = append(recs, rec{"vault", "totp_enc", "1", totp})
	}

	// Transform + write.
	for _, rc := range recs {
		nb, err := transform(rc.table, rc.column, rc.id, rc.blob)
		if err != nil {
			return err
		}
		if _, err := tx.Exec("UPDATE "+rc.table+" SET "+rc.column+"=? WHERE id=?", nb, rc.id); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE vault SET epoch=?, argon_time=?, argon_mem=?,
		argon_par=?, salt=?, wrapped_dek=?, updated_at=? WHERE id=1`,
		v.Epoch, v.ArgonTime, v.ArgonMem, v.ArgonPar, v.Salt, v.WrappedDEK, time.Now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}
