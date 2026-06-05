// Package store is the persistence layer. It deals exclusively in ciphertext
// (encrypted BLOB columns) and opaque IDs - it never sees plaintext or keys.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("store: not found")

type DB struct{ sql *sql.DB }

// Open opens (creating if needed) the SQLite database at path, applies hardened
// pragmas, and runs migrations.
func Open(path string) (*DB, error) {
	dsn := "file:" + path +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=temp_store(MEMORY)" // keep transient temp/sorter data off a read-only fs

	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Single writer keeps a single-user vault free of SQLITE_BUSY races.
	sdb.SetMaxOpenConns(1)
	if err := sdb.Ping(); err != nil {
		sdb.Close()
		return nil, err
	}
	db := &DB{sql: sdb}
	if err := db.migrate(); err != nil {
		sdb.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) Close() error { return db.sql.Close() }

// Raw exposes the underlying handle (used by the backup snapshot).
func (db *DB) Raw() *sql.DB { return db.sql }

// Settings returns all runtime-adjustable operational settings as key→value.
func (db *DB) Settings() (map[string]string, error) {
	rows, err := db.sql.Query(`SELECT key, value FROM app_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SetSettings upserts the given key→value settings in a single transaction.
func (db *DB) SetSettings(kv map[string]string) error {
	tx, err := db.sql.Begin()
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	for k, v := range kv {
		if _, err := tx.Exec(
			`INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
			k, v, now); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// ValidateVaultFile opens path read-only and confirms it is a usable Grafted
// vault database (correct schema version and an initialized vault row). It is
// used to vet a backup file before a restore swaps it into place.
func ValidateVaultFile(path string) error {
	sdb, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return err
	}
	defer sdb.Close()
	if err := sdb.Ping(); err != nil {
		return fmt.Errorf("not a readable database: %w", err)
	}
	var version int
	if err := sdb.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("not a SQLite database: %w", err)
	}
	if version < 1 || version > len(migrations) {
		return fmt.Errorf("unsupported schema version %d (this binary supports 1..%d)", version, len(migrations))
	}
	var n int
	if err := sdb.QueryRow(`SELECT count(*) FROM vault WHERE id = 1`).Scan(&n); err != nil {
		return fmt.Errorf("missing vault table: %w", err)
	}
	if n != 1 {
		return errors.New("no initialized vault in file")
	}
	return nil
}

// migrations are applied in order; index+1 is the schema version.
var migrations = []string{
	`CREATE TABLE vault (
		id            INTEGER PRIMARY KEY CHECK (id = 1),
		epoch         INTEGER NOT NULL,
		argon_time    INTEGER NOT NULL,
		argon_mem     INTEGER NOT NULL,
		argon_par     INTEGER NOT NULL,
		salt          BLOB    NOT NULL,
		wrapped_dek   BLOB    NOT NULL,
		totp_enc      BLOB,
		totp_last     INTEGER NOT NULL DEFAULT 0,
		created_at    INTEGER NOT NULL,
		updated_at    INTEGER NOT NULL
	);
	CREATE TABLE projects (
		id         TEXT PRIMARY KEY,
		name_enc   BLOB NOT NULL,
		sort       INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE environments (
		id         TEXT PRIMARY KEY,
		project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
		name_enc   BLOB NOT NULL,
		sort       INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE folders (
		id             TEXT PRIMARY KEY,
		environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
		name_enc       BLOB NOT NULL,
		sort           INTEGER NOT NULL DEFAULT 0,
		created_at     INTEGER NOT NULL,
		updated_at     INTEGER NOT NULL
	);
	CREATE TABLE secrets (
		id         TEXT PRIMARY KEY,
		folder_id  TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
		name_enc   BLOB NOT NULL,
		value_enc  BLOB NOT NULL,
		notes_enc  BLOB NOT NULL,
		sort       INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE INDEX idx_env_project  ON environments(project_id);
	CREATE INDEX idx_folder_env   ON folders(environment_id);
	CREATE INDEX idx_secret_folder ON secrets(folder_id);`,

	// Allow a secret to attach to a folder OR directly to an environment
	// (uncategorized). SQLite can't relax NOT NULL in place, so rebuild the table.
	`CREATE TABLE secrets_new (
		id             TEXT PRIMARY KEY,
		folder_id      TEXT REFERENCES folders(id) ON DELETE CASCADE,
		environment_id TEXT REFERENCES environments(id) ON DELETE CASCADE,
		name_enc       BLOB NOT NULL,
		value_enc      BLOB NOT NULL,
		notes_enc      BLOB NOT NULL,
		sort           INTEGER NOT NULL DEFAULT 0,
		created_at     INTEGER NOT NULL,
		updated_at     INTEGER NOT NULL,
		CHECK ((folder_id IS NOT NULL) <> (environment_id IS NOT NULL))
	);
	INSERT INTO secrets_new (id, folder_id, environment_id, name_enc, value_enc, notes_enc, sort, created_at, updated_at)
		SELECT id, folder_id, NULL, name_enc, value_enc, notes_enc, sort, created_at, updated_at FROM secrets;
	DROP TABLE secrets;
	ALTER TABLE secrets_new RENAME TO secrets;
	CREATE INDEX idx_secret_folder ON secrets(folder_id);
	CREATE INDEX idx_secret_env    ON secrets(environment_id);`,

	// Runtime-adjustable operational settings (backup schedule/retention, session
	// timeouts). These are plaintext, not secrets, so they can be read before the
	// vault is unlocked and override the corresponding env defaults at startup.
	`CREATE TABLE app_settings (
		key        TEXT PRIMARY KEY,
		value      TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	);`,
}

func (db *DB) migrate() error {
	var version int
	if err := db.sql.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("store: database schema version %d is newer than this binary supports (%d) - upgrade the app or restore a compatible backup", version, len(migrations))
	}
	for i := version; i < len(migrations); i++ {
		tx, err := db.sql.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
