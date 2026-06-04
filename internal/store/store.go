// Package store is the persistence layer. It deals exclusively in ciphertext
// (encrypted BLOB columns) and opaque IDs — it never sees plaintext or keys.
package store

import (
	"database/sql"
	"errors"
	"fmt"

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
}

func (db *DB) migrate() error {
	var version int
	if err := db.sql.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("store: database schema version %d is newer than this binary supports (%d) — upgrade the app or restore a compatible backup", version, len(migrations))
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
