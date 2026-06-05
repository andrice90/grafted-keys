// Package config loads and validates runtime configuration from the environment.
// All knobs have safe defaults; security-relevant values are floored, never
// silently weakened by a bad env value.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// Argon2id KDF parameters. Floors are enforced in Validate.
type Argon struct {
	TimeT  uint32 // iterations
	MemKiB uint32 // memory in KiB
	Par    uint8  // parallelism (lanes)
}

// Acceptable Argon2id cost bounds. Floors follow RFC 9106; ceilings stop a
// misconfiguration (or integer overflow) from hanging/OOM-ing the process.
const (
	minArgonMemMiB = 19
	maxArgonMemMiB = 4096 // 4 GiB
	minArgonTime   = 2
	maxArgonTime   = 30
	minArgonPar    = 1
	maxArgonPar    = 255
)

type Config struct {
	Addr      string
	DataDir   string
	BackupDir string

	BackupAt   string // "HH:MM" daily; empty disables scheduled backups
	BackupKeep int

	SessionIdle time.Duration // auto-lock after inactivity
	SessionMax  time.Duration // absolute session lifetime

	SecureCookie bool
	TrustProxy   bool
	HSTS         bool

	Argon Argon
}

// DBPath is the SQLite database file location.
func (c Config) DBPath() string { return filepath.Join(c.DataDir, "grafted.db") }

// Setting keys for the runtime-adjustable values persisted in the database.
// A stored value overrides the corresponding env default (see WithOverrides).
const (
	KeyBackupAt    = "backup_at"
	KeyBackupKeep  = "backup_keep"
	KeySessionIdle = "session_idle"
	KeySessionMax  = "session_max"
)

// WithOverrides returns a copy of c with any persisted settings applied on top
// of the env-derived values, re-validated. Unknown or unparseable values are
// ignored so a malformed row can never brick startup. DataDir/BackupDir are not
// overridable (they are filesystem mounts, not runtime knobs).
func (c Config) WithOverrides(kv map[string]string) (Config, error) {
	if v, ok := kv[KeyBackupAt]; ok {
		c.BackupAt = v
	}
	if v, ok := kv[KeyBackupKeep]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			c.BackupKeep = n
		}
	}
	if v, ok := kv[KeySessionIdle]; ok {
		if d, err := time.ParseDuration(v); err == nil {
			c.SessionIdle = d
		}
	}
	if v, ok := kv[KeySessionMax]; ok {
		if d, err := time.ParseDuration(v); err == nil {
			c.SessionMax = d
		}
	}
	return c, c.Validate()
}

// Load reads configuration from the environment and validates it.
func Load() (Config, error) {
	c := Config{
		Addr:         env("GRAFTED_ADDR", ":8080"),
		DataDir:      env("GRAFTED_DATA_DIR", "/data"),
		BackupDir:    env("GRAFTED_BACKUP_DIR", "/backups"),
		BackupAt:     env("GRAFTED_BACKUP_AT", "03:00"),
		BackupKeep:   envInt("GRAFTED_BACKUP_KEEP", 14),
		SessionIdle:  envDur("GRAFTED_SESSION_IDLE", 30*time.Minute),
		SessionMax:   envDur("GRAFTED_SESSION_MAX", 12*time.Hour),
		SecureCookie: envBool("GRAFTED_SECURE_COOKIE", true),
		TrustProxy:   envBool("GRAFTED_TRUST_PROXY", false),
		HSTS:         envBool("GRAFTED_HSTS", false),
	}
	argon, err := loadArgon()
	if err != nil {
		return c, err
	}
	c.Argon = argon
	return c, c.Validate()
}

// loadArgon reads the KDF parameters as plain ints and range-checks them BEFORE
// narrowing to fixed-width types, so a negative or huge value can never wrap
// around and silently satisfy the floor.
func loadArgon() (Argon, error) {
	memMiB := envInt("GRAFTED_ARGON_MEM_MIB", 64)
	timeT := envInt("GRAFTED_ARGON_TIME", 3)
	par := envInt("GRAFTED_ARGON_PAR", defaultPar())
	if memMiB < minArgonMemMiB || memMiB > maxArgonMemMiB {
		return Argon{}, fmt.Errorf("GRAFTED_ARGON_MEM_MIB must be in [%d, %d]", minArgonMemMiB, maxArgonMemMiB)
	}
	if timeT < minArgonTime || timeT > maxArgonTime {
		return Argon{}, fmt.Errorf("GRAFTED_ARGON_TIME must be in [%d, %d]", minArgonTime, maxArgonTime)
	}
	if par < minArgonPar || par > maxArgonPar {
		return Argon{}, fmt.Errorf("GRAFTED_ARGON_PAR must be in [%d, %d]", minArgonPar, maxArgonPar)
	}
	return Argon{TimeT: uint32(timeT), MemKiB: uint32(memMiB) * 1024, Par: uint8(par)}, nil
}

func (c *Config) Validate() error {
	if c.BackupKeep < 1 {
		c.BackupKeep = 1
	}
	if c.BackupAt != "" {
		if _, err := time.Parse("15:04", c.BackupAt); err != nil {
			return fmt.Errorf("GRAFTED_BACKUP_AT must be HH:MM (24h): %w", err)
		}
	}
	if c.SessionIdle <= 0 {
		c.SessionIdle = 30 * time.Minute
	}
	if c.SessionMax < c.SessionIdle {
		c.SessionMax = c.SessionIdle
	}
	return nil
}

func defaultPar() int {
	if n := runtime.NumCPU(); n < 4 {
		return n
	}
	return 4
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(k string, def bool) bool {
	switch os.Getenv(k) {
	case "1", "true", "TRUE", "yes", "on":
		return true
	case "0", "false", "FALSE", "no", "off":
		return false
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
