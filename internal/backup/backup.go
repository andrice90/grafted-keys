// Package backup makes consistent, encrypted-at-rest snapshots of the SQLite
// database on a daily schedule and prunes old ones. Because the database is
// ciphertext at rest, backups need no key and run even while the vault is locked.
package backup

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/andrew/grafted-secrets/internal/crypto"
	"github.com/andrew/grafted-secrets/internal/store"
)

const prefix = "grafted-"

type Scheduler struct {
	db  *store.DB
	dir string

	mu     sync.Mutex
	at     string // "HH:MM"; empty disables scheduling
	keep   int
	reload chan struct{} // nudges Run to recompute after a live schedule change
}

func New(db *store.DB, dir, at string, keep int) *Scheduler {
	if keep < 1 {
		keep = 1
	}
	return &Scheduler{db: db, dir: dir, at: at, keep: keep, reload: make(chan struct{}, 1)}
}

// Schedule returns the currently active backup time ("HH:MM"; empty = disabled)
// and retention count.
func (s *Scheduler) Schedule() (at string, keep int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.at, s.keep
}

// SetSchedule updates the live backup time and retention and wakes Run so the
// change takes effect immediately (no restart).
func (s *Scheduler) SetSchedule(at string, keep int) {
	if keep < 1 {
		keep = 1
	}
	s.mu.Lock()
	s.at, s.keep = at, keep
	s.mu.Unlock()
	select {
	case s.reload <- struct{}{}:
	default: // a reload is already pending
	}
}

// Run blocks until ctx is cancelled, taking a snapshot daily at the configured
// time. A disabled schedule (empty at) waits until enabled or cancelled. Live
// schedule changes (SetSchedule) recompute the next fire immediately.
func (s *Scheduler) Run(ctx context.Context) {
	for {
		at, _ := s.Schedule()
		var fire <-chan time.Time
		var t *time.Timer
		if at != "" {
			t = time.NewTimer(untilNext(at, time.Now()))
			fire = t.C
		}
		select {
		case <-ctx.Done():
			if t != nil {
				t.Stop()
			}
			return
		case <-s.reload:
			if t != nil {
				t.Stop()
			}
			// loop: recompute with the new schedule
		case <-fire:
			if path, err := s.Snapshot(); err != nil {
				log.Printf("backup: snapshot failed: %v", err)
			} else {
				log.Printf("backup: wrote %s", path)
			}
		}
	}
}

// Snapshot writes a consistent copy of the database and prunes old backups.
func (s *Scheduler) Snapshot() (string, error) {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return "", err
	}
	// Timestamp keeps chronological sort order; the random suffix avoids a
	// VACUUM-INTO failure if two snapshots land in the same second.
	ts := time.Now().Format("20060102-150405")
	path := filepath.Join(s.dir, prefix+ts+"-"+crypto.RandID()[:6]+".db")
	// path is generated (no user input); escape defensively for the SQL literal.
	lit := strings.ReplaceAll(path, "'", "''")
	if _, err := s.db.Raw().Exec("VACUUM INTO '" + lit + "'"); err != nil {
		return "", err
	}
	if err := s.prune(); err != nil {
		log.Printf("backup: prune failed: %v", err)
	}
	return path, nil
}

func (s *Scheduler) prune() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), prefix) && strings.HasSuffix(e.Name(), ".db") {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names))) // timestamp names sort chronologically
	s.mu.Lock()
	keep := s.keep
	s.mu.Unlock()
	for i := keep; i < len(names); i++ {
		if err := os.Remove(filepath.Join(s.dir, names[i])); err != nil {
			return err
		}
	}
	return nil
}

// untilNext returns the duration from now to the next occurrence of "HH:MM".
func untilNext(hhmm string, now time.Time) time.Duration {
	parsed, err := time.Parse("15:04", hhmm)
	if err != nil {
		return 24 * time.Hour
	}
	next := time.Date(now.Year(), now.Month(), now.Day(), parsed.Hour(), parsed.Minute(), 0, 0, now.Location())
	// On a DST spring-forward day the configured wall time may not exist and
	// time.Date normalizes it backwards an hour; nudge it forward to the intended time.
	if next.Hour() != parsed.Hour() || next.Minute() != parsed.Minute() {
		next = next.Add(time.Hour)
	}
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next.Sub(now)
}
