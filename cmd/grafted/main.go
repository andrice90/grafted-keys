// Command grafted is the Grafted Secrets server: a minimal, security-hardened,
// zero-knowledge secrets manager with scheduled encrypted backups.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/andrew/grafted-secrets/internal/auth"
	"github.com/andrew/grafted-secrets/internal/backup"
	"github.com/andrew/grafted-secrets/internal/config"
	"github.com/andrew/grafted-secrets/internal/store"
	"github.com/andrew/grafted-secrets/internal/vault"
	"github.com/andrew/grafted-secrets/internal/web"
	assets "github.com/andrew/grafted-secrets/web"
)

var version = "dev"

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe /healthz and exit (for container HEALTHCHECK)")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if *healthcheck {
		os.Exit(probe(cfg.Addr))
	}

	if err := run(cfg); err != nil {
		log.Fatal(err)
	}
}

func run(cfg config.Config) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}

	// Apply a restore staged by a previous run before opening the DB: swapping
	// the live SQLite file in-process is unsafe, so it is deferred to a clean boot.
	if err := applyPendingRestore(cfg.DataDir); err != nil {
		return err
	}

	db, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer db.Close()

	// Persisted operational settings override env defaults at runtime.
	if stored, err := db.Settings(); err != nil {
		log.Printf("settings: load failed, using env defaults: %v", err)
	} else if merged, err := cfg.WithOverrides(stored); err != nil {
		log.Printf("settings: stored values invalid, using env defaults: %v", err)
	} else {
		cfg = merged
	}

	v := vault.New(db, cfg.Argon)
	sessions := auth.NewSessions(cfg.SessionIdle, cfg.SessionMax)
	limiter := auth.NewLimiter()
	scheduler := backup.New(db, cfg.BackupDir, cfg.BackupAt, cfg.BackupKeep)

	// restart triggers a graceful shutdown; the container restart policy brings
	// the process back, where applyPendingRestore swaps in a staged restore.
	restart := func() {
		log.Print("restart requested (applying staged restore)")
		if p, err := os.FindProcess(os.Getpid()); err == nil {
			_ = p.Signal(syscall.SIGTERM)
		}
	}

	srv, err := web.NewServer(cfg, v, sessions, limiter, db, scheduler, restart, assets.Files)
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 18, // 256 KiB
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go scheduler.Run(ctx)
	go sweep(ctx, sessions, limiter)

	errCh := make(chan error, 1)
	go func() {
		log.Printf("grafted-secrets %s listening on %s", version, cfg.Addr)
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Print("shutting down...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutCtx)
	}
}

func sweep(ctx context.Context, sessions *auth.Sessions, limiter *auth.Limiter) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sessions.EvictExpired()
			limiter.Sweep()
		}
	}
}

// applyPendingRestore swaps a previously-staged restore file in as the live
// database. It runs before the DB is opened so the swap is clean and atomic; an
// invalid staged file is discarded rather than allowed to brick startup.
func applyPendingRestore(dataDir string) error {
	pending := filepath.Join(dataDir, "restore-pending.db")
	if _, err := os.Stat(pending); err != nil {
		return nil // nothing staged
	}
	if err := store.ValidateVaultFile(pending); err != nil {
		log.Printf("restore: staged file invalid, discarding: %v", err)
		os.Remove(pending)
		return nil
	}
	live := filepath.Join(dataDir, "grafted.db")
	// Drop the live DB and its WAL/SHM sidecars before swapping the new file in.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.Remove(live + suffix); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("restore: clearing %s: %w", live+suffix, err)
		}
	}
	if err := os.Rename(pending, live); err != nil {
		return fmt.Errorf("restore: swap failed: %w", err)
	}
	log.Print("restore: staged backup applied as the live database")
	return nil
}

// probe performs the container health check against the local listener.
func probe(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		port = "8080"
	}
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
