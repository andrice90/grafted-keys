package web

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/andrew/grafted-secrets/internal/auth"
	"github.com/andrew/grafted-secrets/internal/config"
	"github.com/andrew/grafted-secrets/internal/crypto"
	"github.com/andrew/grafted-secrets/internal/store"
)

// maxRestoreBytes caps how much data a restore upload/copy will read.
const maxRestoreBytes = 256 << 20 // 256 MiB

// backupNameRE matches the snapshot filenames Scheduler.Snapshot produces:
// grafted-YYYYMMDD-HHMMSS-<6 base32 chars>.db. Used to vet download/restore
// names so neither can reach outside the backup directory.
var backupNameRE = regexp.MustCompile(`^grafted-\d{8}-\d{6}-[A-Z2-7]{6}\.db$`)

type backupFile struct {
	Name string
	When string
	Size string
}

type settingsView struct {
	Base
	TOTPEnabled bool
	Message     string
	Error       string

	// Currently-applied (live) operational settings, shown as read-only labels
	// separate from the edit forms so a save visibly updates them.
	BackupEnabled bool
	BackupAt      string // "HH:MM"
	BackupKeep    int
	SessionIdle   string // compact duration, e.g. "30m"
	SessionMax    string

	Backups []backupFile
}

type totpEnrollView struct {
	Secret string
	URI    string
}

type restoreWaitView struct {
	Base
	Safety string // filename of the safety snapshot taken before the restore
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, sess *auth.Session, msg, errMsg string) {
	enabled, _ := s.vault.TOTPEnabled()
	at, keep := s.backups.Schedule()
	idle, max := s.sessions.Timeouts()
	b := s.base(r, sess)
	b.TOTPEnabled = enabled
	s.rd.Page(w, r, "settings", settingsView{
		Base: b, TOTPEnabled: enabled, Message: msg, Error: errMsg,
		BackupEnabled: at != "", BackupAt: at, BackupKeep: keep,
		SessionIdle: shortDur(idle), SessionMax: shortDur(max),
		Backups: s.listBackups(),
	})
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	s.renderSettings(w, r, sess, "", "")
}

func (s *Server) changePassphrase(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	ip := auth.ClientIP(r, s.cfg.TrustProxy)
	if !s.limiter.Allowed(ip) {
		w.Header().Set("Retry-After", retryAfterSecs(s.limiter.RetryAfter(ip)))
		w.WriteHeader(http.StatusTooManyRequests)
		s.renderSettings(w, r, sess, "", "Too many attempts. Try again later.")
		return
	}
	newPass := r.FormValue("new")
	confirm := r.FormValue("confirm")
	if len([]rune(newPass)) < minPassphrase {
		s.renderSettings(w, r, sess, "", "New passphrase must be at least 8 characters.")
		return
	}
	if newPass != confirm {
		s.renderSettings(w, r, sess, "", "New passphrases do not match.")
		return
	}

	// Re-verify the current passphrase and use the DEK it yields (never a
	// possibly-stale session DEK) for the re-wrap.
	current := []byte(r.FormValue("current"))
	verifyDEK, err := s.vault.Unlock(current)
	crypto.Zero(current)
	if err != nil {
		s.limiter.Fail(ip)
		s.renderSettings(w, r, sess, "", "Current passphrase is incorrect.")
		return
	}
	s.limiter.Reset(ip)

	np := []byte(newPass)
	err = s.vault.ChangePassphrase(verifyDEK, np)
	crypto.Zero(np)
	crypto.Zero(verifyDEK)
	if err != nil {
		s.renderSettings(w, r, sess, "", "Could not change passphrase.")
		return
	}
	s.renderSettings(w, r, sess, "Passphrase changed.", "")
}

func (s *Server) rekey(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	ip := auth.ClientIP(r, s.cfg.TrustProxy)
	if !s.limiter.Allowed(ip) {
		w.Header().Set("Retry-After", retryAfterSecs(s.limiter.RetryAfter(ip)))
		w.WriteHeader(http.StatusTooManyRequests)
		s.renderSettings(w, r, sess, "", "Too many attempts. Try again later.")
		return
	}
	pass := []byte(r.FormValue("passphrase"))
	newDEK, err := s.vault.Rekey(pass)
	crypto.Zero(pass)
	if err != nil {
		s.limiter.Fail(ip)
		s.renderSettings(w, r, sess, "", "Re-key failed (check passphrase).")
		return
	}
	s.limiter.Reset(ip)
	s.sessions.SetDEK(sess.ID, newDEK) // session now uses the new key
	s.renderSettings(w, r, sess, "Data key rotated; all secrets re-encrypted.", "")
}

func (s *Server) totpBegin(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	secret, uri, err := crypto.NewTOTPSecret("grafted")
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "totpEnroll", totpEnrollView{Secret: secret, URI: uri})
}

func (s *Server) totpConfirm(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	secret := r.FormValue("secret")
	code := strings.TrimSpace(r.FormValue("code"))
	ok, err := s.vault.ConfirmTOTP(dek, secret, code)
	if err != nil || !ok {
		s.renderSettings(w, r, sess, "", "Code did not verify. Two-factor not enabled.")
		return
	}
	s.renderSettings(w, r, sess, "Two-factor authentication enabled.", "")
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	if err := s.vault.DisableTOTP(); err != nil {
		s.fail(w, err)
		return
	}
	s.renderSettings(w, r, sess, "Two-factor authentication disabled.", "")
}

func (s *Server) backupNow(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	if s.backups == nil {
		s.renderSettings(w, r, sess, "", "Backups are not configured.")
		return
	}
	if _, err := s.backups.Snapshot(); err != nil {
		s.renderSettings(w, r, sess, "", "Backup failed: "+err.Error())
		return
	}
	s.renderSettings(w, r, sess, "Backup created.", "")
}

// saveBackupConfig persists and live-applies the backup schedule and retention.
func (s *Server) saveBackupConfig(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	enabled := r.FormValue("enabled") != ""
	at := strings.TrimSpace(r.FormValue("at"))
	if enabled {
		if _, err := time.Parse("15:04", at); err != nil {
			s.renderSettings(w, r, sess, "", "Backup time must be HH:MM (24-hour).")
			return
		}
	} else {
		at = "" // empty disables scheduling
	}
	keep, err := strconv.Atoi(strings.TrimSpace(r.FormValue("keep")))
	if err != nil || keep < 1 {
		s.renderSettings(w, r, sess, "", "Retention must be a whole number of at least 1.")
		return
	}
	if err := s.db.SetSettings(map[string]string{
		config.KeyBackupAt:   at,
		config.KeyBackupKeep: strconv.Itoa(keep),
	}); err != nil {
		s.renderSettings(w, r, sess, "", "Could not save settings.")
		return
	}
	s.backups.SetSchedule(at, keep) // takes effect immediately
	s.renderSettings(w, r, sess, "Backup settings saved and applied.", "")
}

// saveSessionConfig persists and live-applies the session idle/absolute timeouts.
func (s *Server) saveSessionConfig(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	idle, err := time.ParseDuration(strings.TrimSpace(r.FormValue("idle")))
	if err != nil || idle <= 0 {
		s.renderSettings(w, r, sess, "", "Idle timeout must be a positive duration like 30m or 2h.")
		return
	}
	max, err := time.ParseDuration(strings.TrimSpace(r.FormValue("max")))
	if err != nil || max <= 0 {
		s.renderSettings(w, r, sess, "", "Max session must be a positive duration like 12h.")
		return
	}
	if max < idle {
		s.renderSettings(w, r, sess, "", "Max session must be at least the idle timeout.")
		return
	}
	if err := s.db.SetSettings(map[string]string{
		config.KeySessionIdle: shortDur(idle),
		config.KeySessionMax:  shortDur(max),
	}); err != nil {
		s.renderSettings(w, r, sess, "", "Could not save settings.")
		return
	}
	s.sessions.SetTimeouts(idle, max) // enforced on the next request and sweep
	s.renderSettings(w, r, sess, "Session settings saved and applied.", "")
}

// downloadBackup streams a single backup file as an attachment.
func (s *Server) downloadBackup(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	name := r.PathValue("name")
	path, ok := s.safeBackupPath(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, info.ModTime(), f)
}

// restore validates a chosen backup (uploaded or selected), takes a safety
// snapshot of the current vault, stages the backup, and restarts so a clean
// boot swaps it into place. Replacing the live SQLite file in-process is unsafe,
// so the swap is deferred to startup (see applyPendingRestore in main).
func (s *Server) restore(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	if !strings.EqualFold(strings.TrimSpace(r.FormValue("confirm")), "restore backup") {
		s.renderSettings(w, r, sess, "", `Type "restore backup" exactly to confirm.`)
		return
	}

	src, err := s.restoreSource(r)
	if err != nil {
		s.renderSettings(w, r, sess, "", err.Error())
		return
	}
	defer src.Close()

	// Stage to a temp file in the data dir, validate, then commit by rename.
	pending := filepath.Join(s.cfg.DataDir, "restore-pending.db")
	tmp := pending + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		s.renderSettings(w, r, sess, "", "Could not stage the restore.")
		return
	}
	if _, err := io.Copy(out, io.LimitReader(src, maxRestoreBytes)); err != nil {
		out.Close()
		os.Remove(tmp)
		s.renderSettings(w, r, sess, "", "Could not read the backup data.")
		return
	}
	out.Close()
	if err := store.ValidateVaultFile(tmp); err != nil {
		os.Remove(tmp)
		s.renderSettings(w, r, sess, "", "That file is not a valid Grafted backup ("+err.Error()+").")
		return
	}

	// Always snapshot the CURRENT vault before swapping it out.
	var safety string
	if name, err := s.backups.Snapshot(); err == nil {
		safety = filepath.Base(name)
	}

	if err := os.Rename(tmp, pending); err != nil {
		os.Remove(tmp)
		s.renderSettings(w, r, sess, "", "Could not finalize the restore staging.")
		return
	}

	// Full-page interstitial (this is a plain, non-htmx form post) that polls
	// until the server comes back, then sends the user to unlock.
	b := s.authBase(r, sess)
	s.rd.Page(w, r, "restoreWait", restoreWaitView{Base: b, Safety: safety})
	if s.restart != nil {
		s.restart()
	}
}

// restoreSource resolves the restore input to a readable stream: either an
// uploaded file or an existing backup selected from the list.
func (s *Server) restoreSource(r *http.Request) (io.ReadCloser, error) {
	switch r.FormValue("source") {
	case "existing":
		path, ok := s.safeBackupPath(r.FormValue("existing_name"))
		if !ok {
			return nil, fmt.Errorf("Choose a valid backup to restore from.")
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("The selected backup could not be opened.")
		}
		return f, nil
	case "upload":
		f, _, err := r.FormFile("file")
		if err != nil {
			return nil, fmt.Errorf("Choose a backup file to upload.")
		}
		return f, nil
	default:
		return nil, fmt.Errorf("Choose a restore source.")
	}
}

// safeBackupPath joins a vetted backup filename to the backup dir, refusing any
// name that isn't a plain snapshot filename (defeating path traversal).
func (s *Server) safeBackupPath(name string) (string, bool) {
	if name == "" || name != filepath.Base(name) || !backupNameRE.MatchString(name) {
		return "", false
	}
	return filepath.Join(s.cfg.BackupDir, name), true
}

// listBackups returns retained snapshots, newest first, with display metadata.
func (s *Server) listBackups() []backupFile {
	entries, err := os.ReadDir(s.cfg.BackupDir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && backupNameRE.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names))) // timestamped names sort chronologically
	out := make([]backupFile, 0, len(names))
	for _, n := range names {
		bf := backupFile{Name: n}
		if info, err := os.Stat(filepath.Join(s.cfg.BackupDir, n)); err == nil {
			bf.When = info.ModTime().Format("2006-01-02 15:04")
			bf.Size = humanSize(info.Size())
		}
		out = append(out, bf)
	}
	return out
}

// shortDur renders a duration the way a user would type it (e.g. "30m", "12h"),
// trimming Go's zero trailing units. The result is still time.ParseDuration-able.
func shortDur(d time.Duration) string {
	str := d.String()
	if strings.HasSuffix(str, "m0s") {
		str = strings.TrimSuffix(str, "0s")
	}
	if strings.HasSuffix(str, "h0m") {
		str = strings.TrimSuffix(str, "0m")
	}
	return str
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
