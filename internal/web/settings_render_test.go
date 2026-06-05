package web

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestShortDur(t *testing.T) {
	cases := map[time.Duration]string{
		30 * time.Minute:             "30m",
		12 * time.Hour:               "12h",
		90 * time.Minute:             "1h30m",
		45 * time.Second:             "45s",
		2*time.Hour + 30*time.Minute: "2h30m",
		time.Hour + time.Minute:      "1h1m",
	}
	for d, want := range cases {
		if got := shortDur(d); got != want {
			t.Errorf("shortDur(%v) = %q, want %q", d, got, want)
		}
		// must remain parseable
		if _, err := time.ParseDuration(shortDur(d)); err != nil {
			t.Errorf("shortDur(%v) not parseable: %v", d, err)
		}
	}
}

// TestSettingsTemplatesExecute renders the new pages end-to-end so a missing or
// mistyped field surfaces as a test failure rather than a 500 at runtime.
func TestSettingsTemplatesExecute(t *testing.T) {
	rd := newTestRenderer(t)
	base := Base{CSRF: "tok", Asset: "v", Chrome: true}

	sv := settingsView{
		Base: base, TOTPEnabled: true, Message: "ok", Error: "",
		BackupEnabled: true, BackupAt: "03:00", BackupKeep: 14,
		SessionIdle: "30m", SessionMax: "12h",
		Backups: []backupFile{{Name: "grafted-20260101-030000-ABCDEF.db", When: "2026-01-01 03:00", Size: "12.0 KiB"}},
	}
	var buf bytes.Buffer
	if err := rd.pages["settings"].ExecuteTemplate(&buf, "layout", sv); err != nil {
		t.Fatalf("settings render: %v", err)
	}
	if !strings.Contains(buf.String(), "grafted-20260101-030000-ABCDEF.db") {
		t.Error("backup file not rendered")
	}

	buf.Reset()
	rw := restoreWaitView{Base: Base{CSRF: "tok", Asset: "v"}, Safety: "grafted-20260101-040000-ABCDEF.db"}
	if err := rd.pages["restoreWait"].ExecuteTemplate(&buf, "layout", rw); err != nil {
		t.Fatalf("restoreWait render: %v", err)
	}
	if !strings.Contains(buf.String(), "data-restore-wait") {
		t.Error("restore-wait marker not rendered")
	}
}
