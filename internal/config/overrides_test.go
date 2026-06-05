package config

import (
	"testing"
	"time"
)

func TestWithOverrides(t *testing.T) {
	base, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	c, err := base.WithOverrides(map[string]string{
		KeyBackupAt:    "04:30",
		KeyBackupKeep:  "7",
		KeySessionIdle: "15m",
		KeySessionMax:  "8h",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.BackupAt != "04:30" || c.BackupKeep != 7 {
		t.Errorf("backup overrides not applied: %+v", c)
	}
	if c.SessionIdle != 15*time.Minute || c.SessionMax != 8*time.Hour {
		t.Errorf("session overrides not applied: %+v", c)
	}

	// Unparseable values are ignored (env defaults survive), not fatal.
	c2, err := base.WithOverrides(map[string]string{
		KeyBackupKeep:  "not-a-number",
		KeySessionIdle: "garbage",
	})
	if err != nil {
		t.Fatalf("bad values should be ignored, not error: %v", err)
	}
	if c2.BackupKeep != base.BackupKeep || c2.SessionIdle != base.SessionIdle {
		t.Errorf("bad overrides should leave defaults intact: %+v", c2)
	}

	// Validation still runs: max below idle is raised to idle.
	c3, err := base.WithOverrides(map[string]string{KeySessionIdle: "2h", KeySessionMax: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	if c3.SessionMax < c3.SessionIdle {
		t.Errorf("validate should raise max to idle: %+v", c3)
	}
}
