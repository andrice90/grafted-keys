package config

import "testing"

func TestArgonBoundsRejectBadValues(t *testing.T) {
	cases := []struct{ key, val string }{
		{"GRAFTED_ARGON_MEM_MIB", "4194323"}, // would overflow uint32*1024 back onto the floor
		{"GRAFTED_ARGON_MEM_MIB", "1"},       // below floor
		{"GRAFTED_ARGON_MEM_MIB", "-1"},      // negative
		{"GRAFTED_ARGON_TIME", "-1"},         // negative wraps to huge uint32
		{"GRAFTED_ARGON_TIME", "1"},          // below floor
		{"GRAFTED_ARGON_PAR", "257"},         // truncates to 1
		{"GRAFTED_ARGON_PAR", "0"},           // below floor
	}
	for _, c := range cases {
		t.Run(c.key+"="+c.val, func(t *testing.T) {
			t.Setenv(c.key, c.val)
			if _, err := Load(); err == nil {
				t.Errorf("expected Load() to reject %s=%s", c.key, c.val)
			}
		})
	}
}

func TestDefaultsAreValid(t *testing.T) {
	if _, err := Load(); err != nil {
		t.Fatalf("default config must be valid: %v", err)
	}
}
