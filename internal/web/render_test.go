package web

import (
	"strings"
	"testing"

	assets "github.com/andrew/grafted-secrets/web"
)

func newTestRenderer(t *testing.T) *Renderer {
	t.Helper()
	rd, err := NewRenderer(assets.Files)
	if err != nil {
		t.Fatalf("templates failed to parse: %v", err)
	}
	return rd
}

func TestTemplatesParse(t *testing.T) { newTestRenderer(t) }

func TestMarkdownSanitizesXSS(t *testing.T) {
	rd := newTestRenderer(t)
	payloads := []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`[click](javascript:alert(1))`,
		`<svg onload=alert(1)>`,
	}
	for _, p := range payloads {
		out := strings.ToLower(string(rd.Markdown(p)))
		if strings.Contains(out, "<script") || strings.Contains(out, "onerror") ||
			strings.Contains(out, "onload") || strings.Contains(out, "javascript:") {
			t.Errorf("payload not sanitized: %q -> %q", p, out)
		}
	}
}

func TestMarkdownRendersSafe(t *testing.T) {
	rd := newTestRenderer(t)
	out := string(rd.Markdown("**bold** and `code`"))
	if !strings.Contains(out, "<strong>bold</strong>") || !strings.Contains(out, "<code>code</code>") {
		t.Errorf("expected rendered markdown, got %q", out)
	}
}

func TestHighlightEscapes(t *testing.T) {
	out := string(highlight(`<b>API</b>`, "api"))
	if strings.Contains(out, "<b>") {
		t.Errorf("highlight must escape HTML: %q", out)
	}
	if !strings.Contains(out, "<mark>") {
		t.Errorf("highlight must mark matches: %q", out)
	}
}

func TestHighlightNoPanic(t *testing.T) {
	// Queries whose case-folded length differs from the source must not panic.
	cases := [][2]string{
		{"İstanbul API", "i"}, // Turkish dotted I changes length under ToLower
		{"straße key", "ss"},
		{"plain text", ""},
		{"ünïçödé", "ö"},
	}
	for _, c := range cases {
		_ = highlight(c[0], c[1]) // must not panic
	}
}
