package web

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andrew/grafted-secrets/internal/vault"
)

func TestSecretDetailRendersAttachments(t *testing.T) {
	rd := newTestRenderer(t)
	rec := httptest.NewRecorder()
	rd.Frag(rec, "secretDetail", secretDetailView{
		ID: "S1", Name: "K",
		Attachments: []vault.AttachmentMeta{{ID: "A1", SecretID: "S1", Name: "r&d <x>.pdf", Size: 2048}},
	})
	body := rec.Body.String()
	if !strings.Contains(body, "/attachments/A1/download") {
		t.Error("download link missing")
	}
	if !strings.Contains(body, "2.0 KiB") {
		t.Error("file size not humanized")
	}
	if strings.Contains(body, "<x>") || !strings.Contains(body, "&lt;x&gt;") {
		t.Errorf("filename not HTML-escaped: %s", body)
	}
}

func TestSecretDetailRendersAttachmentsWithDisplayName(t *testing.T) {
	rd := newTestRenderer(t)
	rec := httptest.NewRecorder()
	rd.Frag(rec, "secretDetail", secretDetailView{
		ID: "S1", Name: "K",
		Attachments: []vault.AttachmentMeta{{ID: "A1", SecretID: "S1", Name: "actualfile", DisplayName: "Friendly Display Name", Size: 2048}},
	})
	body := rec.Body.String()
	if !strings.Contains(body, "Friendly Display Name") {
		t.Error("display name missing")
	}
	if !strings.Contains(body, "actualfile") {
		t.Error("filename missing")
	}
}

func TestAttachEditFormTemplate(t *testing.T) {
	rd := newTestRenderer(t)
	rec := httptest.NewRecorder()
	rd.Frag(rec, "attachEditForm", vault.AttachmentMeta{
		ID: "A1", SecretID: "S1", Name: "actualfile", DisplayName: "Current Display Name", Size: 2048,
	})
	body := rec.Body.String()
	if !strings.Contains(body, "Current Display Name") {
		t.Error("display name input value missing")
	}
	if !strings.Contains(body, `hx-post="/attachments/A1/edit-inline"`) {
		t.Error("post route missing")
	}
	if !strings.Contains(body, `hx-get="/attachments/A1/row"`) {
		t.Error("cancel route missing")
	}
}

func TestAttachItemTemplate(t *testing.T) {
	rd := newTestRenderer(t)
	rec := httptest.NewRecorder()
	rd.Frag(rec, "attachItem", map[string]any{
		"Item": vault.AttachmentMeta{
			ID: "A1", SecretID: "S1", Name: "actualfile", DisplayName: "Test Display Name", Size: 2048,
		},
		"SecretID": "S1",
	})
	body := rec.Body.String()
	if !strings.Contains(body, "Test Display Name") {
		t.Error("display name missing from item")
	}
	if !strings.Contains(body, "actualfile") {
		t.Error("filename missing from item")
	}
	if !strings.Contains(body, `hx-get="/attachments/A1/edit-inline"`) {
		t.Error("edit inline trigger button missing")
	}
}

func TestSecretDetailEmptyAttachments(t *testing.T) {
	rd := newTestRenderer(t)
	rec := httptest.NewRecorder()
	rd.Frag(rec, "secretDetail", secretDetailView{ID: "S1", Name: "K"})
	if !strings.Contains(rec.Body.String(), "No files attached") {
		t.Error("empty-state hint missing")
	}
}

func TestSanitizeFilenameStripsPathAndControls(t *testing.T) {
	cases := map[string]string{
		"../../etc/passwd":        "passwd",
		`C:\Users\me\secret.kdbx`: "secret.kdbx",
		"clean name.txt":          "clean name.txt",
		"with\nnewline.txt":       "withnewline.txt",
		"":                        "attachment",
		"..":                      "attachment",
	}
	for in, want := range cases {
		if got := sanitizeFilename(in); got != want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

// A filename carrying a quote or CRLF must never break out of the
// Content-Disposition header (header injection / response splitting).
func TestContentDispositionIsInjectionSafe(t *testing.T) {
	evil := "in\"jee\r\nSet-Cookie: x=1\".txt"
	h := contentDisposition(evil)

	if strings.ContainsAny(h, "\r\n") {
		t.Fatalf("header contains a raw CR/LF: %q", h)
	}
	if !strings.HasPrefix(h, "attachment;") {
		t.Fatalf("must force download disposition: %q", h)
	}
	// The quoted ASCII fallback must contain exactly the two delimiter quotes and
	// no embedded quote that could terminate it early.
	if strings.Count(h, `"`) != 2 {
		t.Fatalf("embedded quote not stripped from fallback: %q", h)
	}
	// The RFC 5987 form must percent-encode the CR and LF rather than emit them raw.
	if !strings.Contains(h, "filename*=UTF-8''") || !strings.Contains(h, "%0D%0A") {
		t.Fatalf("RFC 5987 filename* missing or unescaped: %q", h)
	}
}

func TestContentDispositionUnicode(t *testing.T) {
	h := contentDisposition("rézumé €.pdf")
	if !strings.Contains(h, "filename*=UTF-8''r%C3%A9zum%C3%A9%20%E2%82%AC.pdf") {
		t.Fatalf("unexpected RFC 5987 encoding: %q", h)
	}
}
