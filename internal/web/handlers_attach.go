package web

import (
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/andrew/grafted-secrets/internal/auth"
	"github.com/andrew/grafted-secrets/internal/crypto"
	"github.com/andrew/grafted-secrets/internal/vault"
)

// maxAttachmentBytes caps a single uploaded file. The whole payload is held in
// RAM while it is encrypted (and again, transiently, while decrypted on
// download), so the cap is deliberately well under the container mem_limit.
const maxAttachmentBytes = 5 << 20 // 5 MiB

// attachListView drives the per-key attachment list fragment.
type attachListView struct {
	SecretID string
	Items    []vault.AttachmentMeta
}

type attachFormView struct {
	SecretID string
	MaxMB    int
}

// attachForm: the upload dialog for a key.
func (s *Server) attachForm(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	s.rd.Frag(w, "attachForm", attachFormView{SecretID: r.PathValue("id"), MaxMB: maxAttachmentBytes >> 20})
}

// uploadAttachment ingests one file (size-capped, CSRF-checked by middleware,
// vault-unlocked), encrypts its name and bytes under the DEK, and returns the
// refreshed attachment list.
func (s *Server) uploadAttachment(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	secretID := r.PathValue("id")

	// Bound the whole request body before touching it: a hard backstop against an
	// oversized upload buffering to memory/disk. Slack covers multipart framing.
	r.Body = http.MaxBytesReader(w, r.Body, maxAttachmentBytes+(1<<20))

	file, hdr, err := r.FormFile("file")
	if err != nil {
		s.renderAttachList(w, dek, secretID)
		return
	}
	defer file.Close()

	// Read at most cap+1 bytes so we can distinguish "exactly at the cap" from
	// "over the cap" without trusting the multipart-declared length.
	data, err := io.ReadAll(io.LimitReader(file, maxAttachmentBytes+1))
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(data) == 0 || len(data) > maxAttachmentBytes {
		// Empty or too large: no-op, just re-render the current list.
		s.renderAttachList(w, dek, secretID)
		return
	}

	name := sanitizeFilename(hdr.Filename)
	if _, err := s.vault.AddAttachment(dek, secretID, name, data); err != nil {
		s.fail(w, err)
		return
	}
	s.renderAttachList(w, dek, secretID)
}

// downloadAttachment decrypts one attachment and streams it as a forced download.
// It is always served as application/octet-stream with an attachment disposition
// so the browser can never render stored content inline in the app's origin
// (defeats stored-XSS / content-sniffing via uploaded HTML/SVG/etc.); the global
// middleware already adds nosniff, same-origin CORP, and Cache-Control: no-store
// so the decrypted bytes are not cached to disk.
func (s *Server) downloadAttachment(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	att, err := s.vault.AttachmentData(dek, r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer crypto.Zero(att.Data) // scrub the plaintext copy once written

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", contentDisposition(att.Name))
	w.Header().Set("Content-Length", strconv.Itoa(len(att.Data)))
	w.Header().Set("Cache-Control", "no-store")
	w.Write(att.Data)
}

func (s *Server) deleteAttachment(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	id := r.PathValue("id")
	secretID, err := s.vault.AttachmentSecret(id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.vault.DeleteAttachment(id); err != nil {
		s.fail(w, err)
		return
	}
	s.renderAttachList(w, dek, secretID)
}

// renderAttachList re-renders a key's attachment list fragment.
func (s *Server) renderAttachList(w http.ResponseWriter, dek []byte, secretID string) {
	items, err := s.vault.Attachments(dek, secretID)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.rd.Frag(w, "attachList", attachListView{SecretID: secretID, Items: items})
}

// sanitizeFilename reduces an uploaded filename to a safe display/download name:
// strips any path component, drops control characters, and bounds the length.
func sanitizeFilename(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, `\`, "/")) // defeat path components (incl. Windows)
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		name = "attachment"
	}
	if len(name) > 200 {
		name = name[:200]
	}
	return name
}

// contentDisposition builds an injection-safe Content-Disposition header that
// forces a download. It emits a sanitized ASCII quoted-string fallback plus an
// RFC 5987 filename* for full-fidelity UTF-8, never letting a quote, backslash,
// or CR/LF from the filename break out of the header.
func contentDisposition(name string) string {
	var ascii strings.Builder
	for _, r := range name {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' || r > 0x7e {
			continue
		}
		ascii.WriteRune(r)
	}
	fallback := strings.TrimSpace(ascii.String())
	if fallback == "" {
		fallback = "attachment"
	}
	return `attachment; filename="` + fallback + `"; filename*=UTF-8''` + rfc5987Escape(name)
}

// rfc5987Escape percent-encodes a string per RFC 5987 attr-char, operating on
// raw UTF-8 bytes so the result is a valid `UTF-8”` value.
func rfc5987Escape(s string) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			strings.IndexByte("!#$&+-.^_`|~", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperhex[c>>4])
		b.WriteByte(upperhex[c&0x0f])
	}
	return b.String()
}
