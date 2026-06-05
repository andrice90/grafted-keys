package web

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

// Renderer holds the parsed template sets and the markdown pipeline.
type Renderer struct {
	pages  map[string]*template.Template // each = layout + partials + one page
	base   *template.Template            // layout + partials (for fragments)
	md     goldmark.Markdown
	policy *bluemonday.Policy
}

func NewRenderer(assets fs.FS) (*Renderer, error) {
	policy := bluemonday.UGCPolicy()
	policy.AllowURLSchemes("http", "https", "mailto")
	policy.RequireNoFollowOnLinks(true)
	policy.AddTargetBlankToFullyQualifiedLinks(true)

	rd := &Renderer{
		md:     goldmark.New(goldmark.WithExtensions(extension.GFM)), // no WithUnsafe: raw HTML stays escaped
		policy: policy,
	}
	funcs := template.FuncMap{
		"highlight": highlight,
		"markdown":  rd.Markdown,
		"valueCtl":  valueCtl,
		"dict":      dict,
		"breakable": breakable,
	}

	base, err := template.New("").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/partials/*.html")
	if err != nil {
		return nil, err
	}
	rd.base = base

	pagePaths, err := fs.Glob(assets, "templates/pages/*.html")
	if err != nil {
		return nil, err
	}
	rd.pages = make(map[string]*template.Template, len(pagePaths))
	for _, p := range pagePaths {
		t, err := template.Must(base.Clone()).ParseFS(assets, p)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		name := strings.TrimSuffix(filepath.Base(p), ".html")
		rd.pages[name] = t
	}
	return rd, nil
}

// Page renders a full page, or just its "content" block for htmx swaps.
func (rd *Renderer) Page(w http.ResponseWriter, r *http.Request, page string, data any) {
	t, ok := rd.pages[page]
	if !ok {
		http.Error(w, "unknown page: "+page, http.StatusInternalServerError)
		return
	}
	block := "layout"
	if isHTMX(r) {
		block = "content"
	}
	rd.exec(w, t, block, data)
}

// Frag renders a named partial/fragment from the base set.
func (rd *Renderer) Frag(w http.ResponseWriter, name string, data any) {
	rd.exec(w, rd.base, name, data)
}

// exec renders to a buffer first so a template error never yields a half-written
// (and possibly secret-leaking) response.
func (rd *Renderer) exec(w http.ResponseWriter, t *template.Template, name string, data any) {
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// Markdown converts user markdown to sanitized HTML (goldmark output is the input
// to bluemonday - sanitize the rendered HTML, never the raw markdown).
func (rd *Renderer) Markdown(src string) template.HTML {
	var buf bytes.Buffer
	if err := rd.md.Convert([]byte(src), &buf); err != nil {
		return ""
	}
	return template.HTML(rd.policy.SanitizeBytes(buf.Bytes()))
}

func isHTMX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// dict builds a map from alternating key/value template args.
func dict(kv ...any) map[string]any {
	m := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			m[k] = kv[i+1]
		}
	}
	return m
}

// breakable escapes name and inserts <wbr> soft-wrap hints after separator
// characters so long names wrap at segment boundaries instead of mid-word
// (e.g. UPPER_SNAKE_CASE keys break after each underscore). <wbr> adds no
// characters to the text, so copied or selected names are unaffected; a single
// over-long segment still falls back to a character break via CSS overflow-wrap.
func breakable(name string) template.HTML {
	var b strings.Builder
	for _, r := range name {
		b.WriteString(template.HTMLEscapeString(string(r)))
		switch r {
		case '_', '-', '.', '/', ':':
			b.WriteString("<wbr>")
		}
	}
	return template.HTML(b.String())
}

// highlight escapes text and wraps case-insensitive matches of q in <mark>.
// Matching is done on the original string (via regexp) so byte indices always
// align - case folding that changes byte length can never cause a slice panic.
func highlight(text, q string) template.HTML {
	q = strings.TrimSpace(q)
	if q == "" {
		return template.HTML(template.HTMLEscapeString(text))
	}
	re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(q))
	if err != nil {
		return template.HTML(template.HTMLEscapeString(text))
	}
	var b strings.Builder
	last := 0
	for _, m := range re.FindAllStringIndex(text, -1) {
		b.WriteString(template.HTMLEscapeString(text[last:m[0]]))
		b.WriteString("<mark>")
		b.WriteString(template.HTMLEscapeString(text[m[0]:m[1]]))
		b.WriteString("</mark>")
		last = m[1]
	}
	b.WriteString(template.HTMLEscapeString(text[last:]))
	return template.HTML(b.String())
}
