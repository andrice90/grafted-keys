package web

import (
	"io"
	"net/http"
	"strings"

	"github.com/andrew/grafted-secrets/internal/auth"
	"github.com/andrew/grafted-secrets/internal/vault"
)

type importFormView struct {
	Action      string
	Target      string
	ParentField string
	ParentID    string
	Hint        string
}

type envPair struct{ Key, Value string }

// parseEnv extracts KEY=VALUE pairs from a .env file. It skips blanks and
// comments, tolerates a leading "export", and strips matching surrounding quotes.
func parseEnv(content []byte) []envPair {
	var out []envPair
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		val := unquoteEnv(strings.TrimSpace(line[i+1:]))
		if key != "" {
			out = append(out, envPair{Key: key, Value: val})
		}
	}
	return out
}

func unquoteEnv(v string) string {
	if len(v) >= 2 {
		if v[0] == '"' && v[len(v)-1] == '"' {
			inner := v[1 : len(v)-1]
			inner = strings.ReplaceAll(inner, `\n`, "\n")
			return strings.ReplaceAll(inner, `\"`, `"`)
		}
		if v[0] == '\'' && v[len(v)-1] == '\'' {
			return v[1 : len(v)-1]
		}
	}
	return v
}

func (s *Server) importEnvForm(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	eid := r.PathValue("id")
	s.rd.Frag(w, "importForm", importFormView{
		Action: "/import", Target: "#secrets-env-" + eid, ParentField: "environment_id", ParentID: eid,
		Hint: "Keys are added as uncategorized secrets in this environment.",
	})
}

func (s *Server) importFolderForm(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	fid := r.PathValue("id")
	s.rd.Frag(w, "importForm", importFormView{
		Action: "/import", Target: "#secrets-folder-" + fid, ParentField: "folder_id", ParentID: fid,
		Hint: "Keys are added as secrets in this folder.",
	})
}

// importEnv parses an uploaded .env and creates a secret per key (skipping names
// that already exist in the target), returning the new nodes to append.
func (s *Server) importEnv(w http.ResponseWriter, r *http.Request, sess *auth.Session, dek []byte) {
	file, _, err := r.FormFile("envfile")
	if err != nil {
		s.fail(w, err)
		return
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, 1<<20)) // 1 MiB cap
	if err != nil {
		s.fail(w, err)
		return
	}
	fid := r.FormValue("folder_id")
	eid := r.FormValue("environment_id")

	// skip keys that already exist in the target
	existing := map[string]bool{}
	var metas []vault.SecretMeta
	if eid != "" {
		metas, _ = s.vault.EnvSecrets(dek, eid)
	} else {
		metas, _ = s.vault.Secrets(dek, fid)
	}
	for _, m := range metas {
		existing[m.Name] = true
	}

	var created []vault.SecretMeta
	for _, p := range parseEnv(content) {
		name := normalizeKey(p.Key)
		if name == "" || existing[name] {
			continue
		}
		existing[name] = true
		var id string
		var e error
		if eid != "" {
			id, e = s.vault.CreateEnvSecret(dek, eid, name, p.Value, "")
		} else {
			id, e = s.vault.CreateSecret(dek, fid, name, p.Value, "")
		}
		if e != nil {
			continue
		}
		created = append(created, vault.SecretMeta{ID: id, FolderID: fid, EnvironmentID: eid, Name: name})
	}
	s.rd.Frag(w, "secretNodes", created)
}
