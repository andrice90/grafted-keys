# Grafted Secrets - Design & Threat Model

A minimal, security-hardened, self-hostable secrets manager + backup service.
Single static Go binary, embedded assets, SQLite, zero-knowledge encryption.

## Goals & non-goals

**Goals**
- Tiny image (~10–20 MB) and low idle RAM (~10–15 MB).
- Zero-knowledge: server stores only ciphertext; the encryption key is derived
  from the user's master passphrase and lives only in RAM while unlocked.
- Single-user, secure-by-default, safe to expose behind a reverse proxy.
- Clean, dense, mobile-first UI: centered, rounded, pills, cards, grids, dark/light.
- Minimum code, clearly modular, easy to edit later.

**Non-goals**
- Multi-user / RBAC, SSO, secret sharing, audit log streaming.
- Protection against a fully-compromised running host while the vault is unlocked
  (the data key is necessarily in RAM then - same as every secrets manager).
- Recovery if the master passphrase is lost (zero-knowledge ⇒ unrecoverable).

## Hierarchy & data model

```
Project ─┬─ Environment ─┬─ Folder ─┬─ Secret { name, value, notes(markdown) }
         │  (dev/stg/prod)│ (category)│
```

All user-entered text (project/env/folder/secret names, secret values, notes) is
stored as **ciphertext BLOBs**. Only structural IDs, foreign keys, sort order and
timestamps are plaintext. Search runs in memory after unlock.

SQLite tables (pure-Go `modernc.org/sqlite`, CGO-free → static binary):
- `vault`  - single row: kdf params, salt, wrapped DEK (+nonce), totp (enc), flags.
- `projects(id, name_enc, sort, created_at, updated_at)`
- `environments(id, project_id, name_enc, sort, …)`
- `folders(id, environment_id, name_enc, sort, …)`
- `secrets(id, folder_id, name_enc, value_enc, notes_enc, sort, …)`

Pragmas: `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`,
`synchronous=NORMAL`. Cascade deletes via FKs.

## Cryptography (zero-knowledge)

Primitives: **Argon2id** (KDF) + **AES-256-GCM** (AEAD). Stdlib + `x/crypto`.

**Setup (first run)**
1. User chooses a master passphrase.
2. `salt = rand(16)`; `KEK = Argon2id(passphrase, salt, t,m,p)` (params stored).
3. `DEK = rand(32)` (the long-lived data key).
4. `wrappedDEK = AES-GCM(key=KEK, nonce=rand(12), DEK)`.
5. Persist: salt, argon params, wrappedDEK, nonce. The passphrase/KEK/DEK are
   **never** written to disk.

**Unlock (login)**
1. `KEK = Argon2id(passphrase, salt, params)`.
2. `DEK = AES-GCM-Open(KEK, wrappedDEK)` - GCM auth tag failure ⇒ wrong passphrase.
3. If TOTP enabled: decrypt totp secret with DEK, verify code; else discard DEK.
4. On success, DEK is held in the in-memory session (keyed by session id).

**Field encryption** - every field: `nonce(12) || ciphertext || tag`, key = DEK,
fresh random nonce per write. Helpers `Seal(DEK, plaintext)` / `Open(DEK, blob)`.

**Passphrase change** - re-derive KEK from new passphrase (new salt), re-wrap the
*same* DEK. No bulk re-encryption. TOTP secret unaffected.

**Why key-wrapping** - decouples passphrase from data: cheap passphrase rotation,
single DEK to protect, and unlock = a single GCM open (fast, authenticated).

## Authentication & sessions

- The master passphrase **is** the login (zero-knowledge). Optional TOTP (RFC 6238,
  HMAC-SHA1, 30s/6-digit) as a 2nd factor; secret stored encrypted under DEK.
- **Sessions**: server-side, in-memory map `sessionID → {DEK, csrfToken, created,
  lastSeen}`. Opaque 32-byte random id in cookie. No DEK ever leaves the server.
- **Cookie**: `__Host-gs_session`, `HttpOnly`, `Secure` (toggle for plain-HTTP LAN),
  `SameSite=Lax`, `Path=/`.
- **Auto-lock**: idle timeout (default 30m) clears the session + DEK. Server restart
  ⇒ locked (DEK only in RAM). Explicit "Lock" button.
- **CSRF**: synchronizer token per session; injected as `<meta>` + sent on every
  mutating htmx request via `hx-headers` → validated (constant-time compare).
- **Login throttling**: per-IP + global limiter with lockout after N failures and
  backoff; Argon2id already makes guessing expensive.

## HTTP hardening

- Strict CSP: `default-src 'none'; script-src 'self'; style-src 'self'; img-src
  'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none';
  base-uri 'none'`. No inline/eval, no external origins (everything vendored).
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY`, minimal `Permissions-Policy`, optional HSTS (TLS only).
- Cache-Control `no-store` on dynamic responses; long immutable cache on hashed
  static assets.
- Generic auth errors (no user enumeration / timing oracles - constant-time compares).
- Reverse-proxy aware: trust `X-Forwarded-For` only when `GRAFTED_TRUST_PROXY=1`.

## Frontend (no build step, fully offline)

- Go `html/template`: `layout.html` scaffold composes partials (`_tree`, `_card`,
  `_secret_form`, `_search_results`, …).
- **htmx** (vendored, pinned) for partial updates: live search, inline add/edit,
  reveal, delete - CSP-safe (no eval).
- **Tiny vanilla `app.js`** (no Alpine): theme toggle + persistence, copy-to-clipboard,
  reveal/hide value, expand notes, modal open/close. Keeps `script-src 'self'`.
- **Markdown notes**: rendered server-side with `goldmark`, sanitized with
  `bluemonday` (UGC policy) → no client md lib, no stored-XSS.
- **CSS**: one hand-authored `app.css` with design tokens (`--bg`, `--card`,
  `--accent`, radii, spacing). Light/dark via `prefers-color-scheme` + `data-theme`
  override. Aesthetic: centered max-width container, rounded cards, pill badges,
  responsive grid. Bespoke mobile: single column, bottom action bar, big touch
  targets, collapsible tree, sticky search.

## Backup service

- Goroutine scheduler: daily at `GRAFTED_BACKUP_AT` (HH:MM) or every
  `GRAFTED_BACKUP_INTERVAL`. Snapshot via `VACUUM INTO '/backups/grafted-<ts>.db'`
  (consistent copy; already ciphertext at rest ⇒ backup is encrypted).
- Retention: keep newest `GRAFTED_BACKUP_KEEP` (default 14), prune older.
- Runs even while locked (no DEK needed - it copies ciphertext).
- Restore: stop, replace `grafted.db`, start, unlock with the same passphrase.
- Manual "Backup now" button triggers the same path.

## Modules

```
cmd/grafted/main.go          entrypoint: config → store → vault → web → backup
internal/config              env config + defaults
internal/crypto              Argon2id, AES-GCM, DEK wrap/unwrap, Seal/Open, TOTP
internal/store               sqlite open, migrations, pragmas, CRUD (ciphertext)
internal/vault               setup/unlock/lock, decrypt models, in-memory search
internal/auth                session store (DEK custody), csrf, login rate-limit
internal/web                 router (stdlib mux), middleware, handlers, render+md
internal/backup              scheduler, VACUUM INTO snapshot, prune
web/templates, web/static    embedded UI (templates, css, js, vendored htmx)
```

Routing: Go 1.22+ `http.ServeMux` method+pattern routes - no router dependency.

## Dependencies (intentionally few, all pure-Go)
`modernc.org/sqlite`, `golang.org/x/crypto`, `github.com/yuin/goldmark`,
`github.com/microcosm-cc/bluemonday`. TOTP hand-rolled (RFC 6238).

## Configuration (env)
`GRAFTED_ADDR=:8080`, `GRAFTED_DATA_DIR=/data`, `GRAFTED_BACKUP_DIR=/backups`,
`GRAFTED_BACKUP_AT=03:00`, `GRAFTED_BACKUP_KEEP=14`, `GRAFTED_SESSION_IDLE=30m`,
`GRAFTED_SECURE_COOKIE=1`, `GRAFTED_TRUST_PROXY=0`, `GRAFTED_ARGON_MEM_MIB=64`,
`GRAFTED_ARGON_TIME=3`, `GRAFTED_ARGON_PAR=4`.

## Container hardening
distroless `static:nonroot` final stage, `CGO_ENABLED=0` static binary,
read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, non-root uid, named
volumes for `/data` and `/backups`, healthcheck on `/healthz`.

---

## Hardening decisions (post-critique addendum)

These supersede/clarify the sections above after the adversarial design review.

**Crypto**
- DEK wrap uses GCM **AAD** = `serialize(argon params) || vault epoch`, so any
  KDF-param tampering (downgrade) fails authentication instead of silently
  weakening derivation.
- Field encryption uses GCM **AAD** = `"<entity>/<id>/<field>"` to bind every
  ciphertext to its row+column (prevents record/column substitution & rollback).
  Rows therefore use app-generated random string IDs (known before insert).
- Argon2id **hard floors** enforced in code: `m ≥ 19 MiB, t ≥ 2, p ≥ 1`; defaults
  `m=64 MiB, t=3, p=min(4,NumCPU)`. Env can raise, never lower past the floor.
  (Unlock transiently spikes RAM by ~m MiB - accounted for in the mem_limit.)
- **Atomic setup** in one tx; the freshly-wrapped DEK is test-unwrapped before
  commit. An explicit `initialized` marker defines vault state. Setup is **refused
  if any encrypted data rows already exist** (prevents silent re-key/data-loss and
  vault-hijack); missing vault row + present data ⇒ "restore from backup" error.
- **TOTP is an online speed-bump, not cryptographic 2FA** (the passphrase alone
  decrypts at rest). Documented as such. DEK is *not* installed into the session
  until TOTP passes; key buffers are zeroized on failure. TOTP uses `pquerna/otp`
  with skew ±1; last-accepted step is recorded and earlier/equal steps rejected
  (replay/used-code), and attempts share the login rate-limiter.
- Key material is `[]byte` (never `string`), explicitly zeroized on lock/timeout
  and after wrap/unwrap. Swap-disclosure documented (recommend swapoff/encrypted
  swap; mlock left as future work).
- A **DEK-rotation** (rekey) operation re-encrypts all fields under a new DEK.

**Web/HTTP**
- Cookie name is conditional: `__Host-gs_session` only when `Secure` is set;
  `gs_session` (no prefix) in plain-HTTP LAN mode. Plain-HTTP is documented as
  trusted-LAN-only (loses prefix + SameSite guarantees).
- CSRF: **default-deny** synchronizer-token check on every non-GET in middleware;
  mutations never accept GET; plus `Origin`/`Referer` same-origin check and
  `HX-Request` presence as defense-in-depth.
- Session id: `crypto/rand` 32B base64url; **rotated on every unlock** (kills
  fixation) and on passphrase change; idle timeout **+ absolute max lifetime**.
- XFF: honored only when `TRUST_PROXY=1`, taking the **rightmost** entry (added by
  our trusted proxy) and only if `RemoteAddr` is the proxy. A strict **global**
  failure lockout cannot be bypassed by IP rotation.
- Markdown: goldmark **without** `WithUnsafe`; sanitize the rendered **output** with
  `bluemonday.UGCPolicy()` + `AllowURLSchemes(http,https,mailto)` + nofollow/noopener;
  no `<svg>/<object>/<embed>`. Regression tests assert XSS payloads are neutralized.
- CSP: `img-src 'self'` (no `data:`). htmx indicator CSS shipped in `app.css`; htmx
  configured via `<meta name="htmx-config" content='{"includeIndicatorStyles":false}'>`
  so `style-src 'self'` holds. Full security-header set + `Cache-Control: no-store`
  applied by one global middleware to **every** response (errors, partials, healthz);
  only hashed `/static/*` gets long immutable cache.
- HSTS off by default; enabled only via `GRAFTED_HSTS=1` (set only behind HTTPS).

**UX / a11y**
- Navigation: desktop = tree sidebar + content; mobile = **drill-down** with a
  persistent, tappable **breadcrumb** (Project / Env / Folder) for wayfinding; tree
  becomes a drawer. Bottom bar (Add / Search / Lock) respects `safe-area-inset`.
- **Reveal-on-demand**: list/search HTML never contains plaintext values; reveal
  does an htmx GET (`no-store`) to fetch the value, auto-re-masks on lock; reveal is
  an `aria-pressed` toggle. Copy uses `navigator.clipboard` with `execCommand`
  fallback (plain-HTTP has no secure-context clipboard) and announces via live region.
- Global search matches **names + notes only** (never values); each result shows the
  full breadcrumb path + highlighted match; debounced ~200 ms; explicit empty state.
- htmx: a visually-hidden `aria-live=polite` status region announces outcomes; focus
  is moved deliberately after swaps; a global `htmx:responseError` handler catches
  401/locked and shows a re-unlock dialog preserving in-progress input.
- Modals use native `<dialog>` (focus trap, Esc, backdrop, top-layer). Destructive
  deletes confirm with the cascade child counts; Confirm is not auto-focused.
- Tokens meet WCAG 1.4.3/1.4.11 (≥4.5:1 text, ≥3:1 UI) in **both** themes; env pills
  use outline+text. `:focus-visible` ring ≥3:1. `prefers-reduced-motion` honored.
  Theme is Light/Dark/System, persisted in a cookie and emitted server-side as
  `<html data-theme>` to avoid FOUC under the no-inline-script CSP.

**Arch**
- TOTP via `github.com/pquerna/otp` (no hand-rolled crypto). Migrations are numbered,
  embedded SQL applied in a tx, gated by `PRAGMA user_version`. Graceful shutdown
  (`http.Server.Shutdown` + stop scheduler). Session store guarded by `sync.RWMutex`.
