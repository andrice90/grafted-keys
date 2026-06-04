// Package assets embeds the web UI (templates and static files) into the binary
// so the container needs no extra files at runtime.
package assets

import "embed"

//go:embed templates static
var Files embed.FS
