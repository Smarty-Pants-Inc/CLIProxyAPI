package executor

import (
	"net/http"
	"runtime"
	"strings"
	"testing"

	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// Many shallow input[].additional_tools groups on the native Claude route with
// a Codex User-Agent: numeric normalization must rewrite the request once, not
// once per group (O(groups x body), round-4 security finding 3).
func TestRound4WideShallowAdditionalToolsNormalizedOnce(t *testing.T) {
	const groups = 3000
	group := `{"type":"additional_tools","tools":[{"type":"function","name":"sleep","parameters":{"type":"object","properties":{"duration_ms":{"type":"number"}}}}]}`
	source := `{"model":"claude-opus-5-5","max_tokens":64,"messages":[{"role":"user","content":"hi"}],"input":[` + strings.TrimSuffix(strings.Repeat(group+",", groups), ",") + `]}`
	req := core.Request{Model: "claude-opus-5-5", Payload: []byte(source)}
	opts := core.Options{SourceFormat: translator.FormatClaude, ResponseFormat: translator.FormatClaude, OriginalRequest: []byte(source), Headers: http.Header{"User-Agent": {"codex_cli_rs/0.50.0"}}}

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	body := round3Run(t, "claude", req, opts)
	runtime.ReadMemStats(&after)

	if got := strings.Count(string(body), `"duration_ms":{"type":"integer"}`); got != groups {
		t.Fatalf("normalized groups = %d, want %d", got, groups)
	}
	// Linear work is a small multiple of the ~400 KiB body; per-group whole-body
	// rewrites allocate gigabytes.
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 256<<20 {
		t.Fatalf("request of %d KiB allocated %d MiB: whole-body work per group", len(source)>>10, alloc>>20)
	}
}
