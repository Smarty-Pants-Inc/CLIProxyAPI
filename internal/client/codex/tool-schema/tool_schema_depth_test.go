package toolschema

import (
	"net/http"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// Deeply nested namespaces are left untouched at the local limit; real
// one-level namespaces are still normalized.
func TestNormalizeCodexToolIntegerTypesBoundsNesting(t *testing.T) {
	headers := http.Header{"User-Agent": []string{"codex_cli_rs/1.0"}}
	leaf := `{"type":"function","name":"sleep","parameters":{"type":"object","properties":{"duration_ms":{"type":"number"}}}}`
	nest := func(depth int) string {
		return `{"tools":[` + strings.Repeat(`{"type":"namespace","name":"n","tools":[`, depth) + leaf + strings.Repeat(`]}`, depth) + `]}`
	}
	shallow := NormalizeCodexToolIntegerTypes([]byte(nest(1)), headers)
	if got := gjson.GetBytes(shallow, "tools.0.tools.0.parameters.properties.duration_ms.type").String(); got != "integer" {
		t.Fatalf("one-level namespace not normalized: %s", shallow)
	}
	deep := []byte(nest(2000))
	if out := NormalizeCodexToolIntegerTypes(deep, headers); string(out) != string(deep) {
		t.Fatal("namespace nesting beyond the local limit was traversed and rewritten")
	}
}
