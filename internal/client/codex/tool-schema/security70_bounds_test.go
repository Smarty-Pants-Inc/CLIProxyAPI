package toolschema

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const security70Tool = `{"name":"sleep","parameters":{"type":"object","properties":{"duration_ms":{"type":"number"}}}}`

func TestSecurity70NormalizationBudgets(t *testing.T) {
	headers := http.Header{"User-Agent": []string{"codex/1.0"}}
	deep := security70Tool
	for i := 0; i < 64; i++ {
		key := "function_declarations"
		if i%2 != 0 {
			key = "functionDeclarations"
		}
		deep = `{"` + key + `":[` + deep + `]}`
	}
	many := strings.TrimSuffix(strings.Repeat(security70Tool+",", 4097), ",")
	groups := strings.TrimSuffix(strings.Repeat(`{"type":"additional_tools","tools":[`+security70Tool+`]},`, 257), ",")
	workTool := strings.Replace(security70Tool, `"name":`, `"padding":"`+strings.Repeat("x", 1<<20)+`","name":`, 1)
	for _, tc := range []struct{ name, body string }{
		{"declaration-depth", `{"tools":[` + deep + `]}`},
		{"declaration-count", `{"tools":[{"function_declarations":[` + many + `]}]}`},
		{"additional-groups", `{"input":[` + groups + `]}`},
		{"tool-bytes", `{"tools":[{"name":"sleep","description":"` + strings.Repeat("x", (4<<20)+1) + `","parameters":{"properties":{"duration_ms":{"type":"number"}}}}]}`},
		{"aggregate-work", `{"tools":[` + workTool + `,` + workTool + `]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			got := NormalizeCodexToolIntegerTypes(body, headers)
			if !bytes.Equal(got, body) {
				t.Fatal("over-budget normalization processed untrusted declarations")
			}
		})
	}
}

func BenchmarkSecurity70AdditionalTools(b *testing.B) {
	headers := http.Header{"User-Agent": []string{"codex"}}
	for _, count := range []int{1, 32, 128, 256} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			body := []byte(`{"padding":"` + strings.Repeat("x", 1<<20) + `","input":[` + strings.TrimSuffix(strings.Repeat(`{"type":"additional_tools","tools":[`+security70Tool+`]},`, count), ",") + `]}`)
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				NormalizeCodexToolIntegerTypes(body, headers)
			}
		})
	}
}
