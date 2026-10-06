package toolschema

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// cancelOnCheck uses real context cancellation at a deterministic work boundary.
// It avoids timing-dependent disconnect tests or sleeps under -race.
type security70CheckContext struct {
	context.Context
	cancel           context.CancelFunc
	checks, cancelAt int
}

func (c *security70CheckContext) Err() error {
	c.checks++
	if c.cancelAt > 0 && c.checks == c.cancelAt {
		c.cancel()
	}
	return c.Context.Err()
}

func TestSecurity70NormalizationContext(t *testing.T) {
	headers := http.Header{"User-Agent": []string{"codex"}}
	input := []byte(`{"input":[` + strings.TrimSuffix(strings.Repeat(`{"type":"additional_tools","tools":[`+security70Tool+`]},`, 128), ",") + `]}`)
	probe := &security70CheckContext{Context: context.Background()}
	if err := ValidateCodexToolIntegerTypes(probe, input, headers); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checked := &security70CheckContext{Context: ctx, cancel: cancel, cancelAt: probe.checks + 12}
	out, err := NormalizeCodexToolIntegerTypesContext(checked, input, headers)
	if !errors.Is(err, context.Canceled) || out != nil {
		t.Fatalf("cancellation during normalization not honored: out=%d err=%v", len(out), err)
	}
	if checked.checks != checked.cancelAt {
		t.Fatalf("continued work after cancellation: checks=%d cancelAt=%d", checked.checks, checked.cancelAt)
	}
	ctx, cancelEarly := context.WithCancel(context.Background())
	cancelEarly()
	if _, err = NormalizeCodexToolIntegerTypesContext(ctx, input, headers); !errors.Is(err, context.Canceled) {
		t.Fatalf("early cancellation ignored: %v", err)
	}
}

func TestSecurity70NormalDeclarationsUnchanged(t *testing.T) {
	headers := http.Header{"User-Agent": []string{"codex"}}
	plain := []byte(`{"tools":[{"name":"custom","parameters":{"properties":{"duration_ms":{"type":"number"}}}}],"input":"untouched"}`)
	out, err := NormalizeCodexToolIntegerTypesContext(context.Background(), plain, headers)
	if err != nil || !bytes.Equal(out, plain) {
		t.Fatalf("non-target tool changed: %s %v", out, err)
	}
	deep := security70Tool
	for i := 0; i < maxDeclarationDepth; i++ {
		deep = `{"functionDeclarations":[` + deep + `]}`
	}
	body := []byte(`{"tools":[` + deep + `]}`)
	want := bytes.ReplaceAll(body, []byte(`"number"`), []byte(`"integer"`))
	out, err = NormalizeCodexToolIntegerTypesContext(context.Background(), body, headers)
	if err != nil || !bytes.Equal(out, want) {
		t.Fatalf("normal depth boundary changed: %s %v", out, err)
	}
	for _, count := range []int{1, 128, maxAdditionalToolGroups} {
		group := ` {"type":"additional_tools","extra":{"type":"number"},"tools":[` + security70Tool + `]} `
		input := []byte("{\"input\":[\n{\"type\":\"message\",\"content\":\"untouched\"}," + strings.TrimSuffix(strings.Repeat(group+",", count), ",") + "\n],\"other\":{\"type\":\"number\"}}")
		expected := bytes.ReplaceAll(input, []byte(security70Tool), []byte(strings.ReplaceAll(security70Tool, `"number"`, `"integer"`)))
		out, err = NormalizeCodexToolIntegerTypesContext(context.Background(), input, headers)
		if err != nil || !bytes.Equal(out, expected) {
			t.Fatalf("%d groups: raw unrelated input changed: %v", count, err)
		}
	}
}

func TestSecurity70SharedGroupBudget(t *testing.T) {
	headers := http.Header{"User-Agent": []string{"codex"}}
	group := `{"type":"additional_tools","padding":"` + strings.Repeat("x", (maxToolSchemaBytes/2)+1) + `","tools":[` + security70Tool + `]}`
	body := []byte(`{"input":[` + group + `,` + group + `]}`)
	_, err := NormalizeCodexToolIntegerTypesContext(context.Background(), body, headers)
	status, ok := err.(interface{ StatusCode() int })
	if !ok || status.StatusCode() != 400 || !strings.Contains(err.Error(), "aggregate group bytes") {
		t.Fatalf("aggregate group bytes not bounded: %v", err)
	}
}

func TestSecurity70SharedWorkBudget(t *testing.T) {
	headers := http.Header{"User-Agent": []string{"codex"}}
	tool := strings.Replace(security70Tool, `"name":`, `"padding":"`+strings.Repeat("x", 1<<20)+`","name":`, 1)
	single := []byte(`{"tools":[` + tool + `]}`)
	if _, err := NormalizeCodexToolIntegerTypesContext(context.Background(), single, headers); err != nil {
		t.Fatalf("single schema should fit work budget: %v", err)
	}
	body := []byte(`{"tools":[` + tool + `,` + tool + `]}`)
	_, err := NormalizeCodexToolIntegerTypesContext(context.Background(), body, headers)
	status, ok := err.(interface{ StatusCode() int })
	if !ok || status.StatusCode() != 400 || !strings.Contains(err.Error(), "aggregate work") {
		t.Fatalf("shared projected work not bounded: %v", err)
	}
}
