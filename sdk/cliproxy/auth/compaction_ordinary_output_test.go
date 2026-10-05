package auth

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestRecordCompactionOutputOrdinarySuccess(t *testing.T) {
	for name, payload := range map[string]string{
		"auth-id":    "ordinary-auth-A",
		"ok":         "ok",
		"empty":      "",
		"whitespace": " \t\r\n",
		"object":     `{"output":[{"type":"message","content":"ok"}]}`,
		"array":      `[]`,
		"done":       " \t[DONE]\n",
	} {
		t.Run(name, func(t *testing.T) {
			selector := NewSessionAffinitySelector(nil)
			defer selector.Stop()
			_, opts := compactionAffinityRequest("model", "Session-Id", false, true)
			opts.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey] = "ordinary"
			opts.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey] = "model"
			wire := []byte(payload)
			before := bytes.Clone(wire)
			if err := selector.RecordCompactionOutput("A", opts, wire); err != nil {
				t.Fatalf("ordinary success rejected: %v", err)
			}
			if !bytes.Equal(wire, before) {
				t.Fatal("ordinary output bytes changed")
			}
			selector.cache.mu.RLock()
			entries := len(selector.cache.entries)
			selector.cache.mu.RUnlock()
			if entries != 0 {
				t.Fatalf("ordinary output registered %d aliases, want zero", entries)
			}
		})
	}
}

func TestRecordCompactionOutputJSONShapeRemainsStrict(t *testing.T) {
	block := `{"type":"compaction","encrypted_content":"ordinary-test-signed"}`
	for name, payload := range map[string]string{
		"malformed-signed":   " \n" + `{"output":[` + block + `]`,
		"duplicate-type":     `{"output":[{"type":"message","type":"compaction","encrypted_content":"ordinary-test-signed"}]}`,
		"escaped-duplicate":  `{"output":[{"type":"message","\u0074ype":"compaction","encrypted_content":"ordinary-test-signed"}]}`,
		"duplicate-unknown":  `{"output":[` + block + `],"unknown":1,"unknown":2}`,
		"duplicate-output":   `{"output":[],"output":[` + block + `]}`,
		"malformed-array":    " \t[" + block + ",]",
		"ordinary-duplicate": `{"unknown":1,"unknown":2}`,
		"too-many-blocks":    `{"output":[` + strings.Repeat(block+",", maxCompactionBlocks) + block + `]}`,
		"too-many-bytes":     `{"output":[` + block + `],"padding":"` + strings.Repeat("x", maxCompactionJSONBytes) + `"}`,
		"too-deep":           `{"output":[` + block + `],"padding":` + strings.Repeat("[", maxCompactionJSONDepth+1) + "0" + strings.Repeat("]", maxCompactionJSONDepth+1) + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			selector := NewSessionAffinitySelector(nil)
			defer selector.Stop()
			err := selector.RecordCompactionOutput("A", cliproxyexecutor.Options{}, []byte(payload))
			var local *Error
			if !errors.As(err, &local) || local.Code != "compaction_json_rejected" {
				t.Fatalf("JSON-shaped output error = %v, want strict JSON rejection", err)
			}
			selector.cache.mu.RLock()
			entries := len(selector.cache.entries)
			selector.cache.mu.RUnlock()
			if entries != 0 {
				t.Fatalf("rejected output registered %d aliases, want zero", entries)
			}
		})
	}
}

func TestRecordCompactionOutputEscapedTypesRegisterSigner(t *testing.T) {
	for name, payload := range map[string]string{
		"escaped-key":   " \n" + `{"output":[{"\u0074ype":"compaction","encrypted_content":"ordinary-test-signed"}]}`,
		"escaped-value": `{"output":[{"type":"\u0063ompaction","encrypted_content":"ordinary-test-signed"}]}`,
		"escaped-event": `{"\u0074ype":"response.output_item.done","item":{"type":"compaction","encrypted_content":"ordinary-test-signed"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			selector := NewSessionAffinitySelector(nil)
			defer selector.Stop()
			want := compactionOutputKeys([]byte(`{"output":[{"type":"compaction","encrypted_content":"ordinary-test-signed"}]}`))
			if len(want) != 1 {
				t.Fatalf("canonical signer keys = %v, want one", want)
			}
			if err := selector.RecordCompactionOutput("A", cliproxyexecutor.Options{}, []byte(payload)); err != nil {
				t.Fatal(err)
			}
			if id, ok := selector.cache.Get(want[0]); !ok || id != "A" || !selector.cache.IsProtected(want[0]) {
				t.Fatalf("escaped signer not protected: id=%q found=%v", id, ok)
			}
		})
	}
}

func TestRecordCompactionOutputOrdinaryCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opts := cliproxyexecutor.Options{Metadata: map[string]any{compactionRequestContextMetadataKey: ctx}}
	for _, payload := range []string{"ordinary-auth-A", "ok", "", " \t\n", "[DONE]", `{"output":[]}`} {
		t.Run(payload, func(t *testing.T) {
			selector := NewSessionAffinitySelector(nil)
			defer selector.Stop()
			err := selector.RecordCompactionOutput("A", opts, []byte(payload))
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled output error = %v, want cancellation cause", err)
			}
			selector.cache.mu.RLock()
			entries := len(selector.cache.entries)
			selector.cache.mu.RUnlock()
			if entries != 0 {
				t.Fatalf("canceled output registered %d aliases, want zero", entries)
			}
		})
	}
}
