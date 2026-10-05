package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	core "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// These regressions use only public APIs present at the reviewed base.
func TestCompactionProtocolAdmissionOrdinaryToolApplicationData(t *testing.T) {
	origin := NewSessionAffinitySelector(nil)
	defer origin.Stop()
	manager := NewManager(nil, origin, nil)
	jobs := "[" + strings.TrimSuffix(strings.Repeat(`{"type":"compaction"},`, 257), ",") + "]"
	for _, tc := range []struct {
		name   string
		format sdktranslator.Format
		input  string
		output string
	}{
		{"messages", sdktranslator.FormatClaude,
			`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"tool-1","name":"jobs","input":{"jobs":` + jobs + `}}]}]}`,
			`{"content":[{"type":"tool_use","id":"tool-1","name":"jobs","input":{"jobs":` + jobs + `}}]}`},
		{"responses", sdktranslator.FormatOpenAIResponse,
			`{"input":[{"type":"function_call_output","call_id":"tool-1","output":{"jobs":` + jobs + `}}]}`,
			`{"output":[{"type":"function_call","call_id":"tool-1","name":"jobs","arguments":{"jobs":` + jobs + `}}]}`},
	} {
		t.Run(tc.name+"/input", func(t *testing.T) {
			opts, err := manager.PrepareCompactionRequest("model", core.Options{SourceFormat: tc.format, OriginalRequest: []byte(tc.input)}, context.Background())
			if err != nil {
				t.Fatalf("ordinary tool input rejected: %v", err)
			}
			if pin, _ := opts.Metadata[core.PinnedAuthMetadataKey].(string); pin != "" {
				t.Fatalf("application data produced a signer pin: %q", pin)
			}
		})
		t.Run(tc.name+"/output", func(t *testing.T) {
			if err := manager.RecordCompactionOutput("A", core.Options{SourceFormat: tc.format}, []byte(tc.output)); err != nil {
				t.Fatalf("ordinary tool output rejected: %v", err)
			}
		})
	}
}

func TestCompactionProtocolAdmissionGenuineCapsuleBounds(t *testing.T) {
	origin := NewSessionAffinitySelector(nil)
	defer origin.Stop()
	manager := NewManager(nil, origin, nil)
	block := `{"type":"compaction","encrypted_content":"round2-genuine"}`
	if err := manager.RecordCompactionOutput("A", core.Options{}, []byte(`{"output":[`+block+`]}`)); err != nil {
		t.Fatal(err)
	}
	blocks := func(n int) string {
		return strings.TrimSuffix(strings.Repeat(block+",", n), ",")
	}
	inputs := []struct{ name, payload string }{
		{"input", `{"input":[` + blocks(257) + `]}`},
		{"messages", `{"messages":[{"content":[` + blocks(257) + `]}]}`},
		{"shared-input-messages", `{"input":[` + blocks(128) + `],"messages":[{"content":[` + blocks(129) + `]}]}`},
	}
	for _, tc := range inputs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := manager.PrepareCompactionRequest("model", core.Options{OriginalRequest: []byte(tc.payload)}, context.Background())
			requireRound2ProtocolJSONRejection(t, err)
			if !IsLocalCompactionAffinityStop(err) {
				t.Fatal("input bound rejection lost local stop marker")
			}
			prepared, err := manager.PrepareCompactionRequest("model", core.Options{}, context.Background())
			if err != nil {
				t.Fatal(err)
			}
			validate := prepared.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
			requireRound2ProtocolJSONRejection(t, validate("A", []byte(tc.payload)))
		})
	}
	t.Run("256-repeated-input-allowed", func(t *testing.T) {
		opts, err := manager.PrepareCompactionRequest("model", core.Options{OriginalRequest: []byte(`{"input":[` + blocks(256) + `]}`)}, context.Background())
		if err != nil || opts.Metadata[core.PinnedAuthMetadataKey] != "A" {
			t.Fatalf("valid bounded repeated replay: pin=%v err=%v", opts.Metadata[core.PinnedAuthMetadataKey], err)
		}
	})
	outputs := []struct{ name, payload string }{
		{"output", `{"output":[` + blocks(257) + `]}`},
		{"response-output", `{"response":{"output":[` + blocks(257) + `]}}`},
		{"native-content", `{"content":[` + blocks(257) + `]}`},
		{"shared-output-content", `{"output":[` + blocks(128) + `],"content":[` + blocks(129) + `]}`},
		{"event-item", `{"type":"response.output_item.done","output":[` + blocks(256) + `],"item":` + block + `}`},
		{"event-native-block", `{"type":"content_block_start","content":[` + blocks(256) + `],"content_block":` + block + `}`},
	}
	for _, tc := range outputs {
		t.Run(tc.name, func(t *testing.T) {
			requireRound2ProtocolJSONRejection(t, manager.RecordCompactionOutput("A", core.Options{}, []byte(tc.payload)))
		})
	}
	t.Run("256-repeated-output-allowed", func(t *testing.T) {
		if err := manager.RecordCompactionOutput("A", core.Options{}, []byte(`{"output":[`+blocks(256)+`]}`)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCompactionProtocolAdmissionDeclaredMultipartOnly(t *testing.T) {
	origin := NewSessionAffinitySelector(nil)
	defer origin.Stop()
	manager := NewManager(nil, origin, nil)
	const boundary = "round2-boundary"
	multipartBody := []byte("--" + boundary + "\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\nedit\r\n--" + boundary + "--\r\n")
	for _, stream := range []bool{false, true} {
		if _, err := manager.PrepareCompactionRequest("model", core.Options{
			Stream: stream, SourceFormat: sdktranslator.FromString("openai-image"), OriginalRequest: multipartBody,
			Headers: http.Header{"Content-Type": {"multipart/form-data; boundary=" + boundary}},
		}, context.Background()); err != nil {
			t.Fatalf("declared multipart rejected: %v", err)
		}
	}
	for _, format := range []sdktranslator.Format{sdktranslator.FormatClaude, sdktranslator.FormatOpenAIResponse, sdktranslator.FromString("openai-image"), ""} {
		for _, contentType := range []string{"", "application/json", "multipart/form-data", "multipart/form-data; boundary=" + boundary, "multipart/form-data; boundary=\"broken"} {
			for _, body := range []string{`{"input":`, `{"input":[],"\u0069nput":[]}`, `{"messages":[{"content":[{"type":"tool_use","input":{"jobs":[{"type":"compaction","type":"compaction"}]}}]}]}`} {
				_, err := manager.PrepareCompactionRequest("model", core.Options{SourceFormat: format, OriginalRequest: []byte(body), Headers: http.Header{"Content-Type": {contentType}}}, context.Background())
				requireRound2ProtocolJSONRejection(t, err)
			}
		}
		if format.String() != "openai-image" {
			_, err := manager.PrepareCompactionRequest("model", core.Options{SourceFormat: format, OriginalRequest: multipartBody, Headers: http.Header{"Content-Type": {"multipart/form-data; boundary=" + boundary}}}, context.Background())
			requireRound2ProtocolJSONRejection(t, err)
		}
	}
	prepared, err := manager.PrepareCompactionRequest("model", core.Options{SourceFormat: sdktranslator.FromString("openai-image"), OriginalRequest: multipartBody, Headers: http.Header{"Content-Type": {"multipart/form-data; boundary=" + boundary}}}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	validate := prepared.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
	for _, output := range []string{`{"content":`, `{"output":[],"\u006futput":[]}`, `{"content":[{"type":"tool_use","input":{"jobs":[{"type":"compaction","type":"compaction"}]}}]}`} {
		requireRound2ProtocolJSONRejection(t, manager.RecordCompactionOutput("A", core.Options{}, []byte(output)))
	}
	requireRound2ProtocolJSONRejection(t, validate("A", []byte(`{"input":[],"input":[]}`)))
	requireRound2ProtocolJSONRejection(t, validate("A", multipartBody))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = manager.PrepareCompactionRequest("model", core.Options{SourceFormat: sdktranslator.FromString("openai-image"), OriginalRequest: multipartBody, Headers: http.Header{"Content-Type": {"multipart/form-data; boundary=" + boundary}}}, ctx)
	requireRound2ProtocolJSONRejection(t, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("multipart bypass lost cancellation: %v", err)
	}
}

func requireRound2ProtocolJSONRejection(t *testing.T, err error) {
	t.Helper()
	var local *Error
	if !errors.As(err, &local) || local.Code != "compaction_json_rejected" || local.StatusCode() != http.StatusBadRequest {
		t.Fatalf("error=%v, want typed compaction_json_rejected (400)", err)
	}
}
