package responses

import (
	"bytes"
	"encoding/json"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestConvertOpenAIResponsesRequestToCodexReasoningStatusMixedHistory(t *testing.T) {
	inputJSON := []byte(`{
		"model":"gpt-5.6","stream":true,"store":false,"parallel_tool_calls":true,
		"include":["reasoning.encrypted_content"],"status":"queued",
		"metadata":{"status":"keep","large_number":9007199254740993},
		"tools":[{"type":"function","name":"shell","parameters":{"type":"object"}}],
		"input":[
			{"type":"reasoning","status":"completed","id":"rs_1","encrypted_content":"opaque\\sig\u003c","summary":[{"type":"summary_text","text":"plan","status":"nested"}],"extra":{"status":"keep"}},
			{ "type":"message", "role":"user", "status":"completed", "content":[{"type":"input_text","text":"hello"}] },
			{"type":"function_call","id":"fc_1","call_id":"call_1","name":"shell","arguments":"{\"cmd\":\"echo hi\"}","status":"completed"},
			{"type":"reasoning","id":"rs_2","status":null,"encrypted_content":"sig2","summary":[]},
			{"type":"function_call_output","call_id":"call_1","status":"completed","output":[{"type":"input_text","text":"hi","status":"nested"}]},
			{"type":"reasoning","id":"rs_3","encrypted_content":"sig3","summary":[]},
			{"type":"message","role":"assistant","status":"in_progress","content":[{"type":"output_text","text":"done"}]},
			{"type":"reasoning","id":"rs_4","status":false,"encrypted_content":"sig4","summary":[]},
			{"type":"reasoning","id":"rs_5","status":"","encrypted_content":"sig5","summary":[]},
			{"type":"reasoning","id":"rs_6","status":"in_progress","encrypted_content":"sig6","summary":[]},
			{"type":"reasoning","id":"rs_7","sta\u0074us":"completed","encrypted_content":"sig7","summary":[]}
		]
	}`)
	original := bytes.Clone(inputJSON)
	want := decodeReasoningStatusRequest(t, inputJSON)
	for _, index := range []int{0, 3, 7, 8, 9, 10} {
		delete(want["input"].([]any)[index].(map[string]any), "status")
	}

	for _, stream := range []bool{false, true} {
		output := ConvertOpenAIResponsesRequestToCodex("gpt-5.6", inputJSON, stream)
		if got := decodeReasoningStatusRequest(t, output); !reflect.DeepEqual(got, want) {
			t.Fatalf("stream=%v: only reasoning item status should change:\n got: %s\nwant: %#v", stream, output, want)
		}
		beforeItems := gjson.GetBytes(inputJSON, "input").Array()
		afterItems := gjson.GetBytes(output, "input").Array()
		for i, item := range beforeItems {
			if item.Get("type").String() == "reasoning" && item.Get("status").Exists() {
				if afterItems[i].Get("status").Exists() {
					t.Fatalf("input[%d] reasoning status was retained", i)
				}
				if got := afterItems[i].Get("encrypted_content").Raw; got != item.Get("encrypted_content").Raw {
					t.Fatalf("input[%d] encrypted content changed: %s != %s", i, got, item.Get("encrypted_content").Raw)
				}
			} else if afterItems[i].Raw != item.Raw {
				t.Fatalf("untouched input[%d] raw JSON changed:\n got: %s\nwant: %s", i, afterItems[i].Raw, item.Raw)
			}
		}
		if !bytes.Equal(inputJSON, original) {
			t.Fatal("conversion mutated the caller's input")
		}
		second := ConvertOpenAIResponsesRequestToCodex("gpt-5.6", output, stream)
		if !bytes.Equal(second, output) || &second[0] != &output[0] {
			t.Fatal("already-cleaned history should be returned unchanged without copying the request")
		}
	}
}

func TestConvertOpenAIResponsesRequestToCodexReasoningStatusEscapedKey(t *testing.T) {
	// No literal "status" key occurs in this request, so a byte-level shortcut
	// would miss the escaped key even though GJSON resolves it as status.
	request := []byte(`{"model":"gpt-5.6","stream":true,"store":false,"parallel_tool_calls":true,"include":["reasoning.encrypted_content"],"input":[{"type":"reasoning","id":"rs_1","sta\u0074us":"completed","encrypted_content":"sig","summary":[]}]}`)
	if bytes.Contains(request, []byte(`"status"`)) || !gjson.GetBytes(request, "input.0.status").Exists() {
		t.Fatal("fixture must contain only an escaped status key that GJSON resolves")
	}
	want := decodeReasoningStatusRequest(t, request)
	delete(want["input"].([]any)[0].(map[string]any), "status")
	output := ConvertOpenAIResponsesRequestToCodex("gpt-5.6", request, true)
	if got := decodeReasoningStatusRequest(t, output); !reflect.DeepEqual(got, want) {
		t.Fatalf("escaped reasoning status was not stripped without other changes: %s", output)
	}
}

func TestConvertOpenAIResponsesRequestToCodexReasoningStatusUnchanged(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		input string
	}{
		{name: "empty", input: `[]`},
		{name: "null", input: `null`},
		{name: "non-array", input: `{"type":"reasoning","status":"completed"}`},
		{name: "mixed-clean-history", input: `[{"type":"reasoning","id":"rs_1","summary":[{"status":"completed"}],"encrypted_content":"sig"},{"type":"message","role":"assistant","status":"completed","content":[]},{"type":"function_call","name":"shell","call_id":"call_1","status":"completed","arguments":"{}"}]`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := []byte(`{"model":"gpt-5.6","stream":true,"store":false,"parallel_tool_calls":true,"include":["reasoning.encrypted_content"],"status":"completed","input":` + testCase.input + `}`)
			output := ConvertOpenAIResponsesRequestToCodex("gpt-5.6", request, true)
			if !bytes.Equal(output, request) || &output[0] != &request[0] {
				t.Fatal("history without reasoning item status should retain the original request bytes and backing array")
			}
		})
	}
}

func TestConvertOpenAIResponsesRequestToCodexReasoningStatusAllocationScaling(t *testing.T) {
	// Every group adds reasoning, message, tool-call, and tool-result history.
	// Quadrupling history should approximately quadruple bytes allocated, not
	// multiply them by sixteen through per-reasoning whole-request rewrites.
	// Measure allocation bytes (not counts or elapsed time): quadratic copying
	// can still have only a linear number of allocations.
	small := makeReasoningStatusHistory(64)
	large := makeReasoningStatusHistory(256)
	for _, request := range [][]byte{small, large} {
		output := ConvertOpenAIResponsesRequestToCodex("gpt-5.6", request, true)
		items := gjson.GetBytes(output, "input").Array()
		if len(items) != len(gjson.GetBytes(request, "input").Array()) {
			t.Fatal("conversion dropped history items")
		}
		for i, item := range items {
			if item.Get("type").String() == "reasoning" {
				if item.Get("status").Exists() || item.Get("encrypted_content").String() != strings.Repeat("x", 512) {
					t.Fatalf("input[%d] reasoning status or encrypted content is incorrect", i)
				}
			} else if item.Get("status").String() != "completed" {
				t.Fatalf("input[%d] non-reasoning status changed", i)
			}
		}
	}

	smallBytes := reasoningStatusConversionBytesPerRun(small)
	largeBytes := reasoningStatusConversionBytesPerRun(large)
	t.Logf("small: %d request bytes, %d allocated bytes/op; large: %d request bytes, %d allocated bytes/op; allocation growth: %.2fx", len(small), smallBytes, len(large), largeBytes, float64(largeBytes)/float64(smallBytes))
	// Leave ample room for allocator size classes and linear parser overhead;
	// the previous implementation allocates hundreds of request copies here.
	if budget := uint64(len(large)) * 32; largeBytes > budget {
		t.Errorf("large history allocated %d bytes/op, exceeding linear budget %d (32x request size)", largeBytes, budget)
	}
	if largeBytes > smallBytes*8 {
		t.Errorf("4x history allocated %.2fx bytes; want at most 8x (linear with headroom, not quadratic)", float64(largeBytes)/float64(smallBytes))
	}
}

func decodeReasoningStatusRequest(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var result map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if errDecode := decoder.Decode(&result); errDecode != nil {
		t.Fatalf("decode request: %v", errDecode)
	}
	return result
}

func makeReasoningStatusHistory(groups int) []byte {
	var builder strings.Builder
	builder.Grow(groups * 1024)
	builder.WriteString(`{"model":"gpt-5.6","stream":true,"store":false,"parallel_tool_calls":true,"include":["reasoning.encrypted_content"],"input":[`)
	for i := 0; i < groups; i++ {
		if i > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(`{"type":"reasoning","status":"completed","id":"rs_`)
		builder.WriteString(strconv.Itoa(i))
		builder.WriteString(`","encrypted_content":"`)
		builder.WriteString(strings.Repeat("x", 512))
		builder.WriteString(`","summary":[]},{"type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"message"}]},{"type":"function_call","call_id":"call_`)
		builder.WriteString(strconv.Itoa(i))
		builder.WriteString(`","name":"shell","status":"completed","arguments":"{}"},{"type":"function_call_output","call_id":"call_`)
		builder.WriteString(strconv.Itoa(i))
		builder.WriteString(`","status":"completed","output":"tool result"}`)
	}
	builder.WriteString(`]}`)
	return []byte(builder.String())
}

func reasoningStatusConversionBytesPerRun(request []byte) uint64 {
	// Fixed repetitions keep this probe bounded even on the quadratic version.
	// Fixture construction, output checks, and logging stay outside the sample.
	// These tests deliberately do not run in parallel because MemStats is global.
	const runs = 3
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var output []byte
	for i := 0; i < runs; i++ {
		output = ConvertOpenAIResponsesRequestToCodex("gpt-5.6", request, true)
	}
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(output)
	return (after.TotalAlloc - before.TotalAlloc) / runs
}
