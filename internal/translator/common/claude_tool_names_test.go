package common_test

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	gemini "github.com/router-for-me/CLIProxyAPI/v8/internal/translator/claude/gemini"
	chat "github.com/router-for-me/CLIProxyAPI/v8/internal/translator/claude/openai/chat-completions"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/translator/common"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type claudeNameAdapter struct {
	name                      string
	request                   func(string, []byte, bool) []byte
	stream                    func(context.Context, string, []byte, []byte, []byte, *any) [][]byte
	nonstream                 func(context.Context, string, []byte, []byte, []byte, *any) []byte
	streamPath, nonstreamPath string
}

var claudeNameAdapters = []claudeNameAdapter{
	{"gemini", gemini.ConvertGeminiRequestToClaude, gemini.ConvertClaudeResponseToGemini, gemini.ConvertClaudeResponseToGeminiNonStream, "candidates.0.content.parts.0.functionCall", "candidates.0.content.parts"},
	{"chat", chat.ConvertOpenAIRequestToClaude, chat.ConvertClaudeResponseToOpenAI, chat.ConvertClaudeResponseToOpenAINonStream, "choices.0.delta.tool_calls.0", "choices.0.message.tool_calls"},
}

func claudeNameRequest(t *testing.T, format string, names []string) []byte {
	t.Helper()
	var tools, calls, results []any
	for i, name := range names {
		id := fmt.Sprintf("call_%d", i)
		if format == "gemini" {
			tools = append(tools, map[string]any{"name": name, "parameters": map[string]any{"type": "object"}})
			calls = append(calls, map[string]any{"functionCall": map[string]any{"name": name, "id": id, "args": map[string]any{"n": i}}})
			results = append(results, map[string]any{"functionResponse": map[string]any{"name": name, "id": id, "response": map[string]any{"result": "ok"}}})
		} else {
			tools = append(tools, map[string]any{"type": "function", "function": map[string]any{"name": name, "parameters": map[string]any{"type": "object"}}})
			calls = append(calls, map[string]any{"type": "function", "id": id, "function": map[string]any{"name": name, "arguments": fmt.Sprintf(`{"n":%d}`, i)}})
			results = append(results, map[string]any{"role": "tool", "tool_call_id": id, "content": "ok"})
		}
	}
	var request map[string]any
	if format == "gemini" {
		request = map[string]any{"tools": []any{map[string]any{"functionDeclarations": tools}}, "contents": []any{map[string]any{"role": "model", "parts": calls}, map[string]any{"role": "user", "parts": results}}, "toolConfig": map[string]any{"functionCallingConfig": map[string]any{"mode": "ANY", "allowedFunctionNames": []string{names[0]}}}}
	} else {
		messages := []any{map[string]any{"role": "assistant", "tool_calls": calls}}
		messages = append(messages, results...)
		request = map[string]any{"tools": tools, "messages": messages, "tool_choice": map[string]any{"type": "function", "function": map[string]any{"name": names[0]}}}
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func claudeNameEvents(t *testing.T, names []string) [][]byte {
	t.Helper()
	var events [][]byte
	for i, name := range names {
		raw, err := json.Marshal(map[string]any{"type": "content_block_start", "index": i, "content_block": map[string]any{"type": "tool_use", "id": fmt.Sprintf("call_%d", i), "name": name}})
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, append([]byte("data: "), raw...), []byte(fmt.Sprintf(`data: {"type":"content_block_delta","index":%d,"delta":{"type":"input_json_delta","partial_json":"{\"n\":%d}"}}`, i, i)), []byte(fmt.Sprintf(`data: {"type":"content_block_stop","index":%d}`, i)))
	}
	return events
}

func TestClaudeToolNamesReserveGeneratedAliases(t *testing.T) {
	for _, adapter := range claudeNameAdapters {
		t.Run(adapter.name, func(t *testing.T) {
			originals := []string{"get.weather", "get:weather"}
			first := common.NewClaudeToolNames(claudeNameRequest(t, adapter.name, originals))
			reserved := first.ToClaude(originals[0])
			originals = append(originals, reserved, originals[0])
			names := common.NewClaudeToolNames(claudeNameRequest(t, adapter.name, originals))
			if got := names.ToClaude(reserved); got != reserved {
				t.Fatalf("valid original changed: %q", got)
			}
			if got := names.ToClaude(originals[0]); got == reserved {
				t.Fatalf("generated alias collides with original %q", reserved)
			}
			used := map[string]string{}
			for _, original := range originals {
				alias := names.ToClaude(original)
				if previous, ok := used[alias]; ok && previous != original {
					t.Fatalf("secondary collision: %q", alias)
				}
				used[alias] = original
				if got := names.FromClaude(alias); got != original {
					t.Fatalf("restore %q=%q, want %q", alias, got, original)
				}
			}
		})
	}
}

func TestClaudeToolNameResponsesAreRequestLocal(t *testing.T) {
	for _, adapter := range claudeNameAdapters {
		t.Run(adapter.name, func(t *testing.T) {
			t.Parallel()
			requests := [][]byte{claudeNameRequest(t, adapter.name, []string{"get.weather"}), claudeNameRequest(t, adapter.name, []string{"get:weather"}), nil}
			expected := []string{"get.weather", "get:weather", "get_weather"}
			params := make([]any, len(requests))
			events := claudeNameEvents(t, []string{"get_weather"})
			for _, event := range events {
				for i, request := range requests {
					for _, out := range adapter.stream(context.Background(), "model", request, nil, event, &params[i]) {
						call := gjson.GetBytes(out, adapter.streamPath)
						if !call.Exists() {
							continue
						}
						path := "name"
						if adapter.name == "chat" {
							path = "function.name"
						}
						if got := call.Get(path).String(); got != expected[i] {
							t.Errorf("request %d restored %q, want %q", i, got, expected[i])
						}
					}
				}
			}
			var lines []string
			for _, event := range events {
				lines = append(lines, string(event))
			}
			for i, request := range requests {
				out := adapter.nonstream(context.Background(), "model", request, nil, []byte(strings.Join(lines, "\n")), nil)
				path := "candidates.0.content.parts.0.functionCall.name"
				if adapter.name == "chat" {
					path = "choices.0.message.tool_calls.0.function.name"
				}
				if got := gjson.GetBytes(out, path).String(); got != expected[i] {
					t.Errorf("nonstream request %d restored %q, want %q", i, got, expected[i])
				}
			}
			names := common.NewClaudeToolNames(requests[0])
			if got := names.FromClaude("unknown_tool"); got != "unknown_tool" {
				t.Errorf("unknown name changed: %q", got)
			}
			historyOnly, err := sjson.DeleteBytes(requests[0], "tools")
			if err != nil {
				t.Fatal(err)
			}
			if got := common.NewClaudeToolNames(historyOnly).FromClaude("get_weather"); got != expected[0] {
				t.Errorf("history-only restore=%q", got)
			}
		})
	}
}

func TestClaudeAllowedToolsUsesExactOriginalNames(t *testing.T) {
	original := claudeNameRequest(t, "chat", []string{"get.weather", "get_weather"})
	original, err := sjson.SetRawBytes(original, "tool_choice", []byte(`{"type":"allowed_tools","allowed_tools":{"mode":"required","tools":[{"type":"function","function":{"name":"get.weather"}}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	translated := chat.ConvertOpenAIRequestToClaude("model", original, false)
	declarations := gjson.GetBytes(translated, "tools").Array()
	if len(declarations) != 1 {
		t.Fatalf("allowed subset broadened by collision: %s", translated)
	}
	names := common.NewClaudeToolNames(original)
	if got := declarations[0].Get("name").String(); got != names.ToClaude("get.weather") {
		t.Fatalf("allowed alias=%q", got)
	}
	if got := gjson.GetBytes(translated, "tool_choice.type").String(); got != "any" {
		t.Fatalf("allowed mode=%q", got)
	}
}

func TestClaudeToolNameRoundTrip(t *testing.T) {
	validName := regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
	cases := []struct {
		name  string
		names []string
	}{
		{"dotted", []string{"get.weather"}},
		{"punctuation_collision", []string{"get.weather", "get:weather", "get_weather"}},
		{"slash_collision", []string{"get/weather", "get@weather", "get_weather"}},
		{"truncation_collision", []string{strings.Repeat("x", 64) + "a", strings.Repeat("x", 64) + "b"}},
		{"valid", []string{"get_weather", "get-weather"}},
	}
	for _, adapter := range claudeNameAdapters {
		for _, tc := range cases {
			t.Run(adapter.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				original := claudeNameRequest(t, adapter.name, tc.names)
				translated := adapter.request("claude-test", original, true)
				declarations := gjson.GetBytes(translated, "tools").Array()
				if len(declarations) != len(tc.names) {
					t.Fatalf("declarations=%s", translated)
				}
				aliases := make([]string, len(tc.names))
				seen := map[string]string{}
				for i, declaration := range declarations {
					aliases[i] = declaration.Get("name").String()
					if !validName.MatchString(aliases[i]) {
						t.Errorf("invalid Claude alias %q", aliases[i])
					}
					if prev, exists := seen[aliases[i]]; exists && prev != tc.names[i] {
						t.Errorf("collision: %q and %q share %q", prev, tc.names[i], aliases[i])
					}
					seen[aliases[i]] = tc.names[i]
				}
				if tc.name == "dotted" && aliases[0] != "get_weather" {
					t.Errorf("dotted alias=%q, want get_weather", aliases[0])
				}
				if got := gjson.GetBytes(translated, "tool_choice.name").String(); got != aliases[0] {
					t.Errorf("tool choice=%q, want %q", got, aliases[0])
				}
				var historyNames []string
				gjson.GetBytes(translated, "messages").ForEach(func(_, message gjson.Result) bool {
					message.Get("content").ForEach(func(_, block gjson.Result) bool {
						if block.Get("type").String() == "tool_use" {
							historyNames = append(historyNames, block.Get("name").String())
						}
						return true
					})
					return true
				})
				if strings.Join(historyNames, "\x00") != strings.Join(aliases, "\x00") {
					t.Errorf("historical names=%v, aliases=%v", historyNames, aliases)
				}
				events := claudeNameEvents(t, aliases)
				for _, stream := range []bool{true, false} {
					mode := "nonstream"
					if stream {
						mode = "stream"
					}
					t.Run(mode, func(t *testing.T) {
						var calls []gjson.Result
						if stream {
							var param any
							for _, event := range events {
								for _, out := range adapter.stream(context.Background(), "model", original, translated, event, &param) {
									if call := gjson.GetBytes(out, adapter.streamPath); call.Exists() {
										calls = append(calls, call)
									}
								}
							}
						} else {
							var lines []string
							for _, event := range events {
								lines = append(lines, string(event))
							}
							out := adapter.nonstream(context.Background(), "model", original, translated, []byte(strings.Join(lines, "\n")), nil)
							for _, part := range gjson.GetBytes(out, adapter.nonstreamPath).Array() {
								if adapter.name == "gemini" {
									part = part.Get("functionCall")
								}
								if part.Exists() {
									calls = append(calls, part)
								}
							}
						}
						if len(calls) != len(tc.names) {
							t.Fatalf("calls=%v, want %d", calls, len(tc.names))
						}
						for i, call := range calls {
							name := call.Get("name").String()
							args := call.Get("args")
							if adapter.name == "chat" {
								name = call.Get("function.name").String()
								args = gjson.Parse(call.Get("function.arguments").String())
							}
							if name != tc.names[i] {
								t.Errorf("name[%d]=%q, want %q", i, name, tc.names[i])
							}
							if call.Get("id").String() != fmt.Sprintf("call_%d", i) || args.Get("n").Int() != int64(i) {
								t.Errorf("ID/args changed: %s", call.Raw)
							}
						}
					})
				}
				reversed := append([]string(nil), tc.names...)
				for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
					reversed[i], reversed[j] = reversed[j], reversed[i]
				}
				reverseRequest := adapter.request("model", claudeNameRequest(t, adapter.name, reversed), false)
				for i, declaration := range gjson.GetBytes(reverseRequest, "tools").Array() {
					if got := declaration.Get("name").String(); got != aliases[len(aliases)-1-i] {
						t.Errorf("alias changed with declaration order: %q", got)
					}
				}
			})
		}
	}
}
