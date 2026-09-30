package common

import (
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	"github.com/tidwall/gjson"
)

// ClaudeToolNames is an immutable, request-local mapping between client tool
// names and Claude-compatible aliases. Responses rebuild it from the original
// request, so concurrent requests never share mutable name state.
type ClaudeToolNames struct {
	forward map[string]string
	reverse map[string]string
}

// NewClaudeToolNames assigns deterministic, collision-safe aliases to tool
// declarations and historical calls in Gemini and chat-completions requests.
func NewClaudeToolNames(rawJSON []byte) ClaudeToolNames {
	names := make(map[string]struct{})
	add := func(name string) {
		if name != "" {
			names[name] = struct{}{}
		}
	}
	root := gjson.ParseBytes(rawJSON)
	root.Get("tools").ForEach(func(_, tool gjson.Result) bool {
		if tool.Get("type").String() == "function" {
			add(tool.Get("function.name").String())
		}
		tool.Get("functionDeclarations").ForEach(func(_, declaration gjson.Result) bool {
			add(declaration.Get("name").String())
			return true
		})
		return true
	})
	root.Get("contents").ForEach(func(_, content gjson.Result) bool {
		content.Get("parts").ForEach(func(_, part gjson.Result) bool {
			add(part.Get("functionCall.name").String())
			return true
		})
		return true
	})
	root.Get("messages").ForEach(func(_, message gjson.Result) bool {
		message.Get("tool_calls").ForEach(func(_, call gjson.Result) bool {
			if call.Get("type").String() == "function" {
				add(call.Get("function.name").String())
			}
			return true
		})
		return true
	})
	if len(names) == 0 {
		return ClaudeToolNames{}
	}

	sorted := make([]string, 0, len(names))
	counts := make(map[string]int, len(names))
	for name := range names {
		sorted = append(sorted, name)
		counts[util.SanitizeClaudeFunctionName(name)]++
	}
	sort.Strings(sorted)
	result := ClaudeToolNames{forward: make(map[string]string, len(names)), reverse: make(map[string]string, len(names))}
	for _, name := range sorted {
		base := util.SanitizeClaudeFunctionName(name)
		alias := base
		// Preserve already-valid client names. Reserve every base before generating
		// suffixes, including bases not yet assigned, to avoid secondary collisions.
		if base != name && counts[base] > 1 {
			for attempt := 0; ; attempt++ {
				digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", name, attempt)))
				suffix := fmt.Sprintf("_%x", digest[:6])
				prefix := base
				if len(prefix) > 64-len(suffix) {
					prefix = prefix[:64-len(suffix)]
				}
				alias = prefix + suffix
				if _, reserved := counts[alias]; reserved {
					continue
				}
				if _, used := result.reverse[alias]; !used {
					break
				}
			}
		}
		result.forward[name] = alias
		result.reverse[alias] = name
	}
	return result
}

// ToClaude returns the assigned alias, or sanitizes an undeclared name.
func (names ClaudeToolNames) ToClaude(name string) string {
	if alias, ok := names.forward[name]; ok {
		return alias
	}
	return util.SanitizeClaudeFunctionName(name)
}

// FromClaude restores the exact client name. Unknown upstream names pass through.
func (names ClaudeToolNames) FromClaude(name string) string {
	if original, ok := names.reverse[name]; ok {
		return original
	}
	return name
}
