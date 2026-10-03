package responses

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	"github.com/tidwall/gjson"
)

var claudeToolNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// claudeToolNames maps qualified Responses tool identities to unique Claude
// tool names for one request, and back. The request and response translators
// build it from the same Responses JSON, so both sides agree.
type claudeToolNames struct {
	toClaude   map[string]string
	fromClaude map[string]string
}

func buildClaudeToolNames(root gjson.Result) claudeToolNames {
	return buildClaudeToolNamesWithWinners(root, responsesToolWinners(root))
}

func buildClaudeToolNamesWithWinners(root gjson.Result, winners map[string]responsesToolDescriptor) claudeToolNames {
	m := claudeToolNames{toClaude: map[string]string{}, fromClaude: map[string]string{}}
	taken := map[string]bool{}
	var declared []string
	for _, d := range responsesToolDescriptors(root) {
		if w, ok := winners[d.name]; !ok || w.order != d.order {
			continue
		}
		switch d.toolType {
		case "function", "custom":
			declared = append(declared, d.name)
		default:
			m.assign(d.name, d.name, taken)
		}
	}
	m.allocate(declared, taken)
	m.allocate(responsesHistoryToolIdentities(root), taken)
	return m
}

// claudeName returns the Claude name for a qualified Responses identity.
func (m claudeToolNames) claudeName(identity string) string {
	if name, ok := m.toClaude[identity]; ok {
		return name
	}
	return util.SanitizeClaudeFunctionName(identity)
}

// identity returns the qualified Responses identity for a Claude name.
// Unknown names are returned unchanged.
func (m claudeToolNames) identity(claudeName string) string {
	if identity, ok := m.fromClaude[claudeName]; ok {
		return identity
	}
	return claudeName
}

func (m claudeToolNames) assign(identity, name string, taken map[string]bool) {
	m.toClaude[identity] = name
	m.fromClaude[name] = identity
	taken[name] = true
}

func (m claudeToolNames) allocate(identities []string, taken map[string]bool) {
	var changed []string
	seen := map[string]bool{}
	for _, id := range identities {
		if _, done := m.toClaude[id]; done || id == "" || seen[id] {
			continue
		}
		seen[id] = true
		if claudeToolNamePattern.MatchString(id) && !taken[id] {
			m.assign(id, id, taken)
			continue
		}
		changed = append(changed, id)
	}
	count := map[string]int{}
	for _, id := range changed {
		count[util.SanitizeClaudeFunctionName(id)]++
	}
	var hashed []string
	for _, id := range changed {
		if base := util.SanitizeClaudeFunctionName(id); count[base] == 1 && !taken[base] {
			m.assign(id, base, taken)
		} else {
			hashed = append(hashed, id)
		}
	}
	sort.Strings(hashed)
	for _, id := range hashed {
		base := util.SanitizeClaudeFunctionName(id)
		if len(base) > 53 {
			base = base[:53]
		}
		for n := 0; ; n++ {
			seed := id
			if n > 0 {
				seed += "\x00" + strconv.Itoa(n)
			}
			sum := sha256.Sum256([]byte(seed))
			if name := base + "_" + hex.EncodeToString(sum[:])[:10]; !taken[name] {
				m.assign(id, name, taken)
				break
			}
		}
	}
}

// BuildClaudeCompatToolNames reuses the Responses collision-safe allocator for
// Gemini and Chat declarations, history and explicit choices. The original
// request is the sole request-local source for both translation directions.
func BuildClaudeCompatToolNames(raw []byte) claudeToolNames {
	root := gjson.ParseBytes(raw)
	var declared, history []string
	for _, tool := range root.Get("tools").Array() {
		if name := tool.Get("function.name").String(); name != "" {
			declared = append(declared, name)
		}
		for _, d := range tool.Get("functionDeclarations").Array() {
			declared = append(declared, d.Get("name").String())
		}
	}
	for _, message := range root.Get("messages").Array() {
		for _, call := range message.Get("tool_calls").Array() {
			history = append(history, call.Get("function.name").String())
		}
	}
	for _, content := range root.Get("contents").Array() {
		for _, part := range content.Get("parts").Array() {
			for _, key := range []string{"functionCall.name", "functionResponse.name"} {
				if name := part.Get(key).String(); name != "" {
					history = append(history, name)
				}
			}
		}
	}
	for _, key := range []string{"tool_choice.function.name", "tool_choice.name"} {
		if name := root.Get(key).String(); name != "" {
			history = append(history, name)
		}
	}
	for _, key := range []string{"toolConfig.functionCallingConfig.allowedFunctionNames", "toolConfig.function_calling_config.allowed_function_names", "toolConfig.functionCallingConfig.allowed_function_names", "toolConfig.function_calling_config.allowedFunctionNames"} {
		for _, name := range root.Get(key).Array() {
			history = append(history, name.String())
		}
	}
	m := claudeToolNames{toClaude: map[string]string{}, fromClaude: map[string]string{}}
	taken := map[string]bool{}
	m.allocate(declared, taken)
	m.allocate(history, taken)
	return m
}

func (m claudeToolNames) ClaudeName(identity string) string { return m.claudeName(identity) }
func (m claudeToolNames) Identity(name string) string       { return m.identity(name) }

// responsesHistoryToolIdentities lists qualified names of function_call and
// custom_tool_call items in input, in order.
func responsesHistoryToolIdentities(root gjson.Result) []string {
	var ids []string
	input := root.Get("input")
	if input.Exists() && input.IsArray() {
		input.ForEach(func(_, item gjson.Result) bool {
			switch item.Get("type").String() {
			case "function_call", "custom_tool_call":
				name := item.Get("name").String()
				if ns := strings.TrimSpace(item.Get("namespace").String()); ns != "" {
					name = qualifyResponsesNamespaceToolName(ns, name)
				}
				if name != "" {
					ids = append(ids, name)
				}
			}
			return true
		})
	}
	return ids
}
