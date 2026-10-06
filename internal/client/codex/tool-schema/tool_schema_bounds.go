package toolschema

import (
	"context"
	"fmt"
	"net/http"

	"github.com/tidwall/gjson"
)

const (
	maxDeclarationDepth          = 16
	maxToolSchemaNodes           = 4096
	maxAdditionalToolGroups      = 256
	maxToolSchemaBytes           = 4 << 20
	maxToolSchemaWork            = 16 << 20
	maxNormalizationRequestBytes = 32 << 20
)

type toolSchemaLimitError struct{ limit string }

func (e *toolSchemaLimitError) Error() string {
	return fmt.Sprintf("codex tool schema exceeds %s limit", e.limit)
}
func (e *toolSchemaLimitError) StatusCode() int { return http.StatusBadRequest }

type toolSchemaBudget struct {
	ctx                        context.Context
	nodes, groups, bytes, work int
}

func normalizationContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// ValidateCodexToolIntegerTypes bounds all declaration work before any schema
// mutation. The dispatch boundary also uses it before translators/executors run.
// Budgets are shared by top-level tools and every additional_tools group.
func ValidateCodexToolIntegerTypes(ctx context.Context, body []byte, headers http.Header) error {
	if len(body) == 0 || !IsCodexUserAgent(headers) {
		return nil
	}
	ctx = normalizationContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(body) > maxNormalizationRequestBytes {
		return &toolSchemaLimitError{"request bytes"}
	}
	b := toolSchemaBudget{ctx: ctx}
	root := gjson.ParseBytes(body)
	if err := b.array(root.Get("tools"), 0, ""); err != nil {
		return err
	}
	var err error
	input := root.Get("input")
	if input.IsArray() {
		input.ForEach(func(_, item gjson.Result) bool {
			if err = b.node(); err != nil {
				return false
			}
			if item.Get("type").String() != "additional_tools" {
				return true
			}
			b.bytes += len(item.Raw)
			b.work += len(item.Raw)
			if b.bytes > maxToolSchemaBytes {
				err = &toolSchemaLimitError{"aggregate group bytes"}
				return false
			}
			if b.work > maxToolSchemaWork {
				err = &toolSchemaLimitError{"aggregate work"}
				return false
			}
			b.groups++
			if b.groups > maxAdditionalToolGroups {
				err = &toolSchemaLimitError{"additional_tools groups"}
				return false
			}
			err = b.array(item.Get("tools"), 0, "")
			return err == nil
		})
	}
	if err != nil {
		return err
	}
	return ctx.Err()
}

func (b *toolSchemaBudget) node() error {
	if err := b.ctx.Err(); err != nil {
		return err
	}
	b.nodes++
	if b.nodes > maxToolSchemaNodes {
		return &toolSchemaLimitError{"aggregate nodes"}
	}
	return nil
}

func (b *toolSchemaBudget) array(tools gjson.Result, depth int, namespace string) error {
	if err := b.ctx.Err(); err != nil {
		return err
	}
	if !tools.IsArray() {
		return nil
	}
	if depth > maxDeclarationDepth {
		return &toolSchemaLimitError{"declaration depth"}
	}
	b.work += len(tools.Raw)
	if b.work > maxToolSchemaWork {
		return &toolSchemaLimitError{"aggregate work"}
	}
	var err error
	tools.ForEach(func(_, tool gjson.Result) bool {
		if err = b.node(); err != nil {
			return false
		}
		b.bytes += len(tool.Raw)
		// Charge the fixed field/path probes before executing them. Targeted
		// schemas additionally scan/copy parameters for each known field.
		b.work += 8 * len(tool.Raw)
		if b.bytes > maxToolSchemaBytes {
			err = &toolSchemaLimitError{"aggregate tool bytes"}
			return false
		}
		if b.work > maxToolSchemaWork {
			err = &toolSchemaLimitError{"aggregate work"}
			return false
		}
		// Match normalization's single namespace level; nested namespaces are ignored.
		if tool.Get("type").String() == "namespace" {
			if namespace != "" {
				return true
			}
			name := tool.Get("name").String()
			if name != "" {
				err = b.array(tool.Get("tools"), depth, name)
			}
			return err == nil
		}
		for _, key := range []string{"function_declarations", "functionDeclarations"} {
			declarations := tool.Get(key)
			if declarations.IsArray() {
				err = b.array(declarations, depth+1, namespace)
				return err == nil
			}
		}
		name := tool.Get("name").String()
		if name == "" {
			name = tool.Get("function.name").String()
		}
		if namespace != "" {
			name = namespace + "__" + name
		}
		b.work += 3 * len(matchCodexTargetTool(name)) * len(tool.Raw)
		if b.work > maxToolSchemaWork {
			err = &toolSchemaLimitError{"aggregate work"}
			return false
		}
		return true
	})
	return err
}
