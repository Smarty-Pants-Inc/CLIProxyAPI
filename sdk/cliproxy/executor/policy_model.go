package executor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// PolicyModel rejects ambiguous JSON and tools that can execute a second model.
func PolicyModel(body []byte) (string, error) {
	// F29: bounded whole-value validation first, then a depth-bounded duplicate walk.
	if !json.Valid(body) {
		return "", errDeepJSON
	}
	d := json.NewDecoder(bytes.NewReader(body))
	if err := uniqueJSON(d, 0); err != nil {
		return "", err
	}
	if _, err := d.Token(); err != io.EOF {
		return "", fmt.Errorf("trailing JSON")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return "", err
	}
	var model string
	if json.Unmarshal(fields["model"], &model) != nil || model == "" {
		return "", fmt.Errorf("missing model")
	}
	var tools []map[string]json.RawMessage
	if raw := fields["tools"]; len(raw) != 0 {
		if err := json.Unmarshal(raw, &tools); err != nil {
			return "", err
		}
	}
	for _, tool := range tools {
		var kind, name string
		_ = json.Unmarshal(tool["type"], &kind)
		_ = json.Unmarshal(tool["name"], &name)
		if kind == "image_generation" || name == "image_gen.imagegen" || (kind == "namespace" && name == "image_gen") {
			return "", fmt.Errorf("secondary-model tools are unavailable for policied keys")
		}
	}
	return model, nil
}

// maxPolicyJSONDepth bounds nesting in policied request bodies; real Responses
// bodies (including tool JSON schemas) stay far below it.
const maxPolicyJSONDepth = 512

var errDeepJSON = fmt.Errorf("invalid or too deeply nested JSON")

func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > maxPolicyJSONDepth {
		return errDeepJSON
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name := key.(string)
			if seen[name] {
				return fmt.Errorf("duplicate JSON field")
			}
			seen[name] = true
		}
		if err := uniqueJSON(d, depth+1); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}
