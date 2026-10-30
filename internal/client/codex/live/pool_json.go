package live

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// Unique keys are part of the supported pooled shape. Do not let this gateway's
// last-key-wins decoder authorize a control/model that an upstream first-key-wins
// decoder could interpret differently. Validation never rewrites wire bytes.
const maxPoolJSONDepth = 64

func validUniqueJSONObject(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') || !consumeUniqueJSONComposite(decoder, '{', 0) {
		return false
	}
	_, err = decoder.Token()
	return err == io.EOF
}

func consumeUniqueJSONValue(decoder *json.Decoder, depth int) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	if delim, composite := token.(json.Delim); composite {
		return consumeUniqueJSONComposite(decoder, delim, depth)
	}
	return true
}

func consumeUniqueJSONComposite(decoder *json.Decoder, open json.Delim, depth int) bool {
	if depth > maxPoolJSONDepth {
		return false
	}
	switch open {
	case '{':
		keys := make(map[string]bool)
		for decoder.More() {
			token, err := decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok || keys[key] {
				return false
			}
			keys[key] = true
			if !consumeUniqueJSONValue(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !consumeUniqueJSONValue(decoder, depth+1) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}
