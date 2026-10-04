package config

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// PrepareConfigPublication validates edited source bytes and replaces only a
// plaintext management-key scalar with the server parser's bcrypt representation.
// The caller must still compare against the version of its original snapshot.
func PrepareConfigPublication(data []byte) ([]byte, error) {
	cfg, err := ParseConfigBytes(data)
	if err != nil {
		return nil, err
	}
	var root yaml.Node
	if err = yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	var original Config
	if err = root.Decode(&original); err != nil {
		return nil, err
	}
	if original.RemoteManagement.SecretKey == cfg.RemoteManagement.SecretKey {
		return data, nil
	}
	management := publicationMapValue(root.Content[0], "remote-management")
	key := publicationMapValue(management, "secret-key")
	if key == nil {
		if cfg.RemoteManagement.SecretKey != "" {
			return nil, fmt.Errorf("management key must be an explicit scalar for publication")
		}
		return data, nil
	}
	if key.Kind != yaml.ScalarNode || key.Anchor != "" {
		return nil, fmt.Errorf("plaintext management key must be an unanchored scalar for publication")
	}
	start, end, err := publicationScalarRange(data, key, management.Style&yaml.FlowStyle != 0)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, len(data)+len(cfg.RemoteManagement.SecretKey))
	result = append(result, data[:start]...)
	result = append(result, cfg.RemoteManagement.SecretKey...)
	if key.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		// Keep the block header's comment and line ending byte-for-byte.
		headerEnd := bytes.IndexByte(data[start:], '\n')
		if headerEnd < 0 {
			return nil, fmt.Errorf("invalid management-key block header")
		}
		headerEnd += start + 1
		indicatorEnd := start + 1
		for indicatorEnd < headerEnd && strings.ContainsRune("+-123456789", rune(data[indicatorEnd])) {
			indicatorEnd++
		}
		result = append(result, data[indicatorEnd:headerEnd]...)
	}
	result = append(result, data[end:]...)
	// Fail closed if an unusual YAML scalar form cannot be rewritten safely.
	var rewritten Config
	if err = yaml.Unmarshal(result, &rewritten); err != nil || rewritten.RemoteManagement.SecretKey != cfg.RemoteManagement.SecretKey {
		return nil, fmt.Errorf("cannot preserve management-key scalar layout safely")
	}
	return result, nil
}

func publicationMapValue(node *yaml.Node, name string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == name {
			return node.Content[i+1]
		}
	}
	return nil
}

func publicationScalarRange(data []byte, node *yaml.Node, flow bool) (int, int, error) {
	start := 0
	for line := 1; line < node.Line; line++ {
		n := bytes.IndexByte(data[start:], '\n')
		if n < 0 {
			return 0, 0, fmt.Errorf("invalid management-key source position")
		}
		start += n + 1
	}
	// YAML columns count Unicode characters, not UTF-8 bytes.
	for column := 1; column < node.Column; column++ {
		if start >= len(data) {
			return 0, 0, fmt.Errorf("invalid management-key source column")
		}
		start++
		for start < len(data) && data[start]&0xc0 == 0x80 {
			start++
		}
	}
	if start >= len(data) || data[start] == '!' {
		return 0, 0, fmt.Errorf("explicitly tagged management keys cannot be rewritten safely")
	}
	if data[start] == '\'' || data[start] == '"' {
		quote := data[start]
		for end := start + 1; end < len(data); end++ {
			if quote == '"' && data[end] == '\\' {
				end++
				continue
			}
			if data[end] == quote {
				if quote == '\'' && end+1 < len(data) && data[end+1] == quote {
					end++
					continue
				}
				return start, end + 1, nil
			}
		}
		return 0, 0, fmt.Errorf("unterminated management-key scalar")
	}
	if node.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		headerEnd := bytes.IndexByte(data[start:], '\n')
		if headerEnd < 0 {
			return 0, 0, fmt.Errorf("invalid management-key block header")
		}
		end := start + headerEnd + 1
		lineStart := bytes.LastIndexByte(data[:start], '\n') + 1
		parentIndent := 0
		for lineStart+parentIndent < start && data[lineStart+parentIndent] == ' ' {
			parentIndent++
		}
		contentIndent := 0
		for _, c := range data[start+1 : start+headerEnd] {
			if c >= '1' && c <= '9' {
				contentIndent = parentIndent + int(c-'0')
				break
			}
			if c == ' ' || c == '#' || c == '\r' {
				break
			}
		}
		for end < len(data) {
			next := bytes.IndexByte(data[end:], '\n')
			if next < 0 {
				next = len(data) - end
			}
			line := data[end : end+next]
			trimmed := bytes.TrimLeft(line, " ")
			if len(bytes.TrimSpace(trimmed)) != 0 {
				indent := len(line) - len(trimmed)
				if contentIndent == 0 {
					contentIndent = indent
				}
				if indent <= parentIndent || indent < contentIndent {
					break
				}
			}
			end += next
			if end < len(data) {
				end++
			}
		}
		return start, end, nil
	}
	end := start
	for end < len(data) {
		c := data[end]
		if c == '\n' || c == '\r' || (c == '#' && end > start && (data[end-1] == ' ' || data[end-1] == '\t')) || (flow && strings.ContainsRune(",]}", rune(c))) {
			break
		}
		end++
	}
	for end > start && (data[end-1] == ' ' || data[end-1] == '\t') {
		end--
	}
	// Multiline plain scalars are deliberately refused rather than leaving a
	// plaintext continuation on disk. Quoted multiline scalars are supported.
	var scalar string
	if err := yaml.Unmarshal(data[start:end], &scalar); err != nil || scalar != node.Value {
		return 0, 0, fmt.Errorf("use a quoted management key instead of a multiline plain scalar")
	}
	return start, end, nil
}
