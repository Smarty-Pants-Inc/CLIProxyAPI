package helps

import "bytes"

// ObserveStreamUsageChunkLines observes nonempty CR/LF-delimited fragments in a
// transport chunk, without accumulating lines across chunks. Empty fragments
// (including the LF half of a CRLF split across reads) cannot add observations.
func ObserveStreamUsageChunkLines(chunk []byte, observe func([]byte)) {
	for _, line := range bytes.FieldsFunc(chunk, func(r rune) bool { return r == '\r' || r == '\n' }) {
		if line = bytes.TrimSpace(line); len(line) > 0 {
			observe(line)
		}
	}
}
