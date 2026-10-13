package helps

import "bytes"

// CodexImageCarryCut consumes leftmost-longest, nonoverlapping identifier matches.
// Only an unresolved prefix at the next unmatched offset is retained. Its length
// is strictly less than a needle's length, so carry is bounded by maxLen-1.
func CodexImageCarryCut(pending []byte, needles [][]byte) int {
	for offset := 0; offset < len(pending); {
		remaining := pending[offset:]
		longest := 0
		for _, needle := range needles {
			if len(needle) == 0 || needle[0] != remaining[0] {
				continue
			}
			if len(remaining) < len(needle) {
				if bytes.HasPrefix(needle, remaining) {
					// A longer match may arrive in the next read, even when a
					// shorter needle already matches at this same offset.
					return offset
				}
			} else if len(needle) > longest && bytes.HasPrefix(remaining, needle) {
				longest = len(needle)
			}
		}
		if longest == 0 {
			longest = 1
		}
		offset += longest
	}
	return len(pending)
}
