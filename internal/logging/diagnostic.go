package logging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	diagnosticLogRuneLimit     = 300
	diagnosticLogScanRuneLimit = 600
	diagnosticDecodeRounds     = 2
)

var (
	accessTokenExpiredLogPattern  = regexp.MustCompile(`(?i)access token expired`)
	sensitiveLogAssignmentPattern = regexp.MustCompile(`(?i)(["']?(?:access[\s_-]*token|refresh[\s_-]*token|id[\s_-]*token|api[\s_-]*key|client[\s_-]*secret|private[\s_-]*key|proxy[\s_-]*authorization|authorization|password|credential|token|secret)["']?\s*[:=]\s*)(?:(?:bearer|basic)\s+[^\s,;]+|"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s,;&}\]]+)`)
	authorizationLogPattern       = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[^\s,;]+`)
	urlUserinfoLogPattern         = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+@`)
	diagnosticStatusPattern       = regexp.MustCompile(`(?i)\bstatus(?:\s+code)?\s*[:=]?\s*([1-5][0-9]{2})\b`)

	// Same identity and token shapes CLIProxyAPI#64 scrubs from client error frames
	// (sdk/api/handlers/openai scrubResponsesWebsocketErrorText); smarty-dev#5423.
	identityKeyLogPattern = regexp.MustCompile(`(?i)((?:"?(?:(?:refresh|id|session)[_-]?token|(?:chatgpt[_-]?)?account[_-]?id|org(?:anization)?[_-]?id|user[_-]?id|email|cookie)"?)\s*[=:]\s*"?)([^\s"&,;}]+)`)
	jwtLogPattern         = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`)
	apiKeyLogPattern      = regexp.MustCompile(`\b(?:sk|rt|sess|org)-[A-Za-z0-9_-]{8,}`)
	emailLogPattern       = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	uuidLogPattern        = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)

	// Encoded forms (smarty-dev#5423 security round 1): decode a bounded copy of
	// URL (%XX) and JSON (\uXXXX, \", \/, \\) escapes before matching, then
	// redact opaque base64/base64url values that the shape patterns cannot see.
	urlEscapeLogPattern    = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
	jsonEscapeLogPattern   = regexp.MustCompile(`\\u[0-9A-Fa-f]{4}|\\["/\\]`)
	secretFieldLogPattern  = regexp.MustCompile(`(?i)((?:key|sig|signature|auth|session)["']?\s*[:=]\s*["']?)[A-Za-z0-9+/_.~-]{16,}={0,2}`)
	opaqueBase64LogPattern = regexp.MustCompile(`[A-Za-z0-9+/_-]{32,}={0,2}`)
	hexRequestIDLogPattern = regexp.MustCompile(`^[0-9A-Fa-f]{32}$`)
)

// SafeDiagnosticForLog returns a bounded, single-line diagnostic suitable for
// ordinary application logs. It preserves the access-token-expired signal while
// redacting credential values and URL userinfo.
func SafeDiagnosticForLog(message string) string {
	excerpt, sourceTruncated := diagnosticRunePrefix(message, diagnosticLogScanRuneLimit)
	if sourceTruncated && !accessTokenExpiredLogPattern.MatchString(excerpt) {
		if marker := accessTokenExpiredLogPattern.FindString(message); marker != "" {
			excerpt += " ... " + marker
		}
	}

	excerpt = strings.Join(strings.Fields(excerpt), " ")
	if excerpt == "" {
		return ""
	}
	excerpt = decodeDiagnosticEscapes(excerpt)
	excerpt = urlUserinfoLogPattern.ReplaceAllString(excerpt, `${1}[REDACTED]@`)
	excerpt = sensitiveLogAssignmentPattern.ReplaceAllString(excerpt, `${1}"[REDACTED]"`)
	excerpt = authorizationLogPattern.ReplaceAllString(excerpt, `${1} [REDACTED]`)
	excerpt = identityKeyLogPattern.ReplaceAllString(excerpt, `${1}[REDACTED]`)
	for _, pattern := range []*regexp.Regexp{jwtLogPattern, apiKeyLogPattern, emailLogPattern, uuidLogPattern} {
		excerpt = pattern.ReplaceAllString(excerpt, "[REDACTED]")
	}
	excerpt = secretFieldLogPattern.ReplaceAllString(excerpt, `${1}[REDACTED]`)
	excerpt = opaqueBase64LogPattern.ReplaceAllStringFunc(excerpt, redactOpaqueBase64)

	return truncateDiagnosticLogExcerpt(excerpt, sourceTruncated)
}

// decodeDiagnosticEscapes decodes URL and JSON escapes in an already bounded
// excerpt, up to diagnosticDecodeRounds times for double encoding. Decoding
// only shortens the text; invalid sequences stay as they are, and invalid
// UTF-8 or control characters from decoded bytes are replaced.
func decodeDiagnosticEscapes(excerpt string) string {
	for round := 0; round < diagnosticDecodeRounds; round++ {
		decoded := urlEscapeLogPattern.ReplaceAllStringFunc(excerpt, func(escape string) string {
			value, _ := strconv.ParseUint(escape[1:], 16, 8)
			return string([]byte{byte(value)})
		})
		decoded = jsonEscapeLogPattern.ReplaceAllStringFunc(decoded, func(escape string) string {
			if len(escape) == 2 {
				return escape[1:]
			}
			value, _ := strconv.ParseUint(escape[2:], 16, 32)
			return string(rune(value))
		})
		if decoded == excerpt {
			break
		}
		excerpt = decoded
	}
	excerpt = strings.ToValidUTF8(excerpt, "?")
	return strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, excerpt)), " ")
}

// redactOpaqueBase64 redacts a 32+ char base64/base64url run unless it reads
// as a path, identifier or request id: split on '/', '-' and '_', every piece
// must be a 32-hex request id or a short (<16) piece without upper case.
// That keeps /v1/responses/compact, model names and hex request ids readable
// and redacts any opaque token, whatever its case mix (smarty-dev#5423).
// ponytail: a 32-hex secret, or a secret made only of short lower-case pieces,
// still passes outside a named field (see secretFieldLogPattern).
func redactOpaqueBase64(run string) string {
	for _, piece := range strings.FieldsFunc(strings.TrimRight(run, "="), func(r rune) bool {
		return r == '/' || r == '-' || r == '_'
	}) {
		if hexRequestIDLogPattern.MatchString(piece) {
			continue
		}
		if len(piece) >= 16 || strings.IndexFunc(piece, func(r rune) bool { return r >= 'A' && r <= 'Z' }) >= 0 || strings.Contains(piece, "+") {
			return "[REDACTED]"
		}
	}
	return run
}

// SafeErrorDiagnostic extracts only allowlisted failure signals from an
// arbitrary error. It never carries the original free-form error text.
func SafeErrorDiagnostic(err error) string {
	if err == nil {
		return ""
	}
	parts := make([]string, 0, 4)
	appendPart := func(part string) {
		if part == "" {
			return
		}
		for _, existing := range parts {
			if existing == part {
				return
			}
		}
		parts = append(parts, part)
	}

	switch {
	case errors.Is(err, io.ErrUnexpectedEOF):
		appendPart("unexpected_EOF")
	case errors.Is(err, io.EOF):
		appendPart("EOF")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		appendPart("timeout")
	}
	if errors.Is(err, context.Canceled) {
		appendPart("canceled")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr != nil && netErr.Timeout() {
		appendPart("timeout")
	}

	rawOriginal := err.Error()
	raw := strings.ToLower(rawOriginal)
	if strings.EqualFold(strings.TrimSpace(rawOriginal), "EOF") {
		appendPart("EOF")
	}
	if strings.Contains(raw, "socks") && (strings.Contains(raw, "authentication failed") || strings.Contains(raw, "authentication required")) {
		appendPart("proxy_authentication_failed")
	}
	for _, signal := range []struct {
		needle string
		label  string
	}{
		{needle: "socks", label: "proxy=socks"},
		{needle: "proxyconnect", label: "proxy_connect_failed"},
		{needle: "proxy connect", label: "proxy_connect_failed"},
		{needle: "dial ", label: "dial_failed"},
		{needle: "dial failed", label: "dial_failed"},
		{needle: "connection refused", label: "connection_refused"},
		{needle: "connection reset", label: "connection_reset"},
		{needle: "connection aborted", label: "connection_aborted"},
		{needle: "stream reset", label: "stream_reset"},
		{needle: "network is unreachable", label: "network_unreachable"},
		{needle: "no route to host", label: "network_unreachable"},
		{needle: "no such host", label: "dns_not_found"},
		{needle: "server misbehaving", label: "dns_failure"},
		{needle: "tls handshake timeout", label: "tls_handshake_timeout"},
		{needle: "i/o timeout", label: "timeout"},
		{needle: "deadline exceeded", label: "timeout"},
		{needle: "unexpected eof", label: "unexpected_EOF"},
		{needle: "certificate", label: "tls_certificate_error"},
		{needle: "invalid character", label: "invalid_response_json"},
		{needle: "cannot unmarshal", label: "invalid_response_json"},
		{needle: "invalid_grant", label: "oauth_error=invalid_grant"},
		{needle: "refresh_token_expired", label: "oauth_error=refresh_token_expired"},
		{needle: "refresh_token_revoked", label: "oauth_error=refresh_token_revoked"},
		{needle: "refresh_token_reused", label: "oauth_error=refresh_token_reused"},
	} {
		if strings.Contains(raw, signal.needle) {
			appendPart(signal.label)
		}
	}
	if match := diagnosticStatusPattern.FindStringSubmatch(rawOriginal); len(match) == 2 {
		appendPart("status=" + match[1])
	}
	if len(parts) == 0 {
		appendPart(fmt.Sprintf("error_type=%T", err))
	}
	return strings.Join(parts, " ")
}

func diagnosticRunePrefix(value string, limit int) (string, bool) {
	if limit <= 0 {
		return "", value != ""
	}
	count := 0
	for index := range value {
		if count == limit {
			return value[:index], true
		}
		count++
	}
	return value, false
}

func truncateDiagnosticLogExcerpt(message string, sourceTruncated bool) string {
	runes := []rune(message)
	if len(runes) <= diagnosticLogRuneLimit {
		if sourceTruncated {
			return message + "..."
		}
		return message
	}

	output := string(runes[:diagnosticLogRuneLimit])
	if match := accessTokenExpiredLogPattern.FindStringIndex(message); match != nil {
		markerStart := utf8.RuneCountInString(message[:match[0]])
		markerEnd := markerStart + utf8.RuneCountInString(message[match[0]:match[1]])
		if markerEnd > diagnosticLogRuneLimit {
			separator := " ... "
			prefixLimit := diagnosticLogRuneLimit - len([]rune(separator)) - (markerEnd - markerStart)
			if prefixLimit < 0 {
				prefixLimit = 0
			}
			output = string(runes[:prefixLimit]) + separator + string(runes[markerStart:markerEnd])
		}
	}
	return output + "..."
}
