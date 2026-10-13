package session

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const benchmarkNonce = "NONCE-00000000"

// largeClaudeBody builds a Claude Messages request of roughly targetBytes with
// the heavy "messages" array first and the session metadata last, which is the
// worst case for path lookups that scan the document from the start.
func largeClaudeBody(targetBytes int) []byte {
	var b strings.Builder
	b.Grow(targetBytes + 1024)
	b.WriteString(`{"model":"claude-sonnet-4-5","max_tokens":32000,"stream":true,"messages":[`)
	text := strings.Repeat(`lorem ipsum dolor sit amet, \"quoted\" {braces} [brackets] `, 32)
	for i := 0; b.Len() < targetBytes; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		nonce := ""
		if i == 0 {
			nonce = benchmarkNonce
		}
		fmt.Fprintf(&b, `{"role":%q,"content":[{"type":"text","text":"%s%d %s"},{"type":"tool_result","tool_use_id":"toolu_%d","content":[{"type":"text","text":"%s"}]}]}`, role, nonce, i, text, i, text)
	}
	b.WriteString(`],"system":[{"type":"text","text":"You are Claude Code."}],"tools":[{"name":"Bash","input_schema":{"type":"object"}}],`)
	b.WriteString(`"metadata":{"user_id":"{\"device_id\":\"dev\",\"account_uuid\":\"acct\",\"session_id\":\"0b5c0bd6-6e6a-4f7a-9a51-3c0f4c2c9d11\"}"}}`)
	return []byte(b.String())
}

type sessionExtractor func(http.Header, []byte, map[string]any) (SessionInfo, bool)

// benchmarkSessionExtractor calls extract `calls` times per iteration on a
// ~2 MB body. With fresh set, every iteration rewrites a nonce inside the
// messages so the first call of the iteration models a new request (cache miss).
func benchmarkSessionExtractor(b *testing.B, headers http.Header, calls int, fresh bool, extract sessionExtractor) {
	// The TestMain equivalence observer re-runs the legacy path; keep it out of timings.
	observer := sessionPayloadViewObserver
	sessionPayloadViewObserver = nil
	defer func() { sessionPayloadViewObserver = observer }()
	payload := largeClaudeBody(2 << 20)
	nonceAt := bytes.Index(payload, []byte(benchmarkNonce))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if fresh {
			b.StopTimer()
			copy(payload[nonceAt:], fmt.Sprintf("NONCE-%08d", i))
			b.StartTimer()
		}
		for c := 0; c < calls; c++ {
			if _, ok := extract(headers, payload, nil); !ok {
				b.Fatal("expected session info")
			}
		}
	}
}

var claudeCodeHeaders = http.Header{"X-Claude-Code-Session-Id": {"claude-root"}}

// Cold: first ExtractSessionInfo call of a request (projection built).
func BenchmarkExtractSessionInfoColdClaudeHeader2MB(b *testing.B) {
	benchmarkSessionExtractor(b, claudeCodeHeaders, 1, true, ExtractSessionInfo)
}

func BenchmarkExtractSessionInfoColdClaudeMetadata2MB(b *testing.B) {
	benchmarkSessionExtractor(b, http.Header{}, 1, true, ExtractSessionInfo)
}

// Cached: a repeat call for the same request payload.
func BenchmarkExtractSessionInfoCachedClaudeHeader2MB(b *testing.B) {
	benchmarkSessionExtractor(b, claudeCodeHeaders, 1, false, ExtractSessionInfo)
}

// PerRequest: handler, session.Enrich and the auth selector each extract
// session info from the same fresh ~2 MB payload.
func BenchmarkExtractSessionInfoPerRequest2MB(b *testing.B) {
	benchmarkSessionExtractor(b, claudeCodeHeaders, 3, true, ExtractSessionInfo)
}

// Legacy benchmarks run the extractor directly on the full payload, which is
// exactly the behaviour before the payload projection.
func BenchmarkLegacyExtractSessionInfoClaudeHeader2MB(b *testing.B) {
	benchmarkSessionExtractor(b, claudeCodeHeaders, 1, true, extractSessionInfo)
}

func BenchmarkLegacyExtractSessionInfoClaudeMetadata2MB(b *testing.B) {
	benchmarkSessionExtractor(b, http.Header{}, 1, true, extractSessionInfo)
}

func BenchmarkLegacyExtractSessionInfoPerRequest2MB(b *testing.B) {
	benchmarkSessionExtractor(b, claudeCodeHeaders, 3, true, extractSessionInfo)
}

// BenchmarkSessionPayloadProjection2MB measures building the projection alone
// (validation plus one top-level pass).
func BenchmarkSessionPayloadProjection2MB(b *testing.B) {
	payload := largeClaudeBody(2 << 20)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := projectSessionPayload(payload); !ok {
			b.Fatal("expected projection")
		}
	}
}
