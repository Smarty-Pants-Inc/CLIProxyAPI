package helps

import (
	"net/http"
	"testing"
)

// NativePoolTransportForTest replaces only native transport construction, below
// both genuine production fences. Tests are deliberately non-parallel.
func NativePoolTransportForTest(t *testing.T, transport http.RoundTripper) {
	t.Helper()
	previous := newFallbackHTTPTransport
	newFallbackHTTPTransport = func(_, _, _ http.RoundTripper) http.RoundTripper { return transport }
	t.Cleanup(func() { newFallbackHTTPTransport = previous })
}
