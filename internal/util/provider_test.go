package util

import "testing"

func TestHideAPIKeyBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, key, want string
	}{
		{"empty", "", ""},
		{"one_byte", "x", "..."},
		{"two_bytes", "xy", "..."},
		{"two_byte_utf8", "é", "..."},
		{"three_bytes", "xyz", "x...z"},
		{"four_bytes", "wxyz", "w...z"},
		{"five_bytes", "vwxyz", "vw...yz"},
		{"eight_bytes", "abcdefgh", "ab...gh"},
		{"nine_bytes", "abcdefghi", "abcd...fghi"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := HideAPIKey(tc.key); got != tc.want {
				t.Errorf("HideAPIKey(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

func TestMaskSensitiveQueryShortKeys(t *testing.T) {
	for _, tc := range []struct {
		name, query, want string
	}{
		{"empty", "value=", "value="},
		{"one_byte_plain", "value=x", "value=..."},
		{"one_byte_escaped", "value=%78", "value=..."},
		{"one_byte_escaped_name", "v%61lue=%78", "v%61lue=..."},
		{"two_bytes_plain", "value=xy", "value=..."},
		{"two_bytes_escaped", "value=%78%79", "value=..."},
		{"two_bytes_escaped_name", "v%61lue=%78%79", "v%61lue=..."},
		{"two_byte_utf8", "value=%C3%A9", "value=..."},
		{"trimmed_short_key", "value=+%78+", "value=..."},
		{"existing_key", "key=%78%79", "key=..."},
		{"existing_token", "auth_token=%78", "auth_token=..."},
		{"three_bytes", "value=%78%79%7A", "value=x...z"},
		{"repeated_value", "value=x&value=%78%79", "value=...&value=..."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const ordinary = "&note=keep%20visible&value_hint=ordinary-value"
			if got := MaskSensitiveQuery(tc.query + ordinary); got != tc.want+ordinary {
				t.Errorf("MaskSensitiveQuery(%q) = %q, want %q", tc.query+ordinary, got, tc.want+ordinary)
			}
		})
	}
}

func TestMaskSensitiveHeaderValueShortKeys(t *testing.T) {
	for _, key := range []string{"x", "xy"} {
		for _, header := range []string{"X-Api-Key", "X-Auth-Token", "X-Secret"} {
			t.Run(header+"/"+key, func(t *testing.T) {
				if got := MaskSensitiveHeaderValue(header, key); got != "..." {
					t.Errorf("short secret header = %q, want fully masked", got)
				}
			})
		}
		t.Run("Authorization/"+key, func(t *testing.T) {
			if got := MaskSensitiveHeaderValue("Authorization", "Bearer "+key); got != "Bearer ..." {
				t.Errorf("short authorization = %q, want Bearer ...", got)
			}
			if got := MaskAuthorizationHeader(key); got != "..." {
				t.Errorf("bare authorization = %q, want fully masked", got)
			}
		})
	}
}

func TestMaskSensitiveQueryOAuthSecrets(t *testing.T) {
	const secret = "oauth-secret-DO-NOT-USE-0123456789"
	for _, name := range []string{"code", "state", "code_verifier", "id_token", "access_token", "refresh_token", "client_secret", "password", "Code"} {
		t.Run(name, func(t *testing.T) {
			query := name + "=" + secret + "&provider=codex&error=access_denied"
			got := MaskSensitiveQuery(query)
			want := name + "=oaut...6789&provider=codex&error=access_denied"
			if got != want {
				t.Errorf("MaskSensitiveQuery(%q) = %q, want %q", query, got, want)
			}
		})
	}
	for _, name := range []string{"provider", "error", "error_description", "scope", "redirect_uri", "code_challenge_method", "statement"} {
		if shouldMaskQueryParam(name) {
			t.Errorf("shouldMaskQueryParam(%q) = true, want false", name)
		}
	}
}

// MaskSensitiveQuery sees only the raw query, not the route, so "code" and
// "state" are masked on every route, not just OAuth callbacks. This over-masks
// unrelated access-log queries (e.g. ?state=open), which is accepted: the logs
// lose detail, but a callback secret never leaks (CLIProxyAPI#111 review).
func TestMaskSensitiveQueryMasksCodeAndStateOnEveryRoute(t *testing.T) {
	query := "state=open-issues&code=region-eu-west&page=2"
	want := "state=open...sues&code=regi...west&page=2"
	if got := MaskSensitiveQuery(query); got != want {
		t.Fatalf("MaskSensitiveQuery(%q) = %q, want %q (global masking is intentional)", query, got, want)
	}
}
