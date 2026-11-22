package helps

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	claudeauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

// These are native-service return fixtures, not a persisted-token trust claim.
// Transport provenance and private publication are independently guarded.
func TestPoolCodexNativeReturnedIdentityDimensions(t *testing.T) {
	claims := `{"sub":"native-sub","https://api.openai.com/auth":{"chatgpt_user_id":"native-user","chatgpt_account_id":"native-entitlement","user_id":"native-alias"}}`
	td := &codexauth.CodexTokenData{AccessToken: "fake-native-access", IDToken: "e30." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".fixture", AccountID: "native-entitlement"}
	i, err := CodexPoolIdentityFromTokenData(td)
	if err != nil {
		t.Fatal(err)
	}
	if i.AccountID != "native-user" || i.EntitlementID != "native-entitlement" || i.AccountAliases["user_id"] != "native-alias" || i.AccountAliases["sub"] != "native-sub" {
		t.Fatalf("identity=%+v", i)
	}
	td.AccountID = "native-user"
	if _, err = CodexPoolIdentityFromTokenData(td); err == nil {
		t.Fatal("legacy AccountID confused account and entitlement dimensions")
	}
	td.AccountID = "native-entitlement"
	claims = `{"sub":"not-a-fallback","https://api.openai.com/auth":{"chatgpt_account_id":"native-entitlement","user_id":"also-not-a-fallback"}}`
	td.IDToken = "e30." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".fixture"
	if _, err = CodexPoolIdentityFromTokenData(td); err == nil {
		t.Fatal("missing native user was replaced by an alias")
	}
}

func TestPoolClaudeRequiresBothRealProfileUUIDs(t *testing.T) {
	for _, raw := range []string{
		`{"account":{"uuid":"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"},"organization":{"uuid":"BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB"}}`,
		`{"account":{"uuid":"synthetic-account"},"organization":{"uuid":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}}`,
		`{"account":{"uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},"organization":{}}`,
	} {
		var profile claudeauth.OAuthProfile
		if err := json.Unmarshal([]byte(raw), &profile); err != nil {
			t.Fatal(err)
		}
		i, err := ClaudePoolIdentityFromProfile(&profile)
		if profile.Account.UUID == "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" {
			if err != nil || i.AccountID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" || i.EntitlementID != "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" {
				t.Fatalf("identity=%+v err=%v", i, err)
			}
		} else if err == nil {
			t.Fatal("synthetic/missing native identity was accepted")
		}
	}
	if _, err := ClaudePoolIdentityFromProfile(nil); err == nil {
		t.Fatal("nil profile accepted")
	}
}
