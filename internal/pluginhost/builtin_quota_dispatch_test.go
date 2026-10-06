package pluginhost

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/quotaprovider"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func builtinForTest(admit bool) *testQuotaProvider {
	return &testQuotaProvider{
		identifier: "oauth-usage",
		describeFn: func(context.Context, pluginapi.QuotaDescribeRequest) (pluginapi.QuotaDescribeResponse, error) {
			return pluginapi.QuotaDescribeResponse{SupportedProviders: []string{"codex", "claude"}}, nil
		},
		fetchFn: func(context.Context, pluginapi.QuotaFetchRequest) (pluginapi.QuotaFetchResponse, error) {
			if !admit {
				return pluginapi.QuotaFetchResponse{}, quotaprovider.ErrNotApplicable
			}
			return pluginapi.QuotaFetchResponse{Status: "builtin"}, nil
		},
		resetFn: func(context.Context, pluginapi.QuotaResetRequest) (pluginapi.QuotaResetResponse, error) {
			return pluginapi.QuotaResetResponse{Message: "builtin reset"}, nil
		},
	}
}

func TestBuiltinQuotaYieldsToSupportedProvidersPlugin(t *testing.T) {
	plugin := &testQuotaProvider{
		identifier: "multi-quota",
		describeFn: func(context.Context, pluginapi.QuotaDescribeRequest) (pluginapi.QuotaDescribeResponse, error) {
			return pluginapi.QuotaDescribeResponse{SupportedProviders: []string{"codex", "claude"}, SupportsReset: true}, nil
		},
		fetchFn: func(context.Context, pluginapi.QuotaFetchRequest) (pluginapi.QuotaFetchResponse, error) {
			return pluginapi.QuotaFetchResponse{Status: "plugin"}, nil
		},
	}
	host := newHostWithRecords(capabilityRecord{id: "multi-quota-plugin", plugin: pluginapi.Plugin{Capabilities: pluginapi.Capabilities{QuotaProvider: plugin}}})
	host.RegisterBuiltinQuotaProvider(builtinForTest(true))
	for _, provider := range []string{"codex", "claude"} {
		resp, handled, err := host.FetchQuota(context.Background(), pluginapi.QuotaFetchRequest{Provider: provider, AuthID: "a"})
		if err != nil || !handled || resp.Status != "plugin" {
			t.Fatalf("%s fetch went to builtin: handled=%v err=%v resp=%+v", provider, handled, err, resp)
		}
		reset, handled, err := host.ResetQuota(context.Background(), pluginapi.QuotaResetRequest{Provider: provider, AuthID: "a"})
		if err != nil || !handled || !reset.Success {
			t.Fatalf("%s reset went to builtin: handled=%v err=%v resp=%+v", provider, handled, err, reset)
		}
	}
	// Explicit plugin-ID control still reaches the builtin.
	resp, handled, err := host.FetchQuotaByPlugin(context.Background(), "builtin-oauth-usage", pluginapi.QuotaFetchRequest{Provider: "codex", AuthID: "a"})
	if err != nil || !handled || resp.Status != "builtin" {
		t.Fatalf("explicit builtin fetch failed: handled=%v err=%v resp=%+v", handled, err, resp)
	}
}

func TestBuiltinQuotaDefaultAndIneligibleDispatch(t *testing.T) {
	for _, admit := range []bool{true, false} {
		host := New()
		host.RegisterBuiltinQuotaProvider(builtinForTest(admit))
		resp, handled, err := host.FetchQuota(context.Background(), pluginapi.QuotaFetchRequest{Provider: "claude", AuthID: "a"})
		if err != nil || handled != admit || (admit && resp.Status != "builtin") {
			t.Fatalf("admit=%v: handled=%v err=%v resp=%+v", admit, handled, err, resp)
		}
	}
}
