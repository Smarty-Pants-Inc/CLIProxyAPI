package executor

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestAPIKeyExecutionModelAnchorAndWire(t *testing.T) {
	ctx := WithClientExecutionPolicy(context.Background(), "gpt-6.1-sol", true)
	ctx = WithClientExecutionPolicy(ctx, "different", false)
	if ClientExecutionModel(ctx) != "gpt-6.1-sol" || !ClientSingleAttempt(ctx) {
		t.Fatal("admission anchor changed")
	}
	for _, body := range []string{`{"model":"gpt-6.1-sol"}`, `{"request":{"model":"gpt-6.1-sol"}}`} {
		if err := ValidateClientWireModel(ctx, []byte(body), false); err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range []string{`{"model":"other"}`, `{}`, `{"session":{"model":"other"}}`, `{"model":"gpt-6.1-sol","request":{"model":"other"}}`, `{"model":null}`, `{"model":"other","model":"gpt-6.1-sol"}`, `{"request":{"model":"other"},"request":{"model":"gpt-6.1-sol"}}`} {
		if err := ValidateClientWireModel(ctx, []byte(body), false); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://synthetic.test/v1/responses", strings.NewReader(`{"model":"other"}`))
	if err := ValidateClientHTTPRequest(req); err == nil {
		t.Fatal("wire model substitution accepted")
	}
	// Unrestricted clients retain existing transport behavior.
	req, _ = http.NewRequest("POST", "https://synthetic.test/v1/responses", strings.NewReader(`{}`))
	if err := ValidateClientHTTPRequest(req); err != nil {
		t.Fatal(err)
	}
}

func TestAPIKeySingleAttemptTransportBudgetAndFreshTurn(t *testing.T) {
	ctx := WithClientExecutionPolicy(context.Background(), "model", true)
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ClaimClientUpstreamAttempt(ctx) == nil {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if admitted.Load() != 1 {
		t.Fatalf("attempts=%d", admitted.Load())
	}
	original := ctx
	ctx = WithWebsocketRequestAdmission(ctx, func(model string) (context.Context, error) {
		return WithClientExecutionPolicy(WithoutClientExecutionPolicy(original), model, true), nil
	})
	next, err := AdmitWebsocketRequest(ctx, "next-model")
	if err != nil || ClientExecutionModel(next) != "next-model" {
		t.Fatalf("fresh turn %v", err)
	}
	if err = ClaimClientUpstreamAttempt(next); err != nil {
		t.Fatal("fresh retained turn reused old attempt budget", err)
	}
	if err = ClaimClientUpstreamAttempt(next); err == nil {
		t.Fatal("retained turn allowed another attempt")
	}
}
