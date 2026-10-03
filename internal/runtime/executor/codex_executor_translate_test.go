package executor

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestTranslateCodexRequestPairReusesEqualPayload(t *testing.T) {
	from := sdktranslator.Format("codex-test-from-equal")
	to := sdktranslator.Format("codex-test-to-equal")
	var calls int32
	sdktranslator.Register(from, to, func(model string, rawJSON []byte, stream bool) []byte {
		atomic.AddInt32(&calls, 1)
		if model != "test-model" {
			t.Errorf("model = %q, want test-model", model)
		}
		if !stream {
			t.Error("stream = false, want true")
		}
		return append([]byte(nil), rawJSON...)
	}, sdktranslator.ResponseTransform{})

	payload := []byte(`{"model":"test-model","input":[{"role":"user"}]}`)
	originalTranslated, body := translateCodexRequestPair(from, to, "test-model", payload, bytes.Clone(payload), true)

	if gotCalls := atomic.LoadInt32(&calls); gotCalls != 1 {
		t.Fatalf("TranslateRequest calls = %d, want 1", gotCalls)
	}
	if !bytes.Equal(originalTranslated, body) {
		t.Fatalf("translated payloads differ: original=%s body=%s", originalTranslated, body)
	}
}

func TestTranslateCodexRequestPairTranslatesDifferentPayloads(t *testing.T) {
	from := sdktranslator.Format("codex-test-from-different")
	to := sdktranslator.Format("codex-test-to-different")
	var calls int32
	sdktranslator.Register(from, to, func(_ string, rawJSON []byte, _ bool) []byte {
		atomic.AddInt32(&calls, 1)
		return append([]byte(nil), rawJSON...)
	}, sdktranslator.ResponseTransform{})

	originalPayload := []byte(`{"model":"test-model","input":[{"role":"system"}]}`)
	payload := []byte(`{"model":"test-model","input":[{"role":"user"}]}`)
	originalTranslated, body := translateCodexRequestPair(from, to, "test-model", originalPayload, payload, false)

	if gotCalls := atomic.LoadInt32(&calls); gotCalls != 2 {
		t.Fatalf("TranslateRequest calls = %d, want 2", gotCalls)
	}
	if !bytes.Equal(originalTranslated, originalPayload) {
		t.Fatalf("original translated = %s, want %s", originalTranslated, originalPayload)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("body = %s, want %s", body, payload)
	}
}

func TestTranslateCodexRequestPairPreservesPolicyAndUpdateIntent(t *testing.T) {
	from := sdktranslator.Format("codex-test-policy-update-from")
	to := sdktranslator.Format("codex-test-policy-update-to")
	op := &cliproxyauth.KeyPolicyOperation{}
	ctx := cliproxyauth.WithKeyPolicy(context.Background(), op)
	sdktranslator.RegisterRequestEnvelope(from, to, func(transformCtx context.Context, req sdktranslator.RequestEnvelope) sdktranslator.RequestEnvelope {
		if cliproxyauth.KeyPolicyFromContext(transformCtx) != op {
			t.Error("restricted translation lost its policy admission context")
		}
		req.ConfigurationUpdatesChanged = bytes.Contains(req.Body, []byte("changed"))
		return req
	})
	original := []byte(`{"model":"test-model","input":"original"}`)
	payload := []byte(`{"model":"test-model","input":"changed"}`)
	translatedOriginal, body, changed := translateCodexRequestPairWithUpdateIntentContext(ctx, from, to, "test-model", original, payload, false)
	if !bytes.Equal(translatedOriginal, original) || !bytes.Equal(body, payload) || !changed {
		t.Fatal("policy-aware translation lost body or configuration update intent")
	}
	_, _, changed = translateCodexRequestPairWithUpdateIntentContext(ctx, from, to, "test-model", payload, original, true)
	if changed {
		t.Fatal("original request update intent leaked into the actual request")
	}
}
