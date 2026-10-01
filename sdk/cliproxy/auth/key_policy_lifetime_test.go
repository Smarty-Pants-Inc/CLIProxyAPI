package auth

import (
	"context"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"testing"
)

func TestKeyPolicyReleaseWaitsForProducer(t *testing.T) {
	m := NewManager(nil, nil, nil)
	m.SetConfig(&config.Config{})
	p := []config.APIKeyPolicy{{KeySHA256: keyDigest("key"), DailyRequestCap: policyInt(2)}}
	ctx, done, err := m.BeginKeyPolicy(context.Background(), p, "model")
	if err != nil {
		t.Fatal(err)
	}
	producer := make(chan struct{})
	KeyPolicyFromContext(ctx).streamDone = producer
	released := make(chan struct{})
	go func() { done(); close(released) }()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, next, err := m.BeginKeyPolicy(canceled, p, "model"); err == nil {
		next()
		t.Fatal("producer lease released early")
	}
	// A different client's ledger/gate is independent, even while this producer runs.
	_, other, err := m.BeginKeyPolicy(context.Background(), []config.APIKeyPolicy{{KeySHA256: keyDigest("other")}}, "model")
	if err != nil {
		t.Fatal(err)
	}
	other()
	close(producer)
	<-released
	_, next, err := m.BeginKeyPolicy(context.Background(), p, "model")
	if err != nil {
		t.Fatal(err)
	}
	next()
}
