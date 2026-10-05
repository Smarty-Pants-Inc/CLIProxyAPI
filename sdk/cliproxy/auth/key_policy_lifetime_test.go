package auth

import (
	"context"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

type policyUsageFunc func(context.Context, usage.Record)

func (f policyUsageFunc) HandleUsage(ctx context.Context, r usage.Record) { f(ctx, r) }

type policyBuiltinUsageFunc struct{ policyUsageFunc }

func (policyBuiltinUsageFunc) BuiltinUsageSink() {}

func TestKeyPolicyQueuedUsageSurvivesReload(t *testing.T) {
	m := NewManager(nil, nil, nil)
	ctx, done, err := m.BeginKeyPolicy(context.Background(), []config.APIKeyPolicy{{KeySHA256: keyDigest("key")}}, "model")
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	u := usage.NewManager(1)
	defer u.Stop()
	started, release := make(chan struct{}), make(chan struct{})
	u.Register(policyUsageFunc(func(_ context.Context, r usage.Record) {
		if r.Model == "block" {
			close(started)
			<-release
		}
	}))
	u.Publish(context.Background(), usage.Record{Model: "block"})
	<-started
	u.Publish(ctx, usage.Record{Model: "model", APIKey: "key"})
	m.SetConfig(&config.Config{Plugins: config.PluginsConfig{Enabled: true}})
	external := 0
	u.Register(policyUsageFunc(func(_ context.Context, r usage.Record) {
		if r.Model == "model" {
			external++
		}
	}))
	observed := make(chan usage.Record, 1)
	u.Register(policyBuiltinUsageFunc{policyUsageFunc(func(_ context.Context, r usage.Record) {
		if r.Model == "model" {
			observed <- r
		}
	})})
	close(release)
	r := <-observed
	if external != 0 || r.APIKey == "key" {
		t.Fatalf("queued restriction lost: external=%d key=%q", external, r.APIKey)
	}
}

type policyWaitingContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *policyWaitingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestKeyPolicyWaitingAdmissionCapturesTightening(t *testing.T) {
	m := NewManager(nil, nil, nil)
	p := config.APIKeyPolicy{KeySHA256: keyDigest("key"), DailyRequestCap: policyInt(100)}
	m.SetConfig(&config.Config{})
	_, release, err := m.BeginKeyPolicy(context.Background(), []config.APIKeyPolicy{p}, "model")
	if err != nil {
		t.Fatal(err)
	}
	waiting := &policyWaitingContext{Context: context.Background(), waiting: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, done, err := m.BeginKeyPolicy(waiting, []config.APIKeyPolicy{p}, "model")
		if done != nil {
			done()
		}
		result <- err
	}()
	<-waiting.waiting
	p.DailyRequestCap = policyInt(0)
	m.SetConfig(&config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{p}}})
	release()
	if err := <-result; err == nil {
		t.Fatal("queued operation admitted under zero cap")
	}
	m.SetConfig(&config.Config{})
}

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
