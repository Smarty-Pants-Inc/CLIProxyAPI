package usage

import "context"

type observerKey struct{}

// WithObserver observes canonical usage synchronously, before optional async sinks.
func WithObserver(ctx context.Context, observe func(Record)) context.Context {
	return context.WithValue(ctx, observerKey{}, observe)
}
func observeRecord(ctx context.Context, record Record) {
	if ctx != nil {
		if observe, ok := ctx.Value(observerKey{}).(func(Record)); ok {
			observe(record)
		}
	}
}
