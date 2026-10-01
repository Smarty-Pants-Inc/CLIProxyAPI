package executor

import "context"

// WebsocketInput is a frame from the single downstream reader. Err terminates
// the connection; Payload is owned by the receiver and must not be replayed.
type WebsocketInput struct {
	Payload []byte
	Err     error
}
type websocketInputKey struct{}

func WithWebsocketInput(ctx context.Context, input <-chan WebsocketInput) context.Context {
	return context.WithValue(ctx, websocketInputKey{}, input)
}
func WebsocketInputFromContext(ctx context.Context) <-chan WebsocketInput {
	if ctx == nil {
		return nil
	}
	input, _ := ctx.Value(websocketInputKey{}).(<-chan WebsocketInput)
	return input
}

// WithWebsocketAuthCheck supplies the live account-state check for a bound
// connection. It may reject further frames but never select another account.
type websocketRequestCheckKey struct{}

// WithWebsocketRequestCheck checks effective client models on retained turns.
func WithWebsocketRequestCheck(ctx context.Context, check func(string) error) context.Context {
	return context.WithValue(ctx, websocketRequestCheckKey{}, check)
}

func ValidateWebsocketRequest(ctx context.Context, model string) error {
	if ctx == nil {
		return nil
	}
	if check, ok := ctx.Value(websocketRequestCheckKey{}).(func(string) error); ok && check != nil {
		if checkAdmitted, ok := ctx.Value(websocketAdmittedRequestCheckKey{}).(func(context.Context, string) error); ok && checkAdmitted != nil {
			return checkAdmitted(WebsocketAdmittedContext(ctx), model)
		}
		return check(model)
	}
	return nil
}

type websocketAdmittedRequestCheckKey struct{}

func WithWebsocketAdmittedRequestCheck(ctx context.Context, check func(context.Context, string) error) context.Context {
	return context.WithValue(ctx, websocketAdmittedRequestCheckKey{}, check)
}

type websocketRequestAdmissionKey struct{}

// WithWebsocketRequestAdmission counts each retained create/append/steer once,
// independently of repeated credential checks and chunk writes.
func WithWebsocketRequestAdmission(ctx context.Context, admit func(string) (context.Context, error)) context.Context {
	return context.WithValue(ctx, websocketRequestAdmissionKey{}, admit)
}

func AdmitWebsocketRequest(ctx context.Context, model string) (context.Context, error) {
	if ctx != nil {
		if admit, ok := ctx.Value(websocketRequestAdmissionKey{}).(func(string) (context.Context, error)); ok && admit != nil {
			admitted, err := admit(model)
			// Preserve the transport callbacks as well as the new per-turn receipt.
			return context.WithValue(ctx, websocketAdmittedContextKey{}, admitted), err
		}
	}
	return ctx, ValidateWebsocketRequest(ctx, model)
}

type websocketAdmittedContextKey struct{}

func WebsocketAdmittedContext(ctx context.Context) context.Context {
	if ctx != nil {
		if admitted, ok := ctx.Value(websocketAdmittedContextKey{}).(context.Context); ok && admitted != nil {
			return admitted
		}
	}
	return ctx
}

type websocketContextAuthCheckKey struct{}

func WithWebsocketContextAuthCheck(ctx context.Context, check func(context.Context, string) bool) context.Context {
	return context.WithValue(ctx, websocketContextAuthCheckKey{}, check)
}

type websocketAuthCheckKey struct{}
type websocketCredentialBindingKey struct{}

// WithWebsocketCredentialBinding requires retained sockets to match their dial
// credential. Unrestricted clients retain the existing session reuse behavior.
func WithWebsocketCredentialBinding(ctx context.Context) context.Context {
	return context.WithValue(ctx, websocketCredentialBindingKey{}, true)
}

func WebsocketCredentialBindingRequired(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	required, _ := ctx.Value(websocketCredentialBindingKey{}).(bool)
	return required
}

func WithWebsocketAuthCheck(ctx context.Context, check func(string) bool) context.Context {
	return context.WithValue(ctx, websocketAuthCheckKey{}, check)
}
func WebsocketAuthEnabled(ctx context.Context, authID string) bool {
	if ctx == nil {
		return true
	}
	if check, ok := ctx.Value(websocketContextAuthCheckKey{}).(func(context.Context, string) bool); ok && check != nil {
		return check(WebsocketAdmittedContext(ctx), authID)
	}
	check, _ := ctx.Value(websocketAuthCheckKey{}).(func(string) bool)
	return check == nil || check(authID)
}
