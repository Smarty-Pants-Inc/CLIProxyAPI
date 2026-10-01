package live

import (
	"context"
	"fmt"
	"net/http"
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

type liveModelInspectionContextKey struct{}

// Retain only admission values, not the bootstrap request's cancellation parent.
func livePolicyContext(ctx context.Context) context.Context {
	retained := auth.WithClientAPIKeyFromContext(context.Background(), ctx)
	inspected, _ := ctx.Value(liveModelInspectionContextKey{}).(bool)
	return context.WithValue(retained, liveModelInspectionContextKey{}, inspected)
}

// Validate both immutable admission and the attaching request. Checking both
// credential snapshots prevents a same-ID replacement from blessing the call.
func (h *Handler) validateRetainedLiveAuth(ctx context.Context, selected *auth.Auth, session liveSession) error {
	if session.admittedAuth != nil && !sameRetainedLiveIdentity(session.admittedAuth, selected) {
		return &auth.Error{Code: "api_key_policy_unavailable", HTTPStatus: http.StatusServiceUnavailable, Message: "retained Realtime credential identity changed; start a new call"}
	}
	contexts := []context.Context{ctx}
	if session.policyContext != nil {
		contexts = append(contexts, session.policyContext)
	}
	for _, policyContext := range contexts {
		if err := h.validateLiveAuth(policyContext, selected); err != nil {
			return err
		}
		if session.admittedAuth != nil {
			if err := h.validateLiveAuth(policyContext, session.admittedAuth); err != nil {
				return err
			}
		}
	}
	return nil
}

// A refresh may rotate tokens for the same explicit account. A file/account
// replacement starts a new lifetime and cannot rebind an already-created call.
func sameRetainedLiveIdentity(original, current *auth.Auth) bool {
	if current == nil || original.ID != current.ID || original.Provider != current.Provider || original.FileName != current.FileName ||
		(original.RegistrationEpoch != 0 && original.RegistrationEpoch != current.RegistrationEpoch) {
		return false
	}
	identified := false
	for _, key := range []string{"email", "account_id", "account_uuid", "organization_uuid"} {
		if !reflect.DeepEqual(original.Metadata[key], current.Metadata[key]) || original.Attributes[key] != current.Attributes[key] {
			return false
		}
		if value, ok := original.Metadata[key].(string); ok && value != "" {
			identified = true
		}
		identified = identified || original.Attributes[key] != ""
	}
	// ponytail: without a stable account identity, a token change cannot be
	// distinguished safely from substitution. Require a new call in that case.
	return identified || !auth.CredentialsChanged(original, current)
}

func (h *Handler) retainedClientMessagePolicy(ctx context.Context, selected *auth.Auth, session liveSession) func([]byte) error {
	policies := []func([]byte) error{}
	if policy := h.clientMessagePolicy(ctx, selected); policy != nil {
		policies = append(policies, policy)
	}
	if session.policyContext != nil {
		if policy := h.clientMessagePolicy(session.policyContext, selected); policy != nil {
			policies = append(policies, policy)
		}
	}
	if len(policies) == 0 {
		return nil
	}
	return func(payload []byte) error {
		for _, policy := range policies {
			if err := policy(payload); err != nil {
				return err
			}
		}
		return nil
	}
}

func (h *Handler) authorizeClientRequest(c *gin.Context, model string, metered bool) error {
	ctx := c.Request.Context()
	var err error
	ctx, err = h.authManager.AdmitClientRequest(ctx, model)
	if err != nil {
		return err
	}
	if metered {
		if err := h.authManager.ValidateMeteredClientRoute(ctx); err != nil {
			return err
		}
	}
	ctx = context.WithValue(ctx, liveModelInspectionContextKey{}, h.authManager.HasClientModelPolicy(ctx))
	c.Request = c.Request.WithContext(h.authManager.WithClientRequest(ctx, model))
	return nil
}

func (h *Handler) validateLiveAuth(ctx context.Context, selected *auth.Auth) error {
	inspected, _ := ctx.Value(liveModelInspectionContextKey{}).(bool)
	if !inspected && h.authManager.HasClientModelPolicy(ctx) {
		return fmt.Errorf("Realtime model policy changed; reconnect for message inspection")
	}
	if err := h.authManager.ValidateClientAuth(ctx, selected); err != nil {
		return err
	}
	return h.authManager.ValidateMeteredClientRoute(ctx)
}

func (h *Handler) clientMessagePolicy(ctx context.Context, selected *auth.Auth) func([]byte) error {
	if !h.authManager.HasClientModelPolicy(ctx) {
		return nil
	}
	return func(payload []byte) error {
		if err := h.validateLiveAuth(ctx, selected); err != nil {
			return err
		}
		for _, field := range []string{"model", "session.model", "response.model"} {
			if model := gjson.GetBytes(payload, field).String(); model != "" {
				if err := h.authManager.ValidateClientRequest(ctx, model); err != nil {
					return err
				}
			}
		}
		return nil
	}
}
