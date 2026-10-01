package live

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

type liveModelInspectionContextKey struct{}

func (h *Handler) authorizeClientRequest(c *gin.Context, model string, metered bool) error {
	ctx := c.Request.Context()
	if err := h.authManager.ValidateClientRequest(ctx, model); err != nil {
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
