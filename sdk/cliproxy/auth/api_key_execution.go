package auth

import (
	"context"
	"errors"
	"net/http"

	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func (m *Manager) SingleAttemptClient(ctx context.Context) bool {
	for _, policy := range apiKeyPoliciesFromContext(m.withAPIKeyPolicies(ctx)) {
		if policy.SingleAttempt {
			return true
		}
	}
	return false
}

// ClientExecutionMustStop is evaluated before configurable upstream error actions.
// Client policy cannot be overridden by a credential's retry/cooldown rules.
func (m *Manager) ClientExecutionMustStop(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if m.SingleAttemptClient(ctx) || isAPIKeyControlError(err) {
		return true
	}
	var status interface{ StatusCode() int }
	return m.HasClientAPIKeyPolicy(ctx) && errors.As(err, &status) && status.StatusCode() == http.StatusBadRequest
}

func (m *Manager) ValidateClientExecution(ctx context.Context, model string) error {
	if err := coreexecutor.ValidateClientExecutionModel(ctx, model); err != nil {
		return &Error{Code: "api_key_model_forbidden", Message: err.Error(), HTTPStatus: http.StatusForbidden}
	}
	return nil
}

func (m *Manager) preparedClientExecutionModelsWithAlias(ctx context.Context, auth *Auth, routeModel string) ([]string, bool, OAuthModelAliasResult, *apiKeyModelRoutingSnapshot) {
	if !m.HasClientAPIKeyPolicy(ctx) {
		return m.preparedExecutionModelsWithAlias(auth, routeModel)
	}
	// ponytail: restricted clients use exactly their admitted name; aliases/pools,
	// auth prefixes and Home overrides are not an alternate-model permission.
	model := coreexecutor.ClientExecutionModel(ctx)
	return m.filterExecutionModels(auth, model, []string{model}, false), false, OAuthModelAliasResult{}, m.loadAPIKeyModelRouting()
}
