package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// NativePoolIdentity is returned only by explicitly trusted native OAuth acquisition.
// Account and entitlement are distinct reservation dimensions.
type NativePoolIdentity struct {
	Provider, AccountID, EntitlementID string
	AccountAliases                     map[string]string
}

type NativePoolIdentityAcquirer interface {
	AcquirePoolIdentity(context.Context, *Auth) (*Auth, NativePoolIdentity, error)
}

type PoolOperationKind uint8

const (
	PoolResponses PoolOperationKind = iota + 1
	PoolCompact
	PoolMessages
	PoolCountTokens
	PoolLiveCall
)

type poolOperationState struct {
	pool                                        config.AccountPool
	kind                                        PoolOperationKind
	digest                                      string
	ctx                                         context.Context
	cancel                                      context.CancelFunc
	stopBridge                                  func() bool
	closing, finished, live, executing, started bool
	bootstrapPending, bootstrapComplete         bool
	callID                                      string
	selectedID                                  string
	attemptedIDs                                map[string]struct{}
	identity                                    NativePoolIdentity
	work                                        sync.WaitGroup
	done                                        chan struct{}
}

func isLocalPoolStop(ctx context.Context, err error) bool {
	if !KeyPolicyFromContext(ctx).IsPoolOperation() {
		return false
	}
	var typed *Error
	return errors.As(err, &typed) && typed != nil && (strings.HasPrefix(typed.Code, "api_key_pool_") || typed.Code == "api_key_model_forbidden")
}

// PoolMode reports the manager-wide SDK boundary, independently of HTTP context.
func (m *Manager) PoolMode() bool {
	if m == nil {
		return false
	}
	cfg, _ := m.runtimeConfig.Load().(*config.Config)
	return m.poolInvalid.Load() || (cfg != nil && cfg.AccountPools != nil)
}

// IsPoolOperation reports whether this is an admitted native pool operation.
func (op *KeyPolicyOperation) IsPoolOperation() bool { return op != nil && op.pool != nil }
func (op *KeyPolicyOperation) PoolID() string {
	if !op.IsPoolOperation() {
		return ""
	}
	return op.pool.pool.ID
}
func (op *KeyPolicyOperation) PoolClass() string {
	if !op.IsPoolOperation() {
		return ""
	}
	return string(op.pool.pool.Class)
}
func (op *KeyPolicyOperation) PoolKind() PoolOperationKind {
	if !op.IsPoolOperation() {
		return 0
	}
	return op.pool.kind
}

// PoolPrincipal classifies an explicit configured native key without acquiring a slot.
// It is used by live authentication; the live handler admits after bounded parsing.
func (m *Manager) PoolPrincipal(clientKey string) (string, string, error) {
	if m == nil {
		return "", "", poolError("admission_required", 503)
	}
	m.keyPolicyMu.Lock()
	defer m.keyPolicyMu.Unlock()
	p, _, err := m.poolPrincipalLocked(clientKey)
	if err != nil {
		return "", "", err
	}
	return p.ID, string(p.Class), nil
}

// BeginPoolOperation admits one nonqueueing aggregate logical operation.
func (m *Manager) BeginPoolOperation(ctx context.Context, clientKey, model string, kind PoolOperationKind) (context.Context, *KeyPolicyOperation, error) {
	return m.beginPoolOperation(ctx, clientKey, model, kind)
}

// Finish cancels request-owned work and waits for native source cleanup before release.
// After a successful live transfer, only FinishLive owns release.
func (op *KeyPolicyOperation) Finish() { op.finishPool(false) }
func (op *KeyPolicyOperation) TransferToLive(callID string) error {
	return op.transferPoolToLive(callID)
}
func (op *KeyPolicyOperation) FinishLive() { op.finishPool(true) }

func (m *Manager) SelectPoolLiveAuth(ctx context.Context, pinnedAuthID string) (*Auth, error) {
	return m.selectPoolLiveAuth(ctx, pinnedAuthID)
}
func (m *Manager) NewPoolLiveRequest(ctx context.Context, selected *Auth, callID string, body []byte, headers http.Header) (*http.Request, error) {
	return m.newPoolLiveRequest(ctx, selected, callID, body, headers)
}

// SendPoolLiveRequest dispatches only an unmodified, privately minted bootstrap
// request. Generic raw SDK methods remain unavailable even with pool admission.
func (m *Manager) SendPoolLiveRequest(req *http.Request) (*http.Response, error) {
	return m.sendPoolLiveRequest(req)
}
