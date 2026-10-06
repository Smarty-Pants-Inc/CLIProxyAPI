package cliproxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	log "github.com/sirupsen/logrus"
)

func (s *Service) applyConfigUpdate(newCfg *config.Config) {
	s.applyConfigUpdateWithAuthSynthesis(context.Background(), newCfg, true)
}

func (s *Service) applyWatcherConfigUpdate(newCfg *config.Config) {
	s.applyConfigUpdateWithAuthSynthesis(context.Background(), newCfg, false)
}

type configCommit struct {
	cfg      *config.Config
	sequence uint64
}

type routingRuntimeState struct {
	strategy                 string
	sessionAffinity          bool
	sessionAffinityTTL       time.Duration
	statePath                string
	statePathUnavailable     bool
	sessionAffinitySubagents bool
}

func normalizedRoutingRuntimeState(cfg *config.Config) routingRuntimeState {
	state := routingRuntimeState{
		strategy:                 "round-robin",
		sessionAffinityTTL:       coreauth.DefaultSessionAffinityTTL,
		sessionAffinitySubagents: true,
	}
	if cfg == nil {
		return state
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Routing.Strategy)) {
	case "weighted-round-robin", "weightedroundrobin", "wrr":
		state.strategy = "weighted-round-robin"
	case "fill-first", "fillfirst", "ff":
		state.strategy = "fill-first"
	}
	state.sessionAffinity = cfg.Routing.SessionAffinity
	if state.sessionAffinity && !cfg.Home.Enabled && strings.TrimSpace(cfg.AuthDir) != "" {
		authDir, errResolve := util.ResolveAuthDir(cfg.AuthDir)
		if errResolve == nil {
			authDir, errResolve = filepath.Abs(authDir)
		}
		if errResolve == nil {
			authDir, errResolve = resolveAffinityStateDir(authDir)
		}
		if errResolve != nil {
			// Do not write runtime state to an unresolved or unintended directory.
			log.WithError(errResolve).Error("failed to resolve session affinity state directory; routing will fail closed")
			state.statePathUnavailable = true
		} else {
			state.statePath = filepath.Join(authDir, "session-affinity.state")
		}
	}
	if ttl := strings.TrimSpace(cfg.Routing.SessionAffinityTTL); ttl != "" {
		if parsed, errParse := time.ParseDuration(ttl); errParse == nil && parsed > 0 {
			if parsed < time.Second {
				parsed = time.Second
			}
			state.sessionAffinityTTL = parsed
		}
	}
	if state.sessionAffinity && cfg.Routing.SessionAffinitySubagents != nil {
		state.sessionAffinitySubagents = *cfg.Routing.SessionAffinitySubagents
	}
	return state
}

// resolveAffinityStateDir receives an absolute path. Resolve its longest existing
// ancestor so creating missing directories cannot change the cache ownership key.
func resolveAffinityStateDir(path string) (string, error) {
	ancestor := path
	missing := ""
	for {
		realDir, errReal := filepath.EvalSymlinks(ancestor)
		if errReal == nil {
			return filepath.Join(realDir, missing), nil
		}
		if !errors.Is(errReal, os.ErrNotExist) {
			return "", errReal
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", errReal
		}
		missing = filepath.Join(filepath.Base(ancestor), missing)
		ancestor = parent
	}
}

func newRoutingSelector(state routingRuntimeState, cache ...*coreauth.SessionCache) coreauth.Selector {
	var selector coreauth.Selector
	switch state.strategy {
	case "weighted-round-robin":
		selector = &coreauth.WeightedRoundRobinSelector{}
	case "fill-first":
		selector = &coreauth.FillFirstSelector{}
	default:
		selector = &coreauth.RoundRobinSelector{}
	}
	if state.sessionAffinity {
		subagents := state.sessionAffinitySubagents
		var initializationError error
		if state.statePathUnavailable {
			initializationError = errors.New("session affinity state directory is unavailable")
		}
		var sharedCache *coreauth.SessionCache
		if len(cache) > 0 {
			sharedCache = cache[0]
		}
		selector = coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{
			Fallback:            selector,
			TTL:                 state.sessionAffinityTTL,
			StatePath:           state.statePath,
			InitializationError: initializationError,
			SubagentAffinity:    &subagents,
			Cache:               sharedCache,
		})
	}
	return selector
}

func (s *Service) applyConfigUpdateWithAuthSynthesis(ctx context.Context, newCfg *config.Config, synthesizeConfigAuths bool) bool {
	commit := s.commitConfigUpdate(newCfg)
	if commit.cfg == nil {
		return false
	}
	return s.applyConfigRuntime(ctx, commit, synthesizeConfigAuths)
}

// commitConfigUpdate applies only in-memory configuration state. Runtime work that
// may block on plugins, storage, or networking is deliberately deferred. Catalog
// source generations change here so an older commit cannot restart stale readers.
func (s *Service) commitConfigUpdate(newCfg *config.Config) configCommit {
	if s == nil {
		return configCommit{}
	}

	s.configUpdateMu.Lock()
	defer s.configUpdateMu.Unlock()

	if newCfg == nil {
		s.cfgMu.RLock()
		newCfg = s.cfg
		s.cfgMu.RUnlock()
	}
	if newCfg == nil {
		return configCommit{}
	}
	if errValidate := newCfg.ValidateAPIKeyPolicies(); errValidate != nil {
		log.WithError(errValidate).Warn("rejected config update with invalid API key policies")
		return configCommit{}
	}
	if errValidate := newCfg.ValidateCredentialWeights(); errValidate != nil {
		log.WithError(errValidate).Warn("rejected config update with invalid credential weights")
		return configCommit{}
	}

	if errValidate := newCfg.Models.Validate(); errValidate != nil {
		log.WithError(errValidate).Warn("rejected invalid model catalog sources")
		return configCommit{}
	}
	s.cfgMu.Lock()
	newCfg = internalconfig.PreserveAPIKeyPolicies(s.cfg, newCfg)
	if errValidate := newCfg.ValidateAPIKeyPolicies(); errValidate != nil {
		s.cfg = internalconfig.RetainAPIKeyPolicyWarnings(s.cfg, newCfg)
		s.cfgMu.Unlock()
		log.WithError(errValidate).Warn("rejected config update with invalid API key policies")
		return configCommit{}
	}
	s.cfg = newCfg
	s.cfgMu.Unlock()
	s.cancelStaleAntigravityProbes("")
	s.configSequence++
	registry.UpdateModelCatalogSources(newCfg.Models, newCfg.Home.Enabled)
	return configCommit{cfg: newCfg, sequence: s.configSequence}
}

func (s *Service) configCommitCurrent(commit configCommit) bool {
	if s == nil || commit.sequence == 0 {
		return false
	}
	s.configUpdateMu.Lock()
	current := s.configSequence == commit.sequence
	s.configUpdateMu.Unlock()
	return current
}

func (s *Service) applyConfigRuntime(ctx context.Context, commit configCommit, synthesizeConfigAuths bool) bool {
	cfg := commit.cfg
	if s == nil || cfg == nil {
		return false
	}
	s.configRuntimeMu.Lock()
	defer s.configRuntimeMu.Unlock()
	if !s.configCommitCurrent(commit) {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}

	if !s.applyManagerConfig(ctx, commit) {
		return false
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	if !s.applyPprofConfigContext(ctx, cfg) {
		return false
	}
	s.applyDiscoveryConfigContext(ctx, cfg)
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	if !s.updateServerClientsContext(ctx, cfg) {
		return false
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}

	registrationCtx := coreauth.WithSkipPersist(ctx)
	s.syncPluginRuntimeConfigForConfig(registrationCtx, cfg)
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	var auths []*coreauth.Auth
	if s.coreManager != nil {
		auths = s.coreManager.List()
	}
	s.registerAvailableExecutors(registrationCtx, executorRegistrationOptions{
		includeBaseline:   cfg.Home.Enabled,
		forceReplaceAuths: true,
		auths:             auths,
	})
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	if synthesizeConfigAuths {
		s.registerConfigAPIKeyAuths(registrationCtx, cfg)
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	if s.coreManager != nil && !cfg.Home.Enabled && cfg.SaveCooldownStatus {
		if errRestoreCooldown := s.coreManager.RestoreCooldownStates(registrationCtx); errRestoreCooldown != nil && ctx.Err() == nil {
			log.Warnf("failed to restore cooldown state after config update: %v", errRestoreCooldown)
		}
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	s.syncPluginModelRuntime(registrationCtx)
	return ctx.Err() == nil
}

func (s *Service) applyManagerConfig(ctx context.Context, commit configCommit) bool {
	if s == nil || s.coreManager == nil || commit.cfg == nil {
		return s != nil && commit.cfg != nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	// Adopt the builder-created cache before any replacement, including a switch
	// to disabled affinity or Home. Never retarget an old cache: in-flight requests
	// may still write to it after SetSelector stops the old selector.
	if oldState := s.appliedRoutingState; oldState != nil && oldState.statePath != "" {
		if oldSelector, ok := s.coreManager.Selector().(*coreauth.SessionAffinitySelector); ok {
			if s.affinityCaches == nil {
				s.affinityCaches = make(map[string]*coreauth.SessionCache)
			}
			if s.affinityCaches[oldState.statePath] == nil {
				s.affinityCaches[oldState.statePath] = oldSelector.Cache()
			}
		}
	}
	routingState := normalizedRoutingRuntimeState(commit.cfg)
	if s.appliedRoutingState == nil || *s.appliedRoutingState != routingState {
		var sharedCache *coreauth.SessionCache
		if routingState.statePath != "" {
			sharedCache = s.affinityCaches[routingState.statePath]
		}
		selector := newRoutingSelector(routingState, sharedCache)
		if routingState.statePath != "" {
			if s.affinityCaches == nil {
				s.affinityCaches = make(map[string]*coreauth.SessionCache)
			}
			s.affinityCaches[routingState.statePath] = selector.(*coreauth.SessionAffinitySelector).Cache()
		}
		s.coreManager.SetSelector(selector)
		s.appliedRoutingState = &routingState
	}
	s.applyRetryConfig(commit.cfg)
	store := s.resolveCooldownStateStore(commit.cfg)
	if !s.coreManager.ApplyConfigWithCooldownStateStore(ctx, commit.cfg, store) {
		return false
	}
	s.coreManager.SetOAuthModelAlias(commit.cfg.OAuthModelAlias)
	return true
}

func (s *Service) updateServerClientsContext(ctx context.Context, cfg *config.Config) bool {
	if s == nil || cfg == nil || (ctx != nil && ctx.Err() != nil) {
		return false
	}
	if s.updateServerClientsContextFn != nil {
		return s.updateServerClientsContextFn(ctx, cfg)
	}
	if s.server == nil {
		return true
	}
	return s.server.UpdateClientsContext(ctx, cfg)
}

func (s *Service) reloadConfigFromWatcher() bool {
	if s == nil || s.watcher == nil {
		return false
	}
	return s.watcher.ReloadConfigIfChanged()
}

func (s *Service) registerConfigAPIKeyAuths(ctx context.Context, cfg *config.Config) {
	if s == nil || s.coreManager == nil || cfg == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	configSynth := synthesizer.NewConfigSynthesizer()
	auths, errSynthesize := configSynth.Synthesize(&synthesizer.SynthesisContext{
		Config:      cfg,
		Now:         time.Now(),
		IDGenerator: synthesizer.NewStableIDGenerator(),
	})
	if errSynthesize != nil {
		log.Warnf("failed to synthesize config API key auths: %v", errSynthesize)
		return
	}

	registrationCtx := coreauth.WithDeferredAPIKeyModelAliasRebuild(ctx)
	tasks := make([]modelRegistrationTask, 0, len(auths))
	needsAliasRebuild := false
	for _, auth := range auths {
		if !coreauth.IsConfigAPIKeyAuth(auth) {
			continue
		}
		prepared := s.prepareCoreAuthForModelRegistration(registrationCtx, auth)
		if prepared == nil {
			continue
		}
		needsAliasRebuild = true
		authForRegistration := prepared
		tasks = append(tasks, modelRegistrationTask{
			phase:    modelRegistrationPhaseConfigAPIKey,
			category: modelRegistrationCategory(authForRegistration),
			run: func(compatCache *openAICompatibilityRegistrationCache) {
				s.completeModelRegistrationForAuthWithCache(registrationCtx, authForRegistration, compatCache)
			},
		})
	}
	if needsAliasRebuild {
		s.coreManager.RefreshAPIKeyModelAlias()
	}
	s.runModelRegistrationTasks(registrationCtx, tasks)
}

func forceHomeRuntimeConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	if len(cfg.APIKeyPolicies) == 0 {
		cfg.APIKeys = nil
		cfg.WebsocketAuth = false
	}
	cfg.UsageStatisticsEnabled = true
	cfg.DisableCooling = true
	cfg.SaveCooldownStatus = false
	cfg.RemoteManagement.AllowRemote = false
	cfg.RemoteManagement.DisableControlPanel = true
	cfg.Plugins.StoreAuth = nil
}
