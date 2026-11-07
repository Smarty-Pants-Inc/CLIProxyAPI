package helps

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	claudeauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func nativePoolIdentityError() error {
	return &cliproxyauth.Error{Code: "api_key_pool_identity_unverified", Message: "api_key_pool_identity_unverified", HTTPStatus: 503}
}

// CodexPoolIdentityFromTokenData must be called with material returned by the
// official native token service, never with persisted/JWT-file metadata.
func CodexPoolIdentityFromTokenData(td *codexauth.CodexTokenData) (cliproxyauth.NativePoolIdentity, error) {
	var identity cliproxyauth.NativePoolIdentity
	if td == nil || td.AccessToken == "" || td.IDToken == "" {
		return identity, nativePoolIdentityError()
	}
	claims, err := codexauth.ParseJWTToken(td.IDToken)
	if err != nil || claims == nil {
		return identity, nativePoolIdentityError()
	}
	identity = cliproxyauth.NativePoolIdentity{Provider: "codex", AccountID: claims.CodexAuthInfo.ChatgptUserID, EntitlementID: claims.CodexAuthInfo.ChatgptAccountID, AccountAliases: make(map[string]string)}
	if identity.AccountID == "" || identity.EntitlementID == "" || td.AccountID != identity.EntitlementID {
		return cliproxyauth.NativePoolIdentity{}, nativePoolIdentityError()
	}
	if claims.CodexAuthInfo.UserID != "" {
		identity.AccountAliases["user_id"] = claims.CodexAuthInfo.UserID
	}
	if claims.Sub != "" {
		identity.AccountAliases["sub"] = claims.Sub
	}
	return identity, nil
}

func AcquireCodexPoolIdentity(ctx context.Context, cfg *config.Config, a *cliproxyauth.Auth) (*cliproxyauth.Auth, cliproxyauth.NativePoolIdentity, error) {
	var zero cliproxyauth.NativePoolIdentity
	if a == nil || a.Provider != "codex" || a.AuthKind() != cliproxyauth.AuthKindOAuth || a.Attributes["api_key"] != "" || a.Attributes["base_url"] != "" || a.MetadataString("refresh_token") == "" {
		return nil, zero, nativePoolIdentityError()
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	service := codexauth.NewCodexAuthWithHTTPClient(cfg, NewNativePoolAcquisitionClient(cfg, a, "codex"), codexauth.TokenURL)
	td, err := service.RefreshTokens(ctx, a.MetadataString("refresh_token"))
	if err != nil {
		return nil, zero, nativePoolIdentityError()
	}
	identity, err := CodexPoolIdentityFromTokenData(td)
	if err != nil {
		return nil, zero, err
	}
	updated := a.Clone()
	updated.SetMetadata("access_token", td.AccessToken)
	updated.SetMetadata("id_token", td.IDToken)
	updated.SetMetadata("account_id", td.AccountID)
	if td.RefreshToken != "" {
		updated.SetMetadata("refresh_token", td.RefreshToken)
	}
	updated.SetMetadata("expired", td.Expire)
	updated.SetMetadata("last_refresh", time.Now().UTC().Format(time.RFC3339))
	return updated, identity, nil
}

func ClaudePoolIdentityFromProfile(profile *claudeauth.OAuthProfile) (cliproxyauth.NativePoolIdentity, error) {
	var zero cliproxyauth.NativePoolIdentity
	if profile == nil {
		return zero, nativePoolIdentityError()
	}
	a, errA := uuid.Parse(profile.Account.UUID)
	e, errE := uuid.Parse(profile.Organization.UUID)
	if errA != nil || errE != nil || a == uuid.Nil || e == uuid.Nil {
		return zero, nativePoolIdentityError()
	}
	return cliproxyauth.NativePoolIdentity{Provider: "claude", AccountID: a.String(), EntitlementID: e.String()}, nil
}

func AcquireClaudePoolIdentity(ctx context.Context, cfg *config.Config, a *cliproxyauth.Auth) (*cliproxyauth.Auth, cliproxyauth.NativePoolIdentity, error) {
	var zero cliproxyauth.NativePoolIdentity
	if a == nil || a.Provider != "claude" || a.AuthKind() != cliproxyauth.AuthKindOAuth || a.Attributes["api_key"] != "" || a.Attributes["base_url"] != "" {
		return nil, zero, nativePoolIdentityError()
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	service := claudeauth.NewClaudeAuthWithHTTPClient(cfg, NewNativePoolAcquisitionClient(cfg, a, "claude"))
	updated := a.Clone()
	token := claudeauth.ReadMetadataString(updated, "access_token")
	expiry, hasExpiry := updated.AccessTokenExpirationTime()
	if token == "" || (hasExpiry && !expiry.After(time.Now())) || (updated.RejectedAccessToken != "" && updated.RejectedAccessToken == token) {
		refresh := claudeauth.ReadMetadataString(updated, "refresh_token")
		if refresh == "" {
			return nil, zero, nativePoolIdentityError()
		}
		td, err := service.RefreshTokens(ctx, refresh)
		if err != nil || td == nil || td.AccessToken == "" {
			return nil, zero, nativePoolIdentityError()
		}
		token = td.AccessToken
		claudeauth.StoreMetadataString(updated, "access_token", token)
		if td.RefreshToken != "" {
			claudeauth.StoreMetadataString(updated, "refresh_token", td.RefreshToken)
		}
		claudeauth.StoreMetadataString(updated, "expired", td.Expire)
	}
	if token == "" {
		return nil, zero, nativePoolIdentityError()
	}
	// Always fetch a genuine profile for this exact token. Persisted UUIDs,
	// profile timestamps and legacy 403/synthetic fallbacks confer no authority.
	profile, err := service.FetchOAuthProfile(ctx, token)
	if err != nil {
		return nil, zero, nativePoolIdentityError()
	}
	identity, err := ClaudePoolIdentityFromProfile(profile)
	if err != nil {
		return nil, zero, fmt.Errorf("native Claude identity: %w", err)
	}
	claudeauth.StoreMetadataString(updated, "account_uuid", identity.AccountID)
	claudeauth.StoreMetadataString(updated, "organization_uuid", identity.EntitlementID)
	return updated, identity, nil
}
