package claude

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// CredentialFileName returns the filename used to persist Claude OAuth credentials.
// The organization hash is preferred to keep organizations with the same email
// distinct. The account hash is used when no organization is available, and the
// legacy email-based format remains the fallback.
func CredentialFileName(email, organizationUUID, accountUUID string) string {
	email = strings.TrimSpace(email)
	identity := strings.TrimSpace(organizationUUID)
	if identity == "" {
		identity = strings.TrimSpace(accountUUID)
	}
	if identity == "" {
		return fmt.Sprintf("claude-%s.json", email)
	}

	digest := sha256.Sum256([]byte(identity))
	identityHash := hex.EncodeToString(digest[:])[:8]
	return fmt.Sprintf("claude-%s-%s.json", identityHash, email)
}

// FindMatchingLegacyCredential locates a prior filename for the same Claude
// identity as target. In addition to the email-only legacy name, an
// account-hashed name can precede an organization-hashed target when an earlier
// login did not return organization identity.
func FindMatchingLegacyCredential(ctx context.Context, store coreauth.Store, target *coreauth.Auth) (*coreauth.Auth, error) {
	if store == nil || !isHashedCredentialTarget(target) {
		return nil, nil
	}

	records, errList := store.List(ctx)
	if errList != nil {
		if errors.Is(errList, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("list Claude credentials for legacy migration: %w", errList)
	}

	targetEmail := strings.TrimSpace(target.MetadataString("email"))
	targetOrganization := strings.TrimSpace(target.MetadataString("organization_uuid"))
	targetAccount := strings.TrimSpace(target.MetadataString("account_uuid"))
	legacyFileName := CredentialFileName(targetEmail, "", "")
	accountFileName := ""
	if targetOrganization != "" && targetAccount != "" {
		accountFileName = CredentialFileName(targetEmail, "", targetAccount)
	}

	for _, candidate := range records {
		if candidate == nil || !strings.EqualFold(strings.TrimSpace(candidate.Provider), "claude") {
			continue
		}
		candidateFileName := strings.TrimSpace(candidate.FileName)
		if candidateFileName == "" {
			candidateFileName = strings.TrimSpace(candidate.ID)
		}
		candidateBaseName := filepath.Base(candidateFileName)
		isEmailLegacy := strings.EqualFold(candidateBaseName, legacyFileName)
		isAccountPredecessor := accountFileName != "" && strings.EqualFold(candidateBaseName, accountFileName)
		if !isEmailLegacy && !isAccountPredecessor {
			continue
		}

		candidateOrganization := strings.TrimSpace(candidate.MetadataString("organization_uuid"))
		candidateAccount := strings.TrimSpace(candidate.MetadataString("account_uuid"))
		switch {
		case targetOrganization != "":
			if candidateOrganization != "" && strings.EqualFold(candidateOrganization, targetOrganization) {
				return candidate, nil
			}
			if candidateOrganization == "" && isAccountPredecessor && candidateAccount != "" && strings.EqualFold(candidateAccount, targetAccount) {
				return candidate, nil
			}
		case isEmailLegacy && candidateOrganization == "" && targetAccount != "":
			if candidateAccount != "" && strings.EqualFold(candidateAccount, targetAccount) {
				return candidate, nil
			}
		}
	}

	return nil, nil
}

func isHashedCredentialTarget(target *coreauth.Auth) bool {
	if target == nil || !strings.EqualFold(strings.TrimSpace(target.Provider), "claude") {
		return false
	}
	email := strings.TrimSpace(target.MetadataString("email"))
	organizationUUID := strings.TrimSpace(target.MetadataString("organization_uuid"))
	accountUUID := strings.TrimSpace(target.MetadataString("account_uuid"))
	if email == "" || (organizationUUID == "" && accountUUID == "") {
		return false
	}
	targetFileName := strings.TrimSpace(target.FileName)
	if targetFileName == "" {
		targetFileName = strings.TrimSpace(target.ID)
	}
	return strings.EqualFold(filepath.Base(targetFileName), CredentialFileName(email, organizationUUID, accountUUID))
}

func metadataString(metadata map[string]any, key string) string {
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}
