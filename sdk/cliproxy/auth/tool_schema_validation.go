package auth

import (
	"context"

	toolschema "github.com/router-for-me/CLIProxyAPI/v8/internal/client/codex/tool-schema"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Check both input copies before any translation, retry, policy dispatch or
// credential selection. Executors may translate OriginalRequest independently.
func validateClientToolSchemas(ctx context.Context, req ex.Request, opts ex.Options) error {
	if err := toolschema.ValidateCodexToolIntegerTypes(ctx, req.Payload, opts.Headers); err != nil {
		return err
	}
	if len(opts.OriginalRequest) != 0 {
		return toolschema.ValidateCodexToolIntegerTypes(ctx, opts.OriginalRequest, opts.Headers)
	}
	return nil
}
