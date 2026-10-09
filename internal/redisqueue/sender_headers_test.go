package redisqueue

import (
	"context"
	"net/http"
	"testing"

	internallogging "github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	coreusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

// smarty-dev#6207: the usage record carries role, agent and spawner next to session_id,
// and omits a sender field that the request did not supply.
func TestUsageQueuePluginPayloadIncludesSenderNames(t *testing.T) {
	withEnabledQueue(t, func() {
		ctx := internallogging.WithRequestID(context.Background(), "ctx-sender-1")
		ctx = internallogging.WithClientRequestMetadata(ctx, internallogging.ClientRequestMetadata{
			SessionID:     "routing-session",
			SenderRole:    "task-agent",
			SenderSpawner: "session:01a0ec99-ec1c-7467-89ea-f470939c722e",
		})
		ctx = internallogging.WithResponseStatusHolder(ctx)
		internallogging.SetResponseStatus(ctx, http.StatusOK)

		(&usageQueuePlugin{}).HandleUsage(ctx, coreusage.Record{Provider: "openai", Model: "gpt-5.6-sol"})

		payload := popSinglePayload(t)
		requireStringField(t, payload, "role", "task-agent")
		requireStringField(t, payload, "spawner", "session:01a0ec99-ec1c-7467-89ea-f470939c722e")
		if _, ok := payload["session_id"]; !ok {
			t.Fatalf("payload missing session_id")
		}
		if raw, ok := payload["agent"]; ok {
			t.Fatalf("agent = %s, want omitted when unknown", raw)
		}
	})
}
