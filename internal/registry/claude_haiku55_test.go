package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const haiku55ID = "claude-haiku-5-5"

func findModel(models []*ModelInfo, id string) *ModelInfo {
	for _, m := range models {
		if m != nil && m.ID == id {
			return m
		}
	}
	return nil
}

func TestClaudeHaiku55_EmbeddedCatalog(t *testing.T) {
	m := findModel(GetClaudeModels(), haiku55ID)
	if m == nil {
		t.Fatalf("GetClaudeModels() lacks %s", haiku55ID)
	}
	if m.Type != "claude" || m.OwnedBy != "anthropic" || m.DisplayName != "Claude Haiku 5.5" {
		t.Fatalf("unexpected metadata: %+v", m)
	}
	if m.Thinking == nil || !m.Thinking.ZeroAllowed || !m.Thinking.DynamicAllowed || len(m.Thinking.Levels) == 0 {
		t.Fatalf("unexpected thinking support: %+v", m.Thinking)
	}
	if LookupStaticModelInfo(haiku55ID) == nil {
		t.Fatalf("LookupStaticModelInfo(%q) = nil", haiku55ID)
	}
	if LookupStaticModelInfoByChannel(haiku55ID, "claude") == nil {
		t.Fatalf("LookupStaticModelInfoByChannel(%q, claude) = nil", haiku55ID)
	}
}

// refreshFromRemoteCatalog serves catalog as the remote models.json and runs the
// same refresh path the startup and periodic updater use.
func refreshFromRemoteCatalog(t *testing.T, catalog *staticModelsJSON) {
	t.Helper()
	body, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	oldURLs := modelsURLs
	oldData := getModels()
	refreshCallbackMu.Lock()
	oldPending := pendingRefreshChanges
	refreshCallbackMu.Unlock()
	t.Cleanup(func() {
		modelsURLs = oldURLs
		modelsCatalogStore.mu.Lock()
		modelsCatalogStore.data = oldData
		modelsCatalogStore.mu.Unlock()
		refreshCallbackMu.Lock()
		pendingRefreshChanges = oldPending
		refreshCallbackMu.Unlock()
	})

	modelsURLs = []string{srv.URL}
	tryRefreshModels(context.Background(), "test refresh")
}

func embeddedCatalog(t *testing.T) *staticModelsJSON {
	t.Helper()
	var catalog staticModelsJSON
	if err := json.Unmarshal(embeddedModelsJSON, &catalog); err != nil {
		t.Fatal(err)
	}
	return &catalog
}

func TestClaudeHaiku55_SurvivesRemoteRefreshWithoutIt(t *testing.T) {
	remote := embeddedCatalog(t)
	claude := make([]*ModelInfo, 0, len(remote.Claude))
	for _, m := range remote.Claude {
		if m.ID != haiku55ID {
			claude = append(claude, m)
		}
	}
	remote.Claude = claude

	refreshFromRemoteCatalog(t, remote)

	if findModel(GetClaudeModels(), haiku55ID) == nil {
		t.Fatalf("remote refresh dropped %s from GetClaudeModels()", haiku55ID)
	}
	if LookupStaticModelInfo(haiku55ID) == nil {
		t.Fatalf("remote refresh dropped %s from LookupStaticModelInfo", haiku55ID)
	}
}

func TestClaudeHaiku55_UpstreamEntryWins(t *testing.T) {
	remote := embeddedCatalog(t)
	claude := make([]*ModelInfo, 0, len(remote.Claude))
	for _, m := range remote.Claude {
		if m.ID != haiku55ID {
			claude = append(claude, m)
		}
	}
	remote.Claude = append(claude, &ModelInfo{
		ID:                  haiku55ID,
		Object:              "model",
		OwnedBy:             "anthropic",
		Type:                "claude",
		DisplayName:         "Claude Haiku 5.5 (upstream)",
		ContextLength:       1000000,
		MaxCompletionTokens: 128000,
	})

	refreshFromRemoteCatalog(t, remote)

	count := 0
	for _, m := range GetClaudeModels() {
		if m.ID == haiku55ID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%s appears %d times, want 1", haiku55ID, count)
	}
	m := LookupStaticModelInfoByChannel(haiku55ID, "claude")
	if m == nil || m.DisplayName != "Claude Haiku 5.5 (upstream)" || m.ContextLength != 1000000 {
		t.Fatalf("upstream entry was overwritten: %+v", m)
	}
}
