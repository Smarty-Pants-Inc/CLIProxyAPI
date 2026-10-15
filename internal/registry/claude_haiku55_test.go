package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
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
	sonnet := findModel(GetClaudeModels(), "claude-sonnet-5-5")
	if sonnet == nil || m.ContextLength != sonnet.ContextLength || m.MaxCompletionTokens != sonnet.MaxCompletionTokens || !reflect.DeepEqual(m.Thinking, sonnet.Thinking) {
		t.Fatalf("Haiku 5.5 limits/thinking differ from Sonnet 5.5: haiku=%+v sonnet=%+v", m, sonnet)
	}
	if LookupStaticModelInfo(haiku55ID) == nil {
		t.Fatalf("LookupStaticModelInfo(%q) = nil", haiku55ID)
	}
	if LookupStaticModelInfoByChannel(haiku55ID, "claude") == nil {
		t.Fatalf("LookupStaticModelInfoByChannel(%q, claude) = nil", haiku55ID)
	}
}

func TestClaudeHaiku55_ListedForRegisteredClaudeAuth(t *testing.T) {
	reg := newTestModelRegistry()
	const clientID = "test-haiku55-auth"
	reg.RegisterClient(clientID, "claude", GetClaudeModels())
	if findModel(reg.GetModelsForClient(clientID), haiku55ID) == nil {
		t.Fatalf("auth model list lacks %s", haiku55ID)
	}
	for _, format := range []string{"claude", "openai"} {
		found := false
		for _, model := range reg.GetAvailableModels(format) {
			if model["id"] == haiku55ID {
				found = true
			}
		}
		if !found {
			t.Errorf("%s model list lacks %s", format, haiku55ID)
		} else {
			t.Logf("%s model list includes %s", format, haiku55ID)
		}
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

	oldData := getModels()
	refreshCallbackMu.Lock()
	oldPending := pendingRefreshChanges
	refreshCallbackMu.Unlock()
	t.Cleanup(func() {
		modelsCatalogStore.mu.Lock()
		modelsCatalogStore.data = oldData
		modelsCatalogStore.mu.Unlock()
		refreshCallbackMu.Lock()
		pendingRefreshChanges = oldPending
		refreshCallbackMu.Unlock()
	})

	updater := &catalogUpdater{
		fetch:   catalogFetcher(embeddedModelsJSON, []string{srv.URL}, validateCatalogBytes),
		publish: publishCatalogBytes,
	}
	updater.refresh(context.Background(), "", 0)
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
	sonnet := findModel(remote.Claude, "claude-sonnet-5-5")
	if sonnet == nil {
		t.Fatal("remote fixture lacks Sonnet 5.5")
	}
	sonnet.DisplayName = "Sonnet from remote refresh"

	refreshFromRemoteCatalog(t, remote)

	refreshedSonnet := findModel(GetClaudeModels(), sonnet.ID)
	if refreshedSonnet == nil || refreshedSonnet.DisplayName != sonnet.DisplayName {
		t.Fatal("remote catalog was not published")
	}
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
