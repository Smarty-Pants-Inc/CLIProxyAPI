package registry

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// Exercise the upstream publication barrier, not only the fork's merge helper.
func TestPublishCatalogBytesPreservesForkClaudeModels(t *testing.T) {
	previous := getModels()
	t.Cleanup(func() {
		modelsCatalogStore.mu.Lock()
		modelsCatalogStore.data = previous
		modelsCatalogStore.mu.Unlock()
	})
	var remote staticModelsJSON
	if errDecode := json.Unmarshal(embeddedModelsJSON, &remote); errDecode != nil {
		t.Fatal(errDecode)
	}
	remote.Claude = []*ModelInfo{{ID: "claude-opus-5-5", DisplayName: "remote wins"}}
	modelsCatalogStore.mu.Lock()
	modelsCatalogStore.data = &remote
	modelsCatalogStore.mu.Unlock()
	data, errEncode := json.Marshal(&remote)
	if errEncode != nil {
		t.Fatal(errEncode)
	}
	changed, errPublish := publishCatalogBytes(data)
	if errPublish != nil {
		t.Fatal(errPublish)
	}
	if !slices.Contains(changed, "claude") {
		t.Fatalf("fork restoration must participate in change detection: %v", changed)
	}
	if errValidate := validateModelsCatalog(getModels()); errValidate != nil {
		t.Fatalf("fork restoration produced an invalid catalog: %v", errValidate)
	}
	models := make(map[string]*ModelInfo)
	for _, model := range getModels().Claude {
		models[model.ID] = model
	}
	sonnet := models["claude-sonnet-5-5"]
	if sonnet == nil {
		t.Fatal("catalog publication dropped fork builtin claude-sonnet-5-5")
	}
	if sonnet.NativeCapabilities == nil || sonnet.NativeCapabilities.WebSearch == nil || !*sonnet.NativeCapabilities.WebSearch {
		t.Fatal("fork restoration lost Sonnet 5.5 native web search capability")
	}
	if model := models["claude-opus-5-5"]; model == nil || model.DisplayName != "remote wins" {
		t.Fatal("catalog publication overwrote a shared remote model")
	}
	changed, errPublish = publishCatalogBytes(data)
	if errPublish != nil || len(changed) != 0 {
		t.Fatalf("unchanged remote catalog must not repeatedly report fork restoration: changed=%v error=%v", changed, errPublish)
	}
}

func TestEmbeddedCatalogValidAndSonnet55Features(t *testing.T) {
	if errValidate := validateCatalogBytes(embeddedModelsJSON); errValidate != nil {
		t.Fatalf("embedded catalog is invalid: %v", errValidate)
	}
	var embedded staticModelsJSON
	if errDecode := json.Unmarshal(embeddedModelsJSON, &embedded); errDecode != nil {
		t.Fatal(errDecode)
	}
	var sonnet *ModelInfo
	count := 0
	for _, model := range embedded.Claude {
		if model.ID == "claude-sonnet-5-5" {
			sonnet = model
			count++
		}
	}
	if count != 1 {
		t.Fatalf("embedded Sonnet 5.5 definitions = %d, want exactly one", count)
	}
	if sonnet.Object != "model" || sonnet.OwnedBy != "anthropic" || sonnet.Type != "claude" || sonnet.Created != 1790553600 || sonnet.DisplayName != "Claude Sonnet 5.5" {
		t.Fatalf("Sonnet 5.5 identity metadata changed: %+v", sonnet)
	}
	if sonnet.ContextLength != 1000000 || sonnet.MaxCompletionTokens != 128000 {
		t.Fatalf("Sonnet 5.5 token limits changed: %+v", sonnet)
	}
	if sonnet.Thinking == nil || !sonnet.Thinking.ZeroAllowed || !sonnet.Thinking.DynamicAllowed || !slices.Equal(sonnet.Thinking.Levels, []string{"low", "medium", "high", "xhigh", "max"}) {
		t.Fatalf("Sonnet 5.5 thinking support changed: %+v", sonnet.Thinking)
	}
	if !slices.Equal(sonnet.SupportedInputModalities, []string{"text", "image"}) || !slices.Equal(sonnet.SupportedOutputModalities, []string{"text"}) {
		t.Fatal("Sonnet 5.5 modalities changed")
	}
	if sonnet.NativeCapabilities == nil || sonnet.NativeCapabilities.WebSearch == nil || !*sonnet.NativeCapabilities.WebSearch {
		t.Fatal("Sonnet 5.5 native web search capability missing")
	}
}

func TestPublishCatalogBytesRemoteSonnet55Wins(t *testing.T) {
	previous := getModels()
	t.Cleanup(func() {
		modelsCatalogStore.mu.Lock()
		modelsCatalogStore.data = previous
		modelsCatalogStore.mu.Unlock()
	})
	// An explicit remote capability denial must not be replaced by the builtin.
	data := []byte(`{"claude":[{"id":"claude-sonnet-5-5","display_name":"remote Sonnet","context_length":12345,"native_capabilities":{"web_search":false}}]}`)
	if _, errPublish := publishCatalogBytes(data); errPublish != nil {
		t.Fatal(errPublish)
	}
	if errValidate := validateModelsCatalog(getModels()); errValidate != nil {
		t.Fatalf("shared-ID publication produced an invalid catalog: %v", errValidate)
	}
	count := 0
	for _, model := range getModels().Claude {
		if model.ID != "claude-sonnet-5-5" {
			continue
		}
		count++
		if model.DisplayName != "remote Sonnet" || model.ContextLength != 12345 || model.NativeCapabilities == nil || model.NativeCapabilities.WebSearch == nil || *model.NativeCapabilities.WebSearch {
			t.Fatalf("embedded Sonnet overrode remote metadata: %+v", model)
		}
	}
	if count != 1 {
		t.Fatalf("published Sonnet 5.5 definitions = %d, want exactly one", count)
	}
}

func TestDuplicateClaudeCatalogRejectedWithoutPublication(t *testing.T) {
	previous := getModels()
	t.Cleanup(func() {
		modelsCatalogStore.mu.Lock()
		modelsCatalogStore.data = previous
		modelsCatalogStore.mu.Unlock()
	})
	data := []byte(`{"claude":[{"id":"claude-sonnet-5-5"},{"id":"claude-sonnet-5-5"}]}`)
	if errValidate := validateCatalogBytes(data); errValidate == nil || !strings.Contains(errValidate.Error(), "duplicate model id") {
		t.Fatalf("duplicate catalog validation = %v, want duplicate model id error", errValidate)
	}
	if errLoad := loadModelsFromBytes(data, "test"); errLoad == nil || !strings.Contains(errLoad.Error(), "duplicate model id") {
		t.Fatalf("duplicate catalog load = %v, want duplicate model id error", errLoad)
	}
	if changed, errPublish := publishCatalogBytes(data); errPublish == nil || !strings.Contains(errPublish.Error(), "duplicate model id") || len(changed) != 0 {
		t.Fatalf("duplicate catalog publication: changed=%v error=%v", changed, errPublish)
	}
	if getModels() != previous {
		t.Fatal("invalid catalog replaced the last valid catalog")
	}
}
