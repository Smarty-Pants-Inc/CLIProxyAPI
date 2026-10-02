package config

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Supporting invariants for the end-to-end reload regressions: process-only
// history is deeply copied, never serialized, and carries warning suppression.
func TestR3PolicyReloadSnapshotInvariants(t *testing.T) {
	key := t.Name()
	models := []string{"model"}
	cap := int64(10)
	original := &Config{SDKConfig: SDKConfig{APIKeys: []string{key}, APIKeyPolicies: []APIKeyPolicy{{KeySHA256: APIKeyDigest(key), AllowedAuths: []string{"A"}, AllowedModels: &models, DailyRequestCap: &cap}}}, WebsocketAuth: true}
	before := original.CloneForRuntime()
	if initial := PreserveAPIKeyPolicies(nil, original); initial != original || initial.PolicyReloadState != nil {
		t.Fatal("unchanged config identity changed")
	}
	next := original.CloneForRuntime()
	next.APIKeyPolicies = nil
	requested := next.CloneForRuntime()
	var warnings bytes.Buffer
	prior := log.StandardLogger().Out
	log.SetOutput(&warnings)
	defer log.SetOutput(prior)
	effective := PreserveAPIKeyPolicies(original, next)
	if effective == original || effective == next || !reflect.DeepEqual(original, before) || !reflect.DeepEqual(next, requested) {
		t.Fatal("helper mutated/returned input during denied policy change")
	}
	clone := effective.CloneForRuntime()
	state := clone.PolicyReloadState[APIKeyDigest(key)]
	state.Policy.AllowedAuths[0] = "B"
	(*state.Policy.AllowedModels)[0] = "changed"
	*state.Policy.DailyRequestCap = 0
	state.Warned = false
	clone.PolicyReloadState[APIKeyDigest(key)] = state
	kept := effective.PolicyReloadState[APIKeyDigest(key)]
	if !kept.Warned || kept.Policy.AllowedAuths[0] != "A" || (*kept.Policy.AllowedModels)[0] != "model" || *kept.Policy.DailyRequestCap != 10 {
		t.Fatal("runtime history shared nested references")
	}
	(*effective.APIKeyPolicies[0].AllowedModels)[0] = "effective-model"
	if (*original.APIKeyPolicies[0].AllowedModels)[0] != "model" {
		t.Fatal("effective policy shared input nested references")
	}
	(*effective.APIKeyPolicies[0].AllowedModels)[0] = "model"
	again := PreserveAPIKeyPolicies(effective, next)
	downstream := PreserveAPIKeyPolicies(original, effective)
	rejected := RetainAPIKeyPolicyWarnings(original, effective)
	_ = PreserveAPIKeyPolicies(rejected, next)
	if strings.Count(warnings.String(), "client-key policy change for "+APIKeyDigest(key)+" takes effect on restart") != 1 {
		t.Fatalf("repeated fixed warning: %s", warnings.String())
	}
	if !reflect.DeepEqual(again.APIKeyPolicies, original.APIKeyPolicies) || !reflect.DeepEqual(downstream.APIKeyPolicies, original.APIKeyPolicies) {
		t.Fatal("warning transfer relaxed policy")
	}
	rawJSON, err := json.Marshal(effective)
	if err != nil {
		t.Fatal(err)
	}
	rawYAML, err := yaml.Marshal(effective)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{rawJSON, rawYAML} {
		if bytes.Contains(raw, []byte("PolicyReloadState")) || bytes.Contains(raw, []byte("Warned")) || bytes.Contains(raw, []byte("Policy:")) {
			t.Fatal("runtime marker serialized")
		}
	}
	var restarted Config
	if err := yaml.Unmarshal(rawYAML, &restarted); err != nil {
		t.Fatal(err)
	}
	if restarted.PolicyReloadState != nil {
		t.Fatal("runtime history persisted across restart")
	}
}
