package config

import (
	"reflect"
	"testing"
)

func TestPreserveAPIKeyPoliciesFreezesPoolTopologyWithoutFreezingOtherConfig(t *testing.T) {
	capOne := int64(1)
	capTwo := int64(2)
	key := "pool-client"
	policy := APIKeyPolicy{KeySHA256: APIKeyDigest(key), Pool: "pool"}
	previous := &Config{
		SDKConfig: SDKConfig{
			APIKeys:        []string{key},
			AccountPools:   &[]AccountPool{{ID: "pool", Org: "org", Class: PoolClassHuman, MaxInFlight: &capOne}},
			APIKeyPolicies: []APIKeyPolicy{policy},
		},
		Host:          "old-host",
		WebsocketAuth: true,
	}

	requested := previous.CloneForRuntime()
	requested.Host = "new-host"
	requested.AccountPools = &[]AccountPool{{ID: "pool", Org: "org", Class: PoolClassHuman, MaxInFlight: &capTwo}, {ID: "new", Org: "new", Class: PoolClassAgent, MaxInFlight: &capTwo}}

	effective := PreserveAPIKeyPolicies(previous, requested)
	if effective == requested {
		t.Fatal("pool topology change returned the unfrozen requested snapshot")
	}
	if effective.Host != "new-host" {
		t.Fatalf("unrelated host change was discarded: %q", effective.Host)
	}
	if !reflect.DeepEqual(effective.AccountPools, previous.AccountPools) {
		t.Fatalf("pool topology/capacity was not frozen: got=%+v want=%+v", effective.AccountPools, previous.AccountPools)
	}
	if !reflect.DeepEqual(effective.APIKeyPolicies, previous.APIKeyPolicies) {
		t.Fatalf("unchanged policies were not retained: got=%+v want=%+v", effective.APIKeyPolicies, previous.APIKeyPolicies)
	}

	disabled := previous.CloneForRuntime()
	disabled.AccountPools = nil
	disabled.Host = "disabled-request"
	effectiveDisabled := PreserveAPIKeyPolicies(previous, disabled)
	if effectiveDisabled.AccountPools == nil {
		t.Fatal("pool disable request was allowed before restart")
	}
	if effectiveDisabled.Host != "disabled-request" {
		t.Fatalf("unrelated host change on disable request was discarded: %q", effectiveDisabled.Host)
	}
}

func TestPreserveAPIKeyPoliciesUnchangedPoolsReturnRequestedSnapshot(t *testing.T) {
	capOne := int64(1)
	key := "pool-client"
	previous := &Config{
		SDKConfig: SDKConfig{
			APIKeys:        []string{key},
			AccountPools:   &[]AccountPool{{ID: "pool", Org: "org", Class: PoolClassAgent, MaxInFlight: &capOne}},
			APIKeyPolicies: []APIKeyPolicy{{KeySHA256: APIKeyDigest(key), Pool: "pool"}},
		},
		Host:          "old-host",
		WebsocketAuth: true,
	}
	requested := previous.CloneForRuntime()
	requested.Host = "new-host"

	effective := PreserveAPIKeyPolicies(previous, requested)
	if effective != requested {
		t.Fatal("unchanged pools/policies caused an unrelated config snapshot to be cloned")
	}
	if effective.Host != "new-host" {
		t.Fatalf("unrelated host change was lost: %q", effective.Host)
	}
}
