package live

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestClientSecretKnownNoKeyAttribution(t *testing.T) {
	store := newClientSecretStore()
	for _, known := range []bool{false, true} {
		var attribution [][]string
		if known {
			attribution = [][]string{nil}
		}
		token, created, _, err := store.create(json.RawMessage(`{"type":"realtime"}`), time.Minute, "mapped-account", "plugin:synthetic", attribution...)
		if err != nil {
			t.Fatal(err)
		}
		authorized, err := store.authenticate(token)
		if err != nil || created.IssuerRouteKeyAttributionKnown != known || authorized.IssuerRouteKeyAttributionKnown != known || len(authorized.IssuerRouteKeyDigests) != 0 {
			t.Fatalf("lost no-key/legacy distinction: created=%+v authorized=%+v err=%v", created, authorized, err)
		}
		encoded, err := json.Marshal(authorized)
		if err != nil || strings.Contains(string(encoded), "IssuerRoute") {
			t.Fatalf("internal attribution serialized: %s err=%v", encoded, err)
		}
	}
}

// Keep: delegated credential attribution must not alias caller-owned or returned slices.
func TestClientSecretRouteAttributionIsInternalAndImmutable(t *testing.T) {
	store := newClientSecretStore()
	digests := []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
	want := append([]string(nil), digests...)
	token, created, _, err := store.create(json.RawMessage(`{"type":"realtime"}`), time.Minute, "mapped-account", "plugin:synthetic", digests)
	if err != nil {
		t.Fatal(err)
	}
	digests[0] = "mutated-input"
	created.IssuerRouteKeyDigests[1] = "mutated-create-result"
	authorized, err := store.authenticate(token)
	if err != nil {
		t.Fatal(err)
	}
	if !authorized.IssuerRouteKeyAttributionKnown || authorized.IssuerPrincipal != "mapped-account" || authorized.IssuerProvider != "plugin:synthetic" || !reflect.DeepEqual(authorized.IssuerRouteKeyDigests, want) {
		t.Fatalf("issuer identity or attribution changed: %+v", authorized)
	}
	encoded, err := json.Marshal(authorized)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "IssuerRoute") || strings.Contains(string(encoded), want[0]) {
		t.Fatal("internal issuer attribution was serialized")
	}
	authorized.IssuerRouteKeyDigests[0] = "mutated-auth-result"
	again, err := store.authenticate(token)
	if err != nil || !reflect.DeepEqual(again.IssuerRouteKeyDigests, want) {
		t.Fatalf("authenticate leaked mutable attribution: %v %v", again.IssuerRouteKeyDigests, err)
	}
}
