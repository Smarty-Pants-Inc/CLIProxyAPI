package auth

import (
	"encoding/json"
	"reflect"
	"sync"
	"testing"
)

func TestAuthMetadataMethods(t *testing.T) {
	var absent *Auth
	if absent.MetadataString("string") != "" || absent.MetadataBool("bool") || absent.CloneMetadata() != nil {
		t.Fatal("nil receiver must have empty metadata")
	}
	if value, ok := absent.MetadataValue("missing"); ok || value != nil {
		t.Fatal("nil receiver reported a metadata entry")
	}
	absent.SetMetadata("key", "value")
	absent.WithMetadata(func(map[string]any) { t.Fatal("nil receiver invoked callback") })
	shared := &Auth{}
	NormalizeAuthMetadata(shared)
	shared.WithMetadata(nil)
	if shared.CloneMetadata() != nil {
		t.Fatal("normalization or nil callback initialized absent metadata")
	}
	shared.SetMetadata("string", "value")
	shared.SetMetadata("bool", true)
	shared.SetMetadata("nil", nil)
	if shared.MetadataString("string") != "value" || !shared.MetadataBool("bool") || shared.MetadataString("bool") != "" || shared.MetadataBool("string") {
		t.Fatal("typed metadata accessors did not preserve type semantics")
	}
	if value, ok := shared.MetadataValue("nil"); !ok || value != nil {
		t.Fatal("nil entry must remain distinguishable from absence")
	}
	for _, snapshot := range []map[string]any{shared.CloneMetadata(), shared.Clone().Metadata} {
		snapshot["string"] = "changed"
		if shared.MetadataString("string") != "value" {
			t.Fatal("snapshot aliases the live metadata map")
		}
	}
	clone := shared.Clone()
	clone.SetMetadata("string", "clone")
	if shared.MetadataString("string") != "value" {
		t.Fatal("clone writes changed the source credential")
	}
}

func TestAuthMetadataAtomicInitializationAndJSON(t *testing.T) {
	shared := &Auth{}
	const workers, iterations = 8, 128
	start := make(chan struct{})
	var group sync.WaitGroup
	for range workers {
		group.Go(func() {
			<-start
			for range iterations {
				shared.WithMetadata(func(metadata map[string]any) {
					count, _ := metadata["count"].(int)
					metadata["count"] = count + 1
				})
			}
		})
	}
	group.Go(func() {
		<-start
		for range iterations {
			if _, errMarshal := json.Marshal(shared); errMarshal != nil {
				t.Errorf("marshal shared credential: %v", errMarshal)
			}
			_ = shared.Clone()
		}
	})
	close(start)
	group.Wait()
	if count, _ := shared.MetadataValue("count"); count != workers*iterations {
		t.Fatalf("atomic count = %v, want %d", count, workers*iterations)
	}
}

func TestAuthClonePreservesFieldsWithoutCopyingLock(t *testing.T) {
	// Populate every field mechanically, so adding a scalar field without updating
	// Clone cannot silently drop it. Maps have separate behavioral coverage above.
	source := &Auth{}
	value := reflect.ValueOf(source).Elem()
	for i := range value.NumField() {
		field := value.Field(i)
		if !field.CanSet() {
			continue
		}
		switch field.Kind() {
		case reflect.String:
			field.SetString(value.Type().Field(i).Name)
		case reflect.Bool:
			field.SetBool(true)
		case reflect.Uint64:
			field.SetUint(123)
		case reflect.Int, reflect.Int64:
			field.SetInt(123)
		}
	}
	cloned := reflect.ValueOf(source.Clone()).Elem()
	for i := range value.NumField() {
		if value.Type().Field(i).Name == "metadataMu" || !value.Field(i).CanInterface() {
			continue
		}
		if !reflect.DeepEqual(value.Field(i).Interface(), cloned.Field(i).Interface()) {
			t.Errorf("Clone dropped field %s", value.Type().Field(i).Name)
		}
	}
}
