package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Keep these tests at the config trust boundary: malformed restrictions must
// fail before startup, SDK publication, persistence or hot reload can use them.
func TestAPIKeyRoutesValidation(t *testing.T) {
	const key = "synthetic-route-client"
	digest := APIKeyDigest(key)
	valid := APIKeyRoute{KeySHA256: digest, Allow: []string{"GET /v1/models", "/v1/live"}}
	for _, tc := range []struct {
		name   string
		routes []APIKeyRoute
		bad    bool
	}{
		{"absent", nil, false},
		{"empty", []APIKeyRoute{}, false},
		{"valid", []APIKeyRoute{valid}, false},
		{"empty digest", []APIKeyRoute{{Allow: valid.Allow}}, true},
		{"short digest", []APIKeyRoute{{KeySHA256: "abcd", Allow: valid.Allow}}, true},
		{"nonhex digest", []APIKeyRoute{{KeySHA256: strings.Repeat("g", 64), Allow: valid.Allow}}, true},
		{"uppercase digest", []APIKeyRoute{{KeySHA256: strings.ToUpper(digest), Allow: valid.Allow}}, true},
		{"padded digest", []APIKeyRoute{{KeySHA256: " " + digest, Allow: valid.Allow}}, true},
		{"unknown digest", []APIKeyRoute{{KeySHA256: APIKeyDigest("other-synthetic-key"), Allow: valid.Allow}}, true},
		{"duplicate digest", []APIKeyRoute{valid, valid}, true},
		{"nil allow", []APIKeyRoute{{KeySHA256: digest}}, true},
		{"empty allow", []APIKeyRoute{{KeySHA256: digest, Allow: []string{}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{SDKConfig: SDKConfig{APIKeys: []string{" \t" + key + "\n"}, APIKeyRoutes: tc.routes}}
			for name, validate := range map[string]func() error{
				"routes":                 cfg.ValidateAPIKeyRoutes,
				"existing SDK validator": cfg.ValidateAPIKeyPolicies,
			} {
				if err := validate(); (err != nil) != tc.bad {
					t.Errorf("%s error = %v, want invalid=%t", name, err, tc.bad)
				}
			}
		})
	}
}

func TestAPIKeyRoutesAllowSyntax(t *testing.T) {
	valid := []string{
		"/", "/v1/live", "/v1/live/", "/v1/live///", "/v1beta/models/gemini:generateContent",
		"GET /v1/models", "HEAD /v1/models", "POST /v1/live", "PUT /v1/live",
		"PATCH /v1/live", "DELETE /v1/live", "OPTIONS /v1/live", "CONNECT /v1/live", "TRACE /v1/live",
	}
	invalid := []string{
		"", " ", "v1/live", "GET", "GET v1/live", "get /v1/live", "BOGUS /v1/live",
		"* /v1/live", "GET,POST /v1/live", "GET  /v1/live", " GET /v1/live", "GET /v1/live ",
		"GET\t/v1/live", "GET\n/v1/live", "/v1/ live", "/v1/\tlive", "/v1/\nlive", "/v1/\u00a0live",
		"/v1/\x00live", "/v1/\x7flive", "/v1/*", "/v1/li*ve", "/v1/live?", "/v1/live?x=1",
		"/v1/live#", "/v1/live#fragment", "https://example.invalid/v1/live", "//example.invalid/v1/live",
		"/v1\\live", "/v1/%", "/v1/%zz", "/v1/%20live", "/v1/%0alive", "/v1/%2alive",
	}
	for _, entry := range valid {
		t.Run("valid "+entry, func(t *testing.T) {
			cfg := &Config{SDKConfig: SDKConfig{APIKeys: []string{"synthetic-client"}, APIKeyRoutes: []APIKeyRoute{{KeySHA256: APIKeyDigest("synthetic-client"), Allow: []string{entry}}}}}
			if err := cfg.ValidateAPIKeyRoutes(); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, entry := range invalid {
		t.Run("invalid "+entry, func(t *testing.T) {
			cfg := &Config{SDKConfig: SDKConfig{APIKeys: []string{"synthetic-client"}, APIKeyRoutes: []APIKeyRoute{{KeySHA256: APIKeyDigest("synthetic-client"), Allow: []string{entry}}}}}
			if err := cfg.ValidateAPIKeyRoutes(); err == nil {
				t.Fatal("invalid allow entry accepted")
			}
			if cfg.APIKeyRoutes[0].Matches("GET", "/v1/live") {
				t.Fatal("invalid allow entry matched a request")
			}
		})
	}
}

func TestAPIKeyRouteMatches(t *testing.T) {
	route := APIKeyRoute{Allow: []string{"GET /v1/models/", "/v1/live"}}
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{"GET", "/v1/models", true}, {"GET", "/v1/models/", true}, {"GET", "/v1/models///", true},
		{"HEAD", "/v1/models", false}, {"POST", "/v1/models", false}, {"get", "/v1/models", false},
		{"GET", "/v1/models/child", false}, {"GET", "/v1/models-extra", false}, {"GET", "/V1/models", false},
		{"GET", "/v1/live", true}, {"POST", "/v1/live/", true}, {"CUSTOM", "/v1/live", true},
		{"GET", "/v1/live/child", false}, {"GET", "/v1/live?x=1", false}, {"GET", "/v1/live#fragment", false},
		{"GET", "https://example.invalid/v1/live", false}, {"GET", "//v1/live", false},
		{"GET", "/v1/./live", false}, {"GET", "/v1/other/../live", false}, {"GET", "/v1/%6cive", false},
		{"GET", "", false}, {"GET", "/", false},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			if got := route.Matches(tc.method, tc.path); got != tc.want {
				t.Fatalf("Matches() = %t, want %t", got, tc.want)
			}
		})
	}
	if !(APIKeyRoute{Allow: []string{"/"}}).Matches("POST", "/") {
		t.Fatal("root path did not match")
	}
	if (APIKeyRoute{}).Matches("GET", "/v1/live") {
		t.Fatal("empty allow list matched")
	}
}

func TestAPIKeyRoutesIndependentOfPolicies(t *testing.T) {
	cfg := &Config{SDKConfig: SDKConfig{
		APIKeys: []string{"synthetic-client"}, APIKeyRoutes: []APIKeyRoute{{KeySHA256: APIKeyDigest("synthetic-client"), Allow: []string{"/v1/live"}}},
	}}
	cfg.Plugins.Enabled = true
	cfg.Home.Enabled = true
	cfg.WebsocketAuth = false
	if err := cfg.ValidateAPIKeyPolicies(); err != nil {
		t.Fatalf("route-only config inherited policy prohibitions: %v", err)
	}
	cfg.Plugins.Enabled, cfg.Home.Enabled, cfg.WebsocketAuth = false, false, true
	cfg.APIKeyPolicies = []APIKeyPolicy{{KeySHA256: APIKeyDigest("synthetic-client"), AllowedAuths: []string{}}}
	if err := cfg.ValidateAPIKeyPolicies(); err != nil {
		t.Fatalf("route and policy for the same key did not compose: %v", err)
	}
	previous := cfg.CloneForRuntime()
	cfg.APIKeyRoutes[0].Allow = []string{"GET /v1/models"}
	effective := PreserveAPIKeyPolicies(previous, cfg)
	if !reflect.DeepEqual(effective.APIKeyRoutes, cfg.APIKeyRoutes) {
		t.Fatal("policy reload preservation froze route changes")
	}
}

func TestAPIKeyRoutesValidationEntrypoints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	invalid := []byte("access: {api-keys: [synthetic-client], api-key-routes: [{key-sha256: bad, allow: ['/v1/live']}] }\n")
	if err := os.WriteFile(path, invalid, 0600); err != nil {
		t.Fatal(err)
	}
	for name, validate := range map[string]func() error{
		"parse":         func() error { _, err := ParseConfigBytes(invalid); return err },
		"load":          func() error { _, err := LoadConfig(path); return err },
		"load optional": func() error { _, err := LoadConfigOptional(path, true); return err },
		"load snapshot": func() error { _, err := LoadConfigBytes(invalid, path, false); return err },
		"strict v8":     func() error { return ValidateV8Config(invalid) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := validate(); err == nil || !strings.Contains(err.Error(), "api-key-routes") {
				t.Fatalf("invalid routes bypassed validator: %v", err)
			}
		})
	}
	valid := []byte("access: {api-keys: [synthetic-client]}\n")
	if err := os.WriteFile(path, valid, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.APIKeyRoutes = []APIKeyRoute{{KeySHA256: "bad", Allow: []string{"/v1/live"}}}
	if err = SaveConfigPreserveComments(path, cfg); err == nil {
		t.Fatal("save accepted invalid route restrictions")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(valid) {
		t.Fatalf("invalid save mutated source: %v", err)
	}
}

func TestAPIKeyRoutesParseCompatibility(t *testing.T) {
	digest := APIKeyDigest("synthetic-client")
	routes := fmt.Sprintf("[{key-sha256: %s, allow: ['GET /v1/models', '/v1/live']}]", digest)
	for _, tc := range []struct {
		name, raw string
		want      int
	}{
		{"legacy", "api-keys: [synthetic-client]\napi-key-routes: " + routes + "\n", 1},
		{"v8", "config-version: 8\naccess: {api-keys: [synthetic-client], api-key-routes: " + routes + "}\n", 1},
		{"mixed old routes", "access: {api-keys: [synthetic-client]}\napi-key-routes: " + routes + "\n", 1},
		{"canonical wins", "api-key-routes: [{key-sha256: bad}]\naccess: {api-keys: [synthetic-client], api-key-routes: " + routes + "}\n", 1},
		{"canonical empty wins", "api-key-routes: [{key-sha256: bad}]\naccess: {api-keys: [synthetic-client], api-key-routes: []}\n", 0},
		{"canonical null wins", "api-key-routes: [{key-sha256: bad}]\naccess: {api-keys: [synthetic-client], api-key-routes: null}\n", 0},
		{"plugins and ws bypass", "plugins: {enabled: true, dir: " + fmt.Sprintf("%q", t.TempDir()) + "}\nws-auth: false\naccess: {api-keys: [synthetic-client], api-key-routes: " + routes + "}\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseConfigBytes([]byte(tc.raw))
			if err != nil || len(cfg.APIKeyRoutes) != tc.want {
				t.Fatalf("parse route count, err = %v, %v", cfg, err)
			}
			if tc.want > 0 && (!cfg.APIKeyRoutes[0].Matches("GET", "/v1/models") || cfg.APIKeyRoutes[0].Matches("POST", "/v1/models")) {
				t.Fatal("parsed route semantics changed")
			}
		})
	}
	for _, raw := range []string{
		"access: {api-keys: [synthetic-client], api-key-routes: " + routes + "}\n---\n{}\n",
		"api-keys: [synthetic-client]\n\"api-key-rout\\u0065s\": [{key-sha256: bad}]\n",
		"access: {api-keys: [synthetic-client], api-key-routes: " + routes + ", api-key-routes: []}\n",
	} {
		if _, err := ParseConfigBytes([]byte(raw)); err == nil {
			t.Fatal("malformed YAML bypassed route validation")
		}
	}
}

func TestAPIKeyRoutesSaveRoundTrip(t *testing.T) {
	for _, layout := range []string{"legacy", "v8", "migrate", "mixed"} {
		for _, empty := range []string{"nil", "empty"} {
			t.Run(layout+"/"+empty, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "config.yaml")
				raw := []byte("# retained comment\napi-keys: [synthetic-client]\n")
				if layout == "v8" || layout == "mixed" {
					raw = []byte("# retained comment\nconfig-version: 8\naccess: {api-keys: [synthetic-client]}\n")
				}
				if layout == "mixed" {
					raw = append(raw, []byte(fmt.Sprintf("api-key-routes: [{key-sha256: %s, allow: ['/old-route']}]\n", APIKeyDigest("synthetic-client")))...)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				cfg, err := LoadConfig(path)
				if err != nil {
					t.Fatal(err)
				}
				want := []APIKeyRoute{{KeySHA256: APIKeyDigest("synthetic-client"), Allow: []string{"GET /v1/models", "/v1/live"}}}
				cfg.APIKeyRoutes = want
				for _, phase := range []string{"add", "change", "remove", "readd"} {
					switch phase {
					case "change":
						cfg.APIKeyRoutes[0].Allow = []string{"POST /v1/live/"}
					case "remove":
						cfg.APIKeyRoutes = nil
						if empty == "empty" {
							cfg.APIKeyRoutes = []APIKeyRoute{}
						}
					case "readd":
						cfg.APIKeyRoutes = want
					}
					if err = SaveConfigPreserveComments(path, cfg, layout == "migrate"); err != nil {
						t.Fatalf("%s save: %v", phase, err)
					}
					loaded, errLoad := LoadConfig(path)
					if errLoad != nil || (len(cfg.APIKeyRoutes) != 0 && !reflect.DeepEqual(loaded.APIKeyRoutes, cfg.APIKeyRoutes)) || (len(cfg.APIKeyRoutes) == 0 && len(loaded.APIKeyRoutes) != 0) {
						t.Fatalf("%s routes failed roundtrip: %v", phase, errLoad)
					}
					published, errRead := os.ReadFile(path)
					if errRead != nil {
						t.Fatal(errRead)
					}
					if !strings.Contains(string(published), "retained comment") {
						t.Fatal("unrelated comment lost")
					}
					var doc yaml.Node
					if err = yaml.Unmarshal(published, &doc); err != nil {
						t.Fatal(err)
					}
					field := "api-key-routes"
					if layout != "legacy" {
						field = "access.api-key-routes"
						if err = ValidateV8Config(published); err != nil || yamlPath(doc.Content[0], "api-key-routes") != nil {
							t.Fatalf("%s not canonical v8: %v", phase, err)
						}
					}
					if present := yamlPath(doc.Content[0], field) != nil; present != (phase != "remove") {
						t.Fatalf("%s: route presence = %t", phase, present)
					}
					cfg = loaded
				}
			})
		}
	}
}

func TestAPIKeyRoutesCloneAndWireSnapshot(t *testing.T) {
	cfg := &Config{SDKConfig: SDKConfig{APIKeys: []string{"synthetic-client"}, APIKeyRoutes: []APIKeyRoute{{KeySHA256: APIKeyDigest("synthetic-client"), Allow: []string{"GET /v1/models", "/v1/live"}}}}}
	cloned := cfg.CloneForRuntime()
	cloned.APIKeyRoutes[0].Allow[0] = "POST /changed"
	cloned.APIKeyRoutes[0].KeySHA256 = "changed"
	cloned.APIKeyRoutes = append(cloned.APIKeyRoutes, APIKeyRoute{})
	if cfg.APIKeyRoutes[0].Allow[0] != "GET /v1/models" || cfg.APIKeyRoutes[0].KeySHA256 != APIKeyDigest("synthetic-client") || len(cfg.APIKeyRoutes) != 1 {
		t.Fatal("runtime clone shared mutable route config")
	}
	for name, roundtrip := range map[string]func() (*Config, error){
		"yaml": func() (*Config, error) {
			data, err := yaml.Marshal(cfg)
			if err != nil {
				return nil, err
			}
			var got Config
			err = yaml.Unmarshal(data, &got)
			return &got, err
		},
		"json": func() (*Config, error) {
			data, err := json.Marshal(cfg)
			if err != nil {
				return nil, err
			}
			var got Config
			err = json.Unmarshal(data, &got)
			return &got, err
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := roundtrip()
			if err != nil || !reflect.DeepEqual(got.APIKeyRoutes, cfg.APIKeyRoutes) {
				t.Fatalf("snapshot lost routes: %v", err)
			}
		})
	}
}
