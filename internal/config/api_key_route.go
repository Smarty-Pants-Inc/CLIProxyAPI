package config

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

// APIKeyRoute restricts one configured client key to exact request paths.
// Allow entries are paths or "METHOD /path"; paths without a method allow all methods.
// Only trailing slashes are normalized. Prefixes and wildcards never match.
// Unlike APIKeyPolicy, routes support plugins/Home and do not require ws-auth.
type APIKeyRoute struct {
	KeySHA256 string   `yaml:"key-sha256" json:"key-sha256"`
	Allow     []string `yaml:"allow" json:"allow"`
}

// ValidateAPIKeyRoutes validates route restrictions independently of key policies.
func (cfg *Config) ValidateAPIKeyRoutes() error {
	keys := make(map[string]bool, len(cfg.APIKeys))
	for _, key := range cfg.APIKeys {
		keys[APIKeyDigest(key)] = true
	}
	seen := make(map[string]bool, len(cfg.APIKeyRoutes))
	for i, route := range cfg.APIKeyRoutes {
		digest, err := hex.DecodeString(route.KeySHA256)
		if err != nil || len(digest) != 32 || route.KeySHA256 != strings.ToLower(route.KeySHA256) || !keys[route.KeySHA256] || seen[route.KeySHA256] {
			return fmt.Errorf("api-key-routes[%d]: invalid, unconfigured or duplicate key-sha256", i)
		}
		seen[route.KeySHA256] = true
		if len(route.Allow) == 0 {
			return fmt.Errorf("api-key-routes[%d]: allow must not be empty", i)
		}
		for j, entry := range route.Allow {
			if _, _, ok := parseAPIKeyRoute(entry); !ok {
				// Never include the configured digest or route contents in errors/logs.
				return fmt.Errorf("api-key-routes[%d].allow[%d]: expected an exact path or uppercase HTTP method and path", i, j)
			}
		}
	}
	return nil
}

// Matches reports whether a request method and path are explicitly allowed.
// Methods and paths are case-sensitive; no path cleaning, decoding, prefix or
// implicit HEAD-to-GET matching is performed. Invalid allow entries fail closed.
func (route APIKeyRoute) Matches(method, path string) bool {
	if !validAPIKeyRoutePath(path) {
		return false
	}
	path = strings.TrimRight(path, "/")
	for _, entry := range route.Allow {
		allowedMethod, allowedPath, ok := parseAPIKeyRoute(entry)
		if ok && (allowedMethod == "" || allowedMethod == method) && strings.TrimRight(allowedPath, "/") == path {
			return true
		}
	}
	return false
}

func parseAPIKeyRoute(entry string) (method, path string, ok bool) {
	path = entry
	if before, after, found := strings.Cut(entry, " "); found {
		method, path = before, after
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
			http.MethodPatch, http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
		default:
			return "", "", false
		}
	}
	return method, path, validAPIKeyRoutePath(path)
}

func validAPIKeyRoutePath(path string) bool {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "*?#\\") || hasRouteWhitespaceOrControl(path) {
		return false
	}
	parsed, err := url.ParseRequestURI(path)
	return err == nil && !parsed.IsAbs() && parsed.Host == "" &&
		!strings.ContainsAny(parsed.Path, "*?#\\") && !hasRouteWhitespaceOrControl(parsed.Path)
}

func hasRouteWhitespaceOrControl(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0
}
