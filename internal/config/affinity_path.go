package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveSessionAffinityStateDir returns the canonical state directory without
// creating it. Runtime state must never be stored in or beneath the auth directory,
// even when affinity is currently disabled or Home owns routing.
func (cfg *Config) ResolveSessionAffinityStateDir() (string, error) {
	dir := strings.TrimSpace(cfg.Routing.SessionAffinityStateDir)
	if dir == "" {
		base := strings.TrimSpace(os.Getenv("XDG_STATE_HOME"))
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("routing.session-affinity-state-dir: %w", err)
			}
			base = filepath.Join(home, ".local", "state")
		}
		dir = filepath.Join(base, "cliproxyapi")
	}
	stateDir, err := canonicalAffinityDirectory(dir)
	if err != nil {
		return "", fmt.Errorf("routing.session-affinity-state-dir: %w", err)
	}
	authDir := strings.TrimSpace(cfg.AuthDir)
	if authDir == "" {
		authDir = DefaultAuthDir
	}
	authDir, err = canonicalAffinityDirectory(authDir)
	if err != nil {
		return "", fmt.Errorf("routing.session-affinity-state-dir: resolve auth-dir: %w", err)
	}
	rel, err := filepath.Rel(authDir, stateDir)
	if err != nil {
		return "", fmt.Errorf("routing.session-affinity-state-dir: compare with auth-dir: %w", err)
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return "", fmt.Errorf("routing.session-affinity-state-dir %q must be outside auth-dir %q (including symlinks)", stateDir, authDir)
	}
	return stateDir, nil
}

func canonicalAffinityDirectory(path string) (string, error) {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		remainder := strings.TrimLeft(strings.TrimPrefix(path, "~"), "/\\")
		path = filepath.Join(home, filepath.FromSlash(strings.ReplaceAll(remainder, "\\", "/")))
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return resolveAffinityStateDir(path)
}

// resolveAffinityStateDir receives an absolute path. Resolve its longest existing
// ancestor so creating missing directories cannot change the cache ownership key.
func resolveAffinityStateDir(path string) (string, error) {
	ancestor := path
	missing := ""
	for {
		realDir, errReal := filepath.EvalSymlinks(ancestor)
		if errReal == nil {
			return filepath.Join(realDir, missing), nil
		}
		if !errors.Is(errReal, os.ErrNotExist) {
			return "", errReal
		}
		// Do not treat a dangling symlink as a missing directory: its eventual
		// target could be inside auth-dir and would change the ownership key.
		if info, err := os.Lstat(ancestor); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("cannot resolve dangling symlink %q: %w", ancestor, errReal)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", errReal
		}
		missing = filepath.Join(filepath.Base(ancestor), missing)
		ancestor = parent
	}
}
