package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

var errAffinityStateInsideAuthDir = errors.New("must be outside auth-dir")

// Filesystem hooks; tests replace them to simulate case-insensitive volumes.
var (
	affinityEvalSymlinks = filepath.EvalSymlinks
	affinityStat         = os.Stat
)

// ResolveSessionAffinityStateDir returns the canonical state directory without
// creating it. Runtime state must never be stored in or beneath the auth directory,
// even when affinity is currently disabled or Home owns routing.
func (cfg *Config) ResolveSessionAffinityStateDir() (string, error) {
	dir := strings.TrimSpace(cfg.Routing.SessionAffinityStateDir)
	if dir == "" {
		base := strings.TrimSpace(os.Getenv("XDG_STATE_HOME"))
		// The XDG Base Directory spec says relative paths are invalid and ignored.
		if !filepath.IsAbs(base) {
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
	if affinityStateInsideAuthDir(authDir, stateDir) {
		return "", fmt.Errorf("routing.session-affinity-state-dir %q %w %q (including symlinks, case variants and mount aliases)", stateDir, errAffinityStateInsideAuthDir, authDir)
	}
	return stateDir, nil
}

// ValidateSessionAffinityStateDir always refuses a state directory inside auth-dir.
// While the local state file is unused (affinity off or Home on) and no directory
// is configured, an unresolvable default (e.g. HOME unset) only warns, so startup
// and reloads, including API-key revocations, still apply.
func (cfg *Config) ValidateSessionAffinityStateDir() error {
	_, err := cfg.ResolveSessionAffinityStateDir()
	if err == nil || errors.Is(err, errAffinityStateInsideAuthDir) {
		return err
	}
	if (cfg.Routing.SessionAffinity && !cfg.Home.Enabled) || strings.TrimSpace(cfg.Routing.SessionAffinityStateDir) != "" {
		return err
	}
	log.WithError(err).Warn("session affinity state directory unresolved; ignored while session affinity is not in use")
	return nil
}

// affinityStateInsideAuthDir compares canonical paths lexically, then by file
// identity, which also covers case-insensitive volumes and bind-mount aliases.
// A Rel error (Windows: other volume) leaves only the identity check.
func affinityStateInsideAuthDir(authDir, stateDir string) bool {
	if rel, err := filepath.Rel(authDir, stateDir); err == nil &&
		(rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))) {
		return true
	}
	// A missing auth-dir is compared through its longest existing ancestor plus
	// the missing names, case-folded (conservative on case-sensitive volumes).
	authBase, authMissing := authDir, ""
	authInfo, err := affinityStat(authBase)
	for err != nil && errors.Is(err, os.ErrNotExist) && filepath.Dir(authBase) != authBase {
		authMissing = filepath.Join(filepath.Base(authBase), authMissing)
		authBase = filepath.Dir(authBase)
		authInfo, err = affinityStat(authBase)
	}
	if err != nil {
		return false
	}
	missing := strings.Split(authMissing, string(filepath.Separator))
	for dir := stateDir; ; dir = filepath.Dir(dir) {
		if info, errStat := affinityStat(dir); errStat == nil && os.SameFile(authInfo, info) {
			if authMissing == "" {
				return true
			}
			rel, _ := filepath.Rel(dir, stateDir)
			below := strings.Split(rel, string(filepath.Separator))
			if len(below) >= len(missing) {
				inside := true
				for i := range missing {
					inside = inside && strings.EqualFold(missing[i], below[i])
				}
				if inside {
					return true
				}
			}
		}
		if filepath.Dir(dir) == dir {
			return false
		}
	}
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
		realDir, errReal := affinityEvalSymlinks(ancestor)
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
