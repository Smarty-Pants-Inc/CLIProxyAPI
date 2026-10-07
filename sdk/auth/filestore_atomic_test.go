package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/claude"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// assertReadersSeeWholeJSON runs readers that loop over os.ReadFile and
// json.Valid while write is called repeatedly. It fails when a reader ever
// observes a missing, empty or partial auth file.
func assertReadersSeeWholeJSON(t *testing.T, path string, iterations int, write func(i int) error) {
	t.Helper()
	var (
		stop    atomic.Bool
		reads   atomic.Int64
		bad     atomic.Int64
		firstMu sync.Mutex
		first   string
		wg      sync.WaitGroup
	)
	readLoop := func() {
		defer wg.Done()
		for !stop.Load() {
			data, errRead := os.ReadFile(path)
			reads.Add(1)
			if errRead == nil && json.Valid(data) {
				continue
			}
			bad.Add(1)
			firstMu.Lock()
			if first == "" {
				first = fmt.Sprintf("len=%d err=%v", len(data), errRead)
			}
			firstMu.Unlock()
		}
	}
	for r := 0; r < atomicTestReaders; r++ {
		wg.Add(1)
		go readLoop()
	}
	for i := 0; i < iterations; i++ {
		if errWrite := write(i); errWrite != nil {
			stop.Store(true)
			wg.Wait()
			t.Fatalf("write %d: %v", i, errWrite)
		}
	}
	stop.Store(true)
	wg.Wait()
	if n := bad.Load(); n > 0 {
		t.Fatalf("reader saw %d empty or invalid auth files out of %d reads (first: %s)", n, reads.Load(), first)
	}
	info, errStat := os.Stat(path)
	if errStat != nil {
		t.Fatalf("stat auth file: %v", errStat)
	}
	if perm := info.Mode().Perm(); perm != 0o600 && os.PathSeparator == '/' {
		t.Fatalf("auth file mode = %o, want 600", perm)
	}
	entries, errReadDir := os.ReadDir(filepath.Dir(path))
	if errReadDir != nil {
		t.Fatalf("read auth dir: %v", errReadDir)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("auth dir has leftover files: %v", names)
	}
}

const (
	atomicTestBlobSize = 256 << 10
	atomicTestReaders  = 4
	atomicTestWrites   = 150
)

func TestFileTokenStoreSaveIsAtomicForConcurrentReaders(t *testing.T) {
	blob := strings.Repeat("x", atomicTestBlobSize)

	t.Run("metadata", func(t *testing.T) {
		dir := t.TempDir()
		store := NewFileTokenStore()
		store.SetBaseDir(dir)
		path := filepath.Join(dir, "big.json")
		save := func(i int) error {
			_, errSave := store.Save(context.Background(), &cliproxyauth.Auth{
				ID:       "big.json",
				FileName: "big.json",
				Provider: "codex",
				Metadata: map[string]any{"type": "codex", "blob": blob, "seq": i},
			})
			return errSave
		}
		if errSave := save(-1); errSave != nil {
			t.Fatalf("initial save: %v", errSave)
		}
		assertReadersSeeWholeJSON(t, path, atomicTestWrites, save)
	})

	t.Run("token_storage", func(t *testing.T) {
		dir := t.TempDir()
		store := NewFileTokenStore()
		store.SetBaseDir(dir)
		path := filepath.Join(dir, "claude-big.json")
		save := func(i int) error {
			_, errSave := store.Save(context.Background(), &cliproxyauth.Auth{
				ID:       "claude-big.json",
				FileName: "claude-big.json",
				Provider: "claude",
				Storage:  &claude.ClaudeTokenStorage{AccessToken: blob, Email: fmt.Sprintf("seq-%d@example.com", i)},
			})
			return errSave
		}
		if errSave := save(-1); errSave != nil {
			t.Fatalf("initial save: %v", errSave)
		}
		assertReadersSeeWholeJSON(t, path, atomicTestWrites, save)
	})
}
