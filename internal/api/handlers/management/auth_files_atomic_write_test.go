package management

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// assertAuthFileReadsStayWhole runs readers that loop over os.ReadFile and
// json.Valid while write is called repeatedly. It fails when a reader ever
// observes a missing, empty or partial auth file.
func assertAuthFileReadsStayWhole(t *testing.T, path string, iterations int, write func(i int) error) {
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
}

const (
	atomicTestBlobSize = 256 << 10
	atomicTestReaders  = 4
	atomicTestWrites   = 150
)

func TestAuthFileManagementWritesAreAtomicForConcurrentReaders(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	blob := strings.Repeat("x", atomicTestBlobSize)

	t.Run("patch_fields", func(t *testing.T) {
		authDir := t.TempDir()
		fileName := "seat.json"
		filePath := filepath.Join(authDir, fileName)
		store := fileauth.NewFileTokenStore()
		store.SetBaseDir(authDir)
		manager := coreauth.NewManager(store, nil, nil)
		record := &coreauth.Auth{
			ID:         fileName,
			FileName:   fileName,
			Provider:   "codex",
			Attributes: map[string]string{"path": filePath},
			Metadata:   map[string]any{"type": "codex", "blob": blob},
		}
		if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
			t.Fatalf("register auth: %v", errRegister)
		}
		if _, errSave := store.Save(context.Background(), record.Clone()); errSave != nil {
			t.Fatalf("initial save: %v", errSave)
		}
		h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

		assertAuthFileReadsStayWhole(t, filePath, atomicTestWrites, func(i int) error {
			body := fmt.Sprintf(`{"name":%q,"note":"seat-%d"}`, fileName, i)
			rec := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(rec)
			req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/fields", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			ctx.Request = req
			h.PatchAuthFileFields(ctx)
			if rec.Code != http.StatusOK {
				return fmt.Errorf("status %d: %s", rec.Code, rec.Body.String())
			}
			return nil
		})
	})

	t.Run("source_status", func(t *testing.T) {
		filePath := filepath.Join(t.TempDir(), "source.json")
		initial, _ := json.Marshal(map[string]any{"type": "codex", "blob": blob})
		if errWrite := os.WriteFile(filePath, initial, 0o600); errWrite != nil {
			t.Fatalf("seed auth file: %v", errWrite)
		}
		assertAuthFileReadsStayWhole(t, filePath, atomicTestWrites, func(i int) error {
			return setSourceAuthFileDisabled(filePath, i%2 == 0)
		})
	})

	t.Run("upload", func(t *testing.T) {
		authDir := t.TempDir()
		fileName := "upload.json"
		filePath := filepath.Join(authDir, fileName)
		manager := coreauth.NewManager(&memoryAuthStore{}, nil, nil)
		h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
		write := func(i int) error {
			data, _ := json.Marshal(map[string]any{"type": "codex", "blob": blob, "seq": i})
			return h.writeAuthFile(context.Background(), fileName, data)
		}
		if errWrite := write(-1); errWrite != nil {
			t.Fatalf("initial upload: %v", errWrite)
		}
		assertAuthFileReadsStayWhole(t, filePath, atomicTestWrites, write)
	})
}
