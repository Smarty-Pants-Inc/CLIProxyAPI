package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// managementEdit publishes a concurrent management/SDK/operator change through the
// shared CAS boundary, as the management handler does.
func managementEdit(t *testing.T, configPath, contents string) {
	t.Helper()
	version, errVersion := internalconfig.ConfigFileVersion(configPath)
	if errVersion != nil {
		t.Errorf("read management version: %v", errVersion)
		return
	}
	if _, errCAS := internalconfig.AtomicWriteConfigCAS(configPath, []byte(contents), version); errCAS != nil {
		t.Errorf("management CAS publish: %v", errCAS)
	}
}

func assertNoLostManagementEdit(t *testing.T, errSync error, configPath, managementContents string) {
	t.Helper()
	got, errRead := os.ReadFile(configPath)
	if errRead != nil {
		t.Fatalf("read local config: %v", errRead)
	}
	if string(got) != managementContents {
		t.Fatalf("lost update: local config = %q, want concurrent management edit %q (sync error %v)", got, managementContents, errSync)
	}
	if !errors.Is(errSync, internalconfig.ErrConfigConflict) {
		t.Fatalf("sync error = %v, want ErrConfigConflict", errSync)
	}
}

func TestObjectStoreConfigSyncDoesNotOverwriteConcurrentManagementEdit(t *testing.T) {
	const remoteContents = "remote: object\n"
	const managementContents = "management: edit\n"
	var configPath string
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/bucket/config/config.yaml") {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			// A management save lands while the remote config is in flight.
			once.Do(func() { managementEdit(t, configPath, managementContents) })
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(remoteContents)))
		w.Header().Set("Content-Type", "application/x-yaml")
		w.Header().Set("ETag", `"0123456789abcdef0123456789abcdef"`)
		w.Header().Set("Last-Modified", time.Unix(0, 0).UTC().Format(http.TimeFormat))
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, remoteContents)
		}
	}))
	defer server.Close()

	objectStore, errNew := NewObjectTokenStore(ObjectStoreConfig{
		Endpoint:  strings.TrimPrefix(server.URL, "http://"),
		Bucket:    "bucket",
		AccessKey: "access",
		SecretKey: "secret",
		Region:    "us-east-1",
		LocalRoot: t.TempDir(),
		PathStyle: true,
	})
	if errNew != nil {
		t.Fatalf("NewObjectTokenStore: %v", errNew)
	}
	configPath = objectStore.ConfigPath()
	if errWrite := os.WriteFile(configPath, []byte("local: original\n"), 0o600); errWrite != nil {
		t.Fatalf("seed local config: %v", errWrite)
	}

	errSync := objectStore.syncConfigFromBucket(context.Background(), "")
	assertNoLostManagementEdit(t, errSync, configPath, managementContents)
}

type hookSQLDriver struct {
	content     string
	beforeQuery func()
}

func (d *hookSQLDriver) Open(string) (driver.Conn, error) { return &hookSQLConn{driver: d}, nil }

type hookSQLConn struct{ driver *hookSQLDriver }

func (c *hookSQLConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not supported") }
func (c *hookSQLConn) Close() error                        { return nil }
func (c *hookSQLConn) Begin() (driver.Tx, error)           { return nil, errors.New("not supported") }

func (c *hookSQLConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	if c.driver.beforeQuery != nil {
		c.driver.beforeQuery()
	}
	return &hookSQLRows{content: c.driver.content}, nil
}

type hookSQLRows struct {
	content string
	done    bool
}

func (r *hookSQLRows) Columns() []string { return []string{"content"} }
func (r *hookSQLRows) Close() error      { return nil }
func (r *hookSQLRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.content
	return nil
}

func TestPostgresStoreConfigSyncDoesNotOverwriteConcurrentManagementEdit(t *testing.T) {
	const managementContents = "management: edit\n"
	configPath := filepath.Join(t.TempDir(), "config", "config.yaml")
	if errMkdir := os.MkdirAll(filepath.Dir(configPath), 0o700); errMkdir != nil {
		t.Fatalf("mkdir: %v", errMkdir)
	}
	if errWrite := os.WriteFile(configPath, []byte("local: original\n"), 0o600); errWrite != nil {
		t.Fatalf("seed local config: %v", errWrite)
	}
	fake := &hookSQLDriver{content: "remote: postgres\n"}
	// A management save lands while the database row is in flight.
	fake.beforeQuery = func() { managementEdit(t, configPath, managementContents) }
	pgStore := newHookPostgresStore(t, fake, configPath)

	errSync := pgStore.syncConfigFromDatabase(context.Background(), "")
	assertNoLostManagementEdit(t, errSync, configPath, managementContents)
}

func newHookPostgresStore(t *testing.T, fake *hookSQLDriver, configPath string) *PostgresStore {
	t.Helper()
	driverName := "cpa51-hook-" + strings.ReplaceAll(t.Name(), "/", "-")
	sql.Register(driverName, fake)
	db, errOpen := sql.Open(driverName, "")
	if errOpen != nil {
		t.Fatalf("sql.Open: %v", errOpen)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &PostgresStore{
		db:         db,
		cfg:        PostgresStoreConfig{ConfigTable: defaultConfigTable},
		configPath: configPath,
	}
}

// Counterexamples the fix must still allow: without a concurrent writer the remote
// config replaces or creates the local one, and seeding never replaces a local config.
func TestRemoteConfigSyncStillPublishesWithoutConcurrentWriter(t *testing.T) {
	t.Run("remote replaces unchanged local", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "config", "config.yaml")
		if errMkdir := os.MkdirAll(filepath.Dir(configPath), 0o700); errMkdir != nil {
			t.Fatalf("mkdir: %v", errMkdir)
		}
		if errWrite := os.WriteFile(configPath, []byte("local: original\n"), 0o600); errWrite != nil {
			t.Fatalf("seed local config: %v", errWrite)
		}
		pgStore := newHookPostgresStore(t, &hookSQLDriver{content: "remote: postgres\r\n"}, configPath)
		if errSync := pgStore.syncConfigFromDatabase(context.Background(), ""); errSync != nil {
			t.Fatalf("sync: %v", errSync)
		}
		assertLocalFileContents(t, configPath, "remote: postgres\n")
	})
	t.Run("remote creates missing local", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "spool", "config", "config.yaml")
		pgStore := newHookPostgresStore(t, &hookSQLDriver{content: "remote: postgres\n"}, configPath)
		if errSync := pgStore.syncConfigFromDatabase(context.Background(), ""); errSync != nil {
			t.Fatalf("sync: %v", errSync)
		}
		assertLocalFileContents(t, configPath, "remote: postgres\n")
	})
	t.Run("seed creates from template and keeps existing local", func(t *testing.T) {
		dir := t.TempDir()
		example := filepath.Join(dir, "config.example.yaml")
		if errWrite := os.WriteFile(example, []byte("example: true\n"), 0o600); errWrite != nil {
			t.Fatalf("write example: %v", errWrite)
		}
		configPath := filepath.Join(dir, "config", "config.yaml")
		if errSeed := seedLocalConfig(configPath, example); errSeed != nil {
			t.Fatalf("seed: %v", errSeed)
		}
		assertLocalFileContents(t, configPath, "example: true\n")
		if errWrite := os.WriteFile(configPath, []byte("operator: edit\n"), 0o600); errWrite != nil {
			t.Fatalf("operator edit: %v", errWrite)
		}
		if errSeed := seedLocalConfig(configPath, example); errSeed != nil {
			t.Fatalf("reseed: %v", errSeed)
		}
		if errSeed := seedLocalConfig(configPath, filepath.Join(dir, "missing.example.yaml")); errSeed != nil {
			t.Fatalf("existing config with no template: %v", errSeed)
		}
		assertLocalFileContents(t, configPath, "operator: edit\n")
	})
}
