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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-git/v6"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type deleteRevocationTransport func(*http.Request) (*http.Response, error)

func (f deleteRevocationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func assertDeleteWaitsForCodexRefresh(t *testing.T, path string, deleteAuth func() error) {
	t.Helper()
	metadata := map[string]any{"type": "codex", "access_token": "old-access", "refresh_token": "old-refresh"}
	if errWrite := codexauth.WriteJSONFileAtomic(path, metadata); errWrite != nil {
		t.Fatal(errWrite)
	}
	auth := &cliproxyauth.Auth{
		ID: filepath.Base(path), Provider: "codex", FileName: filepath.Base(path),
		Attributes: map[string]string{cliproxyauth.AttributePath: path}, Metadata: metadata,
	}

	started, resume := make(chan struct{}), make(chan struct{})
	original := http.DefaultTransport
	http.DefaultTransport = deleteRevocationTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "auth.openai.com" {
			return original.RoundTrip(req)
		}
		close(started)
		<-resume
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header), Request: req,
			Body: io.NopCloser(strings.NewReader(`{"access_token":"refreshed-access","refresh_token":"refreshed-refresh","expires_in":3600}`)),
		}, nil
	})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	defer func() { release(); http.DefaultTransport = original }()

	refreshDone := make(chan error, 1)
	go func() {
		_, errRefresh := executor.NewCodexExecutor(&config.Config{}).Refresh(context.Background(), auth)
		refreshDone <- errRefresh
	}()
	select {
	case <-started: // Refresh has read the credential and holds its file lock through persistence.
	case errRefresh := <-refreshDone:
		t.Fatalf("refresh did not reach OAuth: %v", errRefresh)
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not reach OAuth")
	}

	deleteStarted, deleteDone := make(chan struct{}), make(chan error, 1)
	go func() {
		close(deleteStarted)
		deleteDone <- deleteAuth()
	}()
	<-deleteStarted
	select {
	case errDelete := <-deleteDone:
		release()
		<-refreshDone
		t.Fatalf("deletion overtook the in-flight refresh lock: %v", errDelete)
	case <-time.After(100 * time.Millisecond): // Bounded lock-wait observation, not a TTL assertion.
	}
	release()
	errRefresh, errDelete := <-refreshDone, <-deleteDone
	if errRefresh != nil {
		t.Fatalf("refresh: %v", errRefresh)
	}
	if errDelete != nil {
		t.Fatalf("Delete: %v", errDelete)
	}
	if _, errStat := os.Stat(path); !os.IsNotExist(errStat) {
		t.Fatalf("deleted credential exists: %v", errStat)
	}
	restarted := fileauth.NewFileTokenStore()
	restarted.SetBaseDir(filepath.Dir(path))
	loaded, errList := restarted.List(context.Background())
	if errList != nil || len(loaded) != 0 {
		t.Fatalf("restart recovered revoked credential: count=%d err=%v", len(loaded), errList)
	}
}

func assertDeleteRemoteOutsideFileLock(t *testing.T, path string) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- codexauth.WithFileLock(path, func() error { return nil }) }()
	select {
	case errLock := <-done:
		if errLock != nil {
			t.Errorf("remote deletion credential lock probe: %v", errLock)
		}
	case <-time.After(5 * time.Second):
		t.Error("remote deletion ran while holding the credential file lock")
	}
}

func TestGitTokenStoreDeleteWaitsForCodexRefresh(t *testing.T) {
	root := t.TempDir()
	remoteDir := setupGitRemoteRepository(t, root, "master", testBranchSpec{name: "master", contents: "remote\n"})
	store := NewGitTokenStore(remoteDir, "", "", "")
	store.SetBaseDir(filepath.Join(root, "workspace", "auths"))
	auth := &cliproxyauth.Auth{
		ID: "revoked.json", FileName: "revoked.json", Provider: "codex",
		Metadata: map[string]any{"type": "codex", "access_token": "old-access", "refresh_token": "old-refresh"},
	}
	path, errSave := store.Save(context.Background(), auth)
	if errSave != nil {
		t.Fatal(errSave)
	}
	assertRemoteTreePath(t, remoteDir, "master", "auths/revoked.json", true)
	// Keep the real local git push, but probe that it is outside the credential lock.
	store.pushFn = func(ctx context.Context, repo *git.Repository, opts *git.PushOptions) error {
		assertDeleteRemoteOutsideFileLock(t, path)
		return repo.PushContext(ctx, opts)
	}
	assertDeleteWaitsForCodexRefresh(t, path, func() error { return store.Delete(context.Background(), path) })
	assertRemoteTreePath(t, remoteDir, "master", "auths/revoked.json", false)
	reopened := NewGitTokenStore(remoteDir, "", "", "")
	reopened.SetBaseDir(store.AuthDir())
	loaded, errList := reopened.List(context.Background())
	if errList != nil || len(loaded) != 0 {
		t.Fatalf("git restart recovered revoked credential: count=%d err=%v", len(loaded), errList)
	}
	if errDelete := reopened.Delete(context.Background(), path); errDelete != nil {
		t.Fatalf("repeated Delete: %v", errDelete)
	}
}

func TestGitReconcileDeletionWaitsForCodexRefresh(t *testing.T) {
	root := t.TempDir()
	remoteDir := setupGitRemoteRepository(t, root, "master", testBranchSpec{name: "master", contents: "remote\n"})
	store := NewGitTokenStore(remoteDir, "", "", "")
	store.SetBaseDir(filepath.Join(root, "workspace", "auths"))
	if errEnsure := store.EnsureRepository(); errEnsure != nil {
		t.Fatal(errEnsure)
	}
	repo, errOpen := git.PlainOpen(filepath.Dir(store.AuthDir()))
	if errOpen != nil {
		t.Fatal(errOpen)
	}
	defer func() {
		if errClose := repo.Close(); errClose != nil {
			t.Errorf("close test repository: %v", errClose)
		}
	}()
	head, errHead := repo.Head()
	if errHead != nil {
		t.Fatal(errHead)
	}
	commit, errCommit := repo.CommitObject(head.Hash())
	if errCommit != nil {
		t.Fatal(errCommit)
	}
	tree, errTree := commit.Tree()
	if errTree != nil {
		t.Fatal(errTree)
	}
	// applyTreePaths is reconciliation's real per-file removal path when the
	// remote tree no longer contains an auth. Exercise it against a live refresh.
	path := filepath.Join(store.AuthDir(), "revoked.json")
	assertDeleteWaitsForCodexRefresh(t, path, func() error {
		return applyTreePaths(tree, filepath.Dir(store.AuthDir()), []string{"auths/revoked.json"})
	})
}

func TestObjectTokenStoreDeleteWaitsForCodexRefresh(t *testing.T) {
	var mu sync.Mutex
	remoteExists := true
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodDelete || req.URL.Path != "/bucket/tenant/auths/revoked.json" {
			t.Errorf("unexpected object-store request: %s %s", req.Method, req.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		assertDeleteRemoteOutsideFileLock(t, path)
		mu.Lock()
		remoteExists = false
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	store, errNew := NewObjectTokenStore(ObjectStoreConfig{
		Endpoint: strings.TrimPrefix(server.URL, "http://"), Bucket: "bucket", Prefix: "tenant",
		AccessKey: "test-access", SecretKey: "test-secret", Region: "us-east-1", PathStyle: true, LocalRoot: t.TempDir(),
	})
	if errNew != nil {
		t.Fatal(errNew)
	}
	path = filepath.Join(store.AuthDir(), "revoked.json")
	assertDeleteWaitsForCodexRefresh(t, path, func() error { return store.Delete(context.Background(), "revoked") })
	mu.Lock()
	exists := remoteExists
	mu.Unlock()
	if exists {
		t.Fatal("remote object still exists after Delete")
	}
	if errDelete := store.Delete(context.Background(), "revoked"); errDelete != nil {
		t.Fatalf("repeated Delete: %v", errDelete)
	}
}

// Use the existing database/sql seam (as in postgres_cooldown_store_test.go),
// without a live database or a production-only callback for Delete.
type deleteRevocationConnector struct {
	exec func(context.Context, string, []driver.NamedValue) (driver.Result, error)
}

type deleteRevocationDriver struct{ connector deleteRevocationConnector }
type deleteRevocationConn struct{ connector deleteRevocationConnector }

func (c deleteRevocationConnector) Connect(context.Context) (driver.Conn, error) {
	return &deleteRevocationConn{connector: c}, nil
}
func (c deleteRevocationConnector) Driver() driver.Driver {
	return deleteRevocationDriver{connector: c}
}
func (d deleteRevocationDriver) Open(string) (driver.Conn, error) {
	return d.connector.Connect(context.Background())
}
func (*deleteRevocationConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare is not supported")
}
func (*deleteRevocationConn) Close() error { return nil }
func (*deleteRevocationConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are not supported")
}
func (c *deleteRevocationConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.connector.exec(ctx, query, args)
}

func TestPostgresStoreDeleteWaitsForCodexRefresh(t *testing.T) {
	authDir := t.TempDir()
	path := filepath.Join(authDir, "revoked.json")
	var mu sync.Mutex
	remoteExists := true
	db := sql.OpenDB(deleteRevocationConnector{exec: func(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
		if query != `DELETE FROM "auth_store" WHERE id = $1` || len(args) != 1 || args[0].Value != "revoked.json" {
			t.Errorf("unexpected auth deletion: %s %v", query, args)
			return nil, errors.New("unexpected auth deletion")
		}
		assertDeleteRemoteOutsideFileLock(t, path)
		mu.Lock()
		remoteExists = false
		mu.Unlock()
		return driver.RowsAffected(1), nil
	}})
	defer func() {
		if errClose := db.Close(); errClose != nil {
			t.Errorf("close test database: %v", errClose)
		}
	}()
	store := &PostgresStore{db: db, cfg: PostgresStoreConfig{AuthTable: defaultAuthTable}, authDir: authDir}
	assertDeleteWaitsForCodexRefresh(t, path, func() error { return store.Delete(context.Background(), "revoked.json") })
	mu.Lock()
	exists := remoteExists
	mu.Unlock()
	if exists {
		t.Fatal("remote row still exists after Delete")
	}
	if errDelete := store.Delete(context.Background(), "revoked.json"); errDelete != nil {
		t.Fatalf("repeated Delete: %v", errDelete)
	}
}
