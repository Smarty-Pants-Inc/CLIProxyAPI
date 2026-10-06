package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"gopkg.in/yaml.v3"
)

type round4BlockedWriter struct {
	http.ResponseWriter
	entered, release chan struct{}
	once             sync.Once
}

func (w *round4BlockedWriter) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.release })
	return w.ResponseWriter.Write(b)
}

func round4Server(t *testing.T) *Server {
	t.Helper()
	t.Setenv("MANAGEMENT_PASSWORD", "round4-fixture-key")
	cfg, errParse := config.ParseConfigBytes([]byte("claude-api-key:\n  - api-key: fixture\n"))
	if errParse != nil {
		t.Fatal(errParse)
	}
	s := newTestServerWithConfig(t, cfg)
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(s.configFilePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cfg.ConfigFileVersion, err = config.ConfigFileVersion(s.configFilePath)
	if err != nil {
		t.Fatal(err)
	}
	s.mgmt.SetConfig(cfg)
	return s
}

func TestRound4ValidationResponseDoesNotBlockRealServer(t *testing.T) {
	s := round4Server(t)
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v0/management/claude-api-key" {
			w = &round4BlockedWriter{ResponseWriter: w, entered: entered, release: release}
		}
		s.engine.ServeHTTP(w, r)
	}))
	defer server.Close()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		req, _ := http.NewRequest(http.MethodPatch, server.URL+"/v0/management/claude-api-key", strings.NewReader(`{"index":0,"value":{"fingerprint-profile":"`+strings.Repeat("x", 6<<20)+`"}}`))
		req.Header.Set("Authorization", "Bearer round4-fixture-key")
		req.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(req)
		if err != nil {
			t.Error(err)
			return
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		if response.StatusCode != 400 || len(raw) > 512 {
			t.Errorf("validation response status=%d bytes=%d", response.StatusCode, len(raw))
		}
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		close(release)
		<-finished
		t.Fatal("response did not start")
	}
	reloadDone := make(chan struct{})
	go func() { s.mgmt.SetConfig(s.cfg.CloneForRuntime()); close(reloadDone) }()
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/v0/management/debug", nil)
	req.Header.Set("Authorization", "Bearer round4-fixture-key")
	client := &http.Client{Timeout: time.Second}
	response, err := client.Do(req)
	if err != nil {
		t.Errorf("blocked validation response stopped second real management request: %v", err)
	} else {
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Errorf("authorization status=%d", response.StatusCode)
		}
	}
	select {
	case <-reloadDone:
	case <-time.After(time.Second):
		t.Error("blocked validation response stopped SetConfig")
	}
	close(release)
	<-finished
	<-reloadDone
}

func TestRound4ManagementSaveKeepsRuntimeSnapshotImmutable(t *testing.T) {
	s := round4Server(t)
	original := s.cfg
	start, stop, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		close(start)
		for {
			select {
			case <-stop:
				return
			default:
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/v0/management/debug", nil)
			req.Header.Set("Authorization", "Bearer round4-fixture-key")
			s.engine.ServeHTTP(rec, req)
		}
	}()
	<-start
	for i := 0; i < 20; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/v0/management/logging-to-file", strings.NewReader(`{"value":true}`))
		req.Header.Set("Authorization", "Bearer round4-fixture-key")
		req.Header.Set("Content-Type", "application/json")
		s.engine.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("save status=%d %s", rec.Code, rec.Body.String())
			break
		}
	}
	close(stop)
	<-done
	if original.LoggingToFile {
		t.Error("successful management edit overwrote published runtime snapshot")
	}
	disk, err := config.LoadConfig(s.configFilePath)
	if err != nil || !disk.LoggingToFile {
		t.Fatalf("candidate was not published: %v", err)
	}
}
