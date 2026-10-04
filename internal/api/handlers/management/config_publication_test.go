package management

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestManagementConfigPublicationConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("debug: false\nrequest-retry: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	original, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{cfg: original, configFilePath: path}
	operator, err := sdkconfig.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	operator.RequestRetry = 7
	if err = sdkconfig.SaveConfigPreserveComments(path, operator); err != nil {
		t.Fatal(err)
	}
	rec := configRequest(h.PutDebug, http.MethodPut, `{"value":true}`, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale scalar status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if original.Debug || h.cfg.Debug {
		t.Fatal("conflicted mutation leaked into memory")
	}
	disk, err := config.LoadConfig(path)
	if err != nil || disk.RequestRetry != 7 || disk.Debug {
		t.Fatalf("operator edit lost: cfg=%+v err=%v", disk, err)
	}
	h.SetConfig(disk)
	if rec = configRequest(h.PutDebug, http.MethodPut, `{"value":true}`, ""); rec.Code != http.StatusOK {
		t.Fatalf("retry status = %d, body = %s", rec.Code, rec.Body.String())
	}
	disk, err = config.LoadConfig(path)
	if err != nil || disk.RequestRetry != 7 || !disk.Debug {
		t.Fatalf("retry lost a write: cfg=%+v err=%v", disk, err)
	}
}

func TestManagementConfigYAMLRequiresSourceETag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("debug: false\nrequest-retry: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{cfg: cfg, configFilePath: path}
	get := configRequest(h.GetConfigYAML, http.MethodGet, "", "")
	etag := get.Header().Get("ETag")
	if etag == "" {
		t.Fatal("GET did not return an ETag")
	}
	if rec := configRequest(h.PutConfigYAML, http.MethodPut, "debug: true\n", ""); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing version status = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := configRequest(h.PutDebug, http.MethodPut, `{"value":true}`, ""); rec.Code != http.StatusOK {
		t.Fatalf("scalar write status = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := configRequest(h.PutConfigYAML, http.MethodPut, get.Body.String(), etag); rec.Code != http.StatusConflict {
		t.Fatalf("stale full body status = %d: %s", rec.Code, rec.Body.String())
	}
	get = configRequest(h.GetConfigYAML, http.MethodGet, "", "")
	if rec := configRequest(h.PutConfigYAML, http.MethodPut, "debug: true\nrequest-retry: 9\n", get.Header().Get("ETag")); rec.Code != http.StatusOK {
		t.Fatalf("current full body status = %d: %s", rec.Code, rec.Body.String())
	}
	disk, err := config.LoadConfig(path)
	if err != nil || !disk.Debug || disk.RequestRetry != 9 {
		t.Fatalf("full put not published: cfg=%+v err=%v", disk, err)
	}
}

func TestManagementConcurrentConfigPublication(t *testing.T) {
	if os.Getenv("CPA_MANAGEMENT_WRITER") == "1" {
		path := os.Getenv("CPA_MANAGEMENT_CONFIG")
		for attempt := 0; attempt < 100; attempt++ {
			cfg, err := sdkconfig.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.OAuthExcludedModels == nil {
				cfg.OAuthExcludedModels = make(map[string][]string)
			}
			cfg.OAuthExcludedModels["process"] = []string{"process-model"}
			if err = sdkconfig.SaveConfigPreserveComments(path, cfg); err == nil {
				return
			} else if !errors.Is(err, sdkconfig.ErrConfigConflict) {
				t.Fatal(err)
			}
		}
		t.Fatal("process writer exhausted retries")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("oauth-excluded-models: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{cfg: cfg, configFilePath: path}
	const workers = 12
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"provider":"writer-%d","models":["model-%d"]}`, i, i)
			for attempt := 0; attempt < 100; attempt++ {
				rec := configRequest(h.PatchOAuthExcludedModels, http.MethodPatch, body, "")
				if rec.Code == http.StatusOK {
					return
				}
				if rec.Code != http.StatusConflict {
					t.Errorf("writer %d: status %d: %s", i, rec.Code, rec.Body.String())
					return
				}
				latest, errLoad := config.LoadConfig(path)
				if errLoad != nil {
					t.Error(errLoad)
					return
				}
				h.SetConfig(latest)
			}
			t.Errorf("writer %d exhausted retries", i)
		}(i)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestManagementConcurrentConfigPublication$", "-test.v")
	child.Env = append(os.Environ(), "CPA_MANAGEMENT_WRITER=1", "CPA_MANAGEMENT_CONFIG="+path)
	output, errChild := child.CombinedOutput()
	wg.Wait()
	if errChild != nil {
		t.Fatalf("SDK process writer failed: %v\n%s", errChild, output)
	}
	disk, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(disk.OAuthExcludedModels) != workers+1 {
		t.Fatalf("lost writers: got %d want %d: %v", len(disk.OAuthExcludedModels), workers+1, disk.OAuthExcludedModels)
	}
	for i := 0; i < workers; i++ {
		key := fmt.Sprintf("writer-%d", i)
		if got := disk.OAuthExcludedModels[key]; len(got) != 1 || got[0] != fmt.Sprintf("model-%d", i) {
			t.Errorf("lost %s: %v", key, got)
		}
	}
	if got := disk.OAuthExcludedModels["process"]; len(got) != 1 || got[0] != "process-model" {
		t.Errorf("lost process writer: %v", got)
	}
}

func configRequest(handler gin.HandlerFunc, method, body, etag string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(method, "/v0/management/config.yaml", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	if etag != "" {
		ctx.Request.Header.Set("If-Match", etag)
	}
	handler(ctx)
	return rec
}
