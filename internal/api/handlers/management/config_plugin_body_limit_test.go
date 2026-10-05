package management

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

type configCountingBody struct {
	io.Reader
	bytes int
}

func (b *configCountingBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.bytes += n
	return n, err
}
func (*configCountingBody) Close() error { return nil }

func TestPluginConfigRoutesBoundJSONBeforeDecoding(t *testing.T) {
	for _, route := range []string{"put", "patch", "enabled"} {
		t.Run(route, func(t *testing.T) {
			cfg := &config.Config{}
			h := &Handler{cfg: cfg}
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Params = gin.Params{{Key: "id", Value: "test-plugin"}}
			c.Request = httptest.NewRequest(http.MethodPut, "/plugins/test-plugin/config", nil)
			body := &configCountingBody{Reader: strings.NewReader(`{"padding":"` + strings.Repeat("x", managementBodyLimit) + `","enabled":true}`)}
			c.Request.Body = body
			switch route {
			case "put":
				h.PutPluginConfig(c)
			case "patch":
				h.PatchPluginConfig(c)
			case "enabled":
				h.PatchPluginEnabled(c)
			}
			if rec.Code != http.StatusBadRequest {
				t.Errorf("over-limit status=%d, want 400", rec.Code)
			}
			if body.bytes > managementBodyLimit+1 {
				t.Errorf("decoder read %d bytes, exceeds bound %d", body.bytes, managementBodyLimit+1)
			}
			if h.cfg != cfg || len(cfg.Plugins.Configs) != 0 {
				t.Error("over-limit input mutated config")
			}
		})
	}
}

func TestManagementRawConfigBodyBoundBeforeRead(t *testing.T) {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "/config.yaml", nil)
	body := &configCountingBody{Reader: strings.NewReader(strings.Repeat("x", managementBodyLimit+100))}
	c.Request.Body = body
	if prepareManagementRawBody(c) {
		t.Error("over-limit raw config input accepted")
	}
	if body.bytes > managementBodyLimit+1 || rec.Code != http.StatusBadRequest {
		t.Fatalf("unbounded raw read: bytes=%d status=%d", body.bytes, rec.Code)
	}
}
