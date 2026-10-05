package management

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	log "github.com/sirupsen/logrus"
)

const (
	latestReleaseURL       = "https://api.github.com/repos/router-for-me/CLIProxyAPI/releases/latest"
	latestReleaseUserAgent = "CLIProxyAPI"
)

func (h *Handler) GetConfig(c *gin.Context) {
	if h == nil {
		c.JSON(200, gin.H{})
		return
	}
	cfg := h.configResponseSnapshot()
	if cfg == nil {
		c.JSON(200, gin.H{})
		return
	}
	c.JSON(200, new(*cfg))
}

type releaseInfo struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
}

func setLatestReleaseRequestHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", latestReleaseUserAgent)
	if token := util.ResolveGitHubToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

// GetLatestVersion returns the latest release version from GitHub without downloading assets.
func (h *Handler) GetLatestVersion(c *gin.Context) {
	client := &http.Client{Timeout: 10 * time.Second}
	proxyURL := ""
	if h != nil {
		h.mu.Lock()
		if h.cfg != nil {
			proxyURL = strings.TrimSpace(h.cfg.ProxyURL)
		}
		h.mu.Unlock()
	}
	if proxyURL != "" {
		sdkCfg := &sdkconfig.SDKConfig{ProxyURL: proxyURL}
		util.SetProxy(sdkCfg, client)
	}

	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, latestReleaseURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "request_create_failed", "message": err.Error()})
		return
	}
	setLatestReleaseRequestHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "request_failed", "message": err.Error()})
		return
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.WithError(errClose).Debug("failed to close latest version response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		c.JSON(http.StatusBadGateway, gin.H{"error": "unexpected_status", "message": fmt.Sprintf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))})
		return
	}

	var info releaseInfo
	if errDecode := json.NewDecoder(resp.Body).Decode(&info); errDecode != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "decode_failed", "message": errDecode.Error()})
		return
	}

	version := strings.TrimSpace(info.TagName)
	if version == "" {
		version = strings.TrimSpace(info.Name)
	}
	if version == "" {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid_response", "message": "missing release version"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"latest-version": version})
}

func WriteConfig(path string, data []byte, expectedVersion ...string) error {
	if len(expectedVersion) == 0 {
		return config.AtomicWriteConfig(path, config.NormalizeCommentIndentation(data))
	}
	_, errWrite := config.AtomicWriteConfigCAS(path, config.NormalizeCommentIndentation(data), expectedVersion[0])
	return errWrite
}

func (h *Handler) PutConfigYAML(c *gin.Context) {
	if !prepareManagementRawBody(c) {
		return
	}
	expectedVersion := strings.Trim(c.GetHeader("If-Match"), "\"")
	if expectedVersion == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "config_version_required", "message": "send the ETag from GET /config.yaml as If-Match"})
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_yaml", "message": "cannot read request body"})
		return
	}
	if _, errValidate := config.ParseConfigBytes(body); errValidate != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid_config", "message": errValidate.Error()})
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !managementRequestActive(c) {
		return
	}
	version, errWrite := config.AtomicWriteConfigCAS(h.configFilePath, config.NormalizeCommentIndentation(body), expectedVersion)
	if errWrite != nil {
		if errWrite == config.ErrConfigConflict {
			c.JSON(http.StatusConflict, gin.H{"error": "config_changed", "message": "config changed since it was read"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "write_failed", "message": errWrite.Error()})
		}
		return
	}
	h.configVersion = version
	// Reload into handler to keep memory in sync
	newCfg, err := config.LoadConfig(h.configFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reload_failed", "message": err.Error()})
		return
	}
	h.cfg = newCfg
	h.configVersion = newCfg.ConfigFileVersion
	c.JSON(http.StatusOK, gin.H{"ok": true, "changed": []string{"config"}})
}

// GetConfigYAML returns the raw config.yaml file bytes without re-encoding.
// It preserves comments and original formatting/styles.
func (h *Handler) GetConfigYAML(c *gin.Context) {
	data, err := os.ReadFile(h.configFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "message": "config file not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "read_failed", "message": err.Error()})
		return
	}
	hash := sha256.Sum256(data)
	c.Header("ETag", fmt.Sprintf("\"%x\"", hash[:]))
	c.Header("Content-Type", "application/yaml; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	// Write raw bytes as-is
	_, _ = c.Writer.Write(data)
}

// Debug
func (h *Handler) GetDebug(c *gin.Context) {
	cfg := h.configResponseSnapshot()
	c.JSON(200, gin.H{"debug": cfg.Debug})
}
func (h *Handler) PutDebug(c *gin.Context) { h.updateBoolField(c, func(v bool) { h.cfg.Debug = v }) }

// UsageStatisticsEnabled
func (h *Handler) GetUsageStatisticsEnabled(c *gin.Context) {
	cfg := h.configResponseSnapshot()
	c.JSON(200, gin.H{"usage-statistics-enabled": cfg.UsageStatisticsEnabled})
}
func (h *Handler) PutUsageStatisticsEnabled(c *gin.Context) {
	if !prepareManagementBody(c) {
		return
	}
	h.updateBoolField(c, func(v bool) { h.cfg.UsageStatisticsEnabled = v })
}

// UsageStatisticsEnabled
func (h *Handler) GetLoggingToFile(c *gin.Context) {
	cfg := h.configResponseSnapshot()
	c.JSON(200, gin.H{"logging-to-file": cfg.LoggingToFile})
}
func (h *Handler) PutLoggingToFile(c *gin.Context) {
	if !prepareManagementBody(c) {
		return
	}
	h.updateBoolField(c, func(v bool) { h.cfg.LoggingToFile = v })
}

// LogsMaxTotalSizeMB
func (h *Handler) GetLogsMaxTotalSizeMB(c *gin.Context) {
	cfg := h.configResponseSnapshot()
	c.JSON(200, gin.H{"logs-max-total-size-mb": cfg.LogsMaxTotalSizeMB})
}
func (h *Handler) PutLogsMaxTotalSizeMB(c *gin.Context) {
	if !prepareManagementBody(c) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	defer h.configMutationLocked()()
	var body struct {
		Value *int `json:"value"`
	}
	if errBindJSON := c.ShouldBindJSON(&body); errBindJSON != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	value := *body.Value
	if value < 0 {
		value = 0
	}
	h.cfg.LogsMaxTotalSizeMB = value
	h.persistLocked(c)
}

// ErrorLogsMaxFiles
func (h *Handler) GetErrorLogsMaxFiles(c *gin.Context) {
	cfg := h.configResponseSnapshot()
	c.JSON(200, gin.H{"error-logs-max-files": cfg.ErrorLogsMaxFiles})
}
func (h *Handler) PutErrorLogsMaxFiles(c *gin.Context) {
	if !prepareManagementBody(c) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	defer h.configMutationLocked()()
	var body struct {
		Value *int `json:"value"`
	}
	if errBindJSON := c.ShouldBindJSON(&body); errBindJSON != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	value := *body.Value
	if value < 0 {
		value = 10
	}
	h.cfg.ErrorLogsMaxFiles = value
	h.persistLocked(c)
}

// Request log
func (h *Handler) GetRequestLog(c *gin.Context) {
	cfg := h.configResponseSnapshot()
	c.JSON(200, gin.H{"request-log": cfg.RequestLog})
}
func (h *Handler) PutRequestLog(c *gin.Context) {
	if !prepareManagementBody(c) {
		return
	}
	h.updateBoolField(c, func(v bool) { h.cfg.RequestLog = v })
}

// Websocket auth
func (h *Handler) GetWebsocketAuth(c *gin.Context) {
	cfg := h.configResponseSnapshot()
	c.JSON(200, gin.H{"ws-auth": cfg.WebsocketAuth})
}
func (h *Handler) PutWebsocketAuth(c *gin.Context) {
	if !prepareManagementBody(c) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	defer h.configMutationLocked()()
	var body struct {
		Value *bool `json:"value"`
	}
	if c.ShouldBindJSON(&body) != nil || body.Value == nil || (!*body.Value && len(h.cfg.APIKeyPolicies) != 0) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ws-auth for api-key-policies"})
		return
	}
	h.cfg.WebsocketAuth = *body.Value
	h.persistLocked(c)
}

// Request retry
func (h *Handler) GetRequestRetry(c *gin.Context) {
	cfg := h.configResponseSnapshot()
	c.JSON(200, gin.H{"request-retry": cfg.RequestRetry})
}
func (h *Handler) PutRequestRetry(c *gin.Context) {
	if !prepareManagementBody(c) {
		return
	}
	h.updateIntField(c, func(v int) { h.cfg.RequestRetry = v })
}

// Max retry credentials
func (h *Handler) GetMaxRetryCredentials(c *gin.Context) {
	cfg := h.configResponseSnapshot()
	c.JSON(200, gin.H{"max-retry-credentials": cfg.MaxRetryCredentials})
}
func (h *Handler) PutMaxRetryCredentials(c *gin.Context) {
	if !prepareManagementBody(c) {
		return
	}
	h.updateIntField(c, func(v int) { h.cfg.MaxRetryCredentials = v })
}

// Max retry interval
func (h *Handler) GetMaxRetryInterval(c *gin.Context) {
	cfg := h.configResponseSnapshot()
	c.JSON(200, gin.H{"max-retry-interval": cfg.MaxRetryInterval})
}
func (h *Handler) PutMaxRetryInterval(c *gin.Context) {
	if !prepareManagementBody(c) {
		return
	}
	h.updateIntField(c, func(v int) { h.cfg.MaxRetryInterval = v })
}

// ForceModelPrefix
func (h *Handler) GetForceModelPrefix(c *gin.Context) {
	cfg := h.configResponseSnapshot()
	c.JSON(200, gin.H{"force-model-prefix": cfg.ForceModelPrefix})
}
func (h *Handler) PutForceModelPrefix(c *gin.Context) {
	if !prepareManagementBody(c) {
		return
	}
	h.updateBoolField(c, func(v bool) { h.cfg.ForceModelPrefix = v })
}

func normalizeRoutingStrategy(strategy string) (string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(strategy))
	switch normalized {
	case "", "round-robin", "roundrobin", "rr":
		return "round-robin", true
	case "weighted-round-robin", "weightedroundrobin", "wrr":
		return "weighted-round-robin", true
	case "fill-first", "fillfirst", "ff":
		return "fill-first", true
	default:
		return "", false
	}
}

// RoutingStrategy
func (h *Handler) GetRoutingStrategy(c *gin.Context) {
	cfg := h.configResponseSnapshot()
	strategy, ok := normalizeRoutingStrategy(cfg.Routing.Strategy)
	if !ok {
		c.JSON(200, gin.H{"strategy": strings.TrimSpace(cfg.Routing.Strategy)})
		return
	}
	c.JSON(200, gin.H{"strategy": strategy})
}
func (h *Handler) PutRoutingStrategy(c *gin.Context) {
	if !prepareManagementBody(c) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	defer h.configMutationLocked()()
	var body struct {
		Value *string `json:"value"`
	}
	if errBindJSON := c.ShouldBindJSON(&body); errBindJSON != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	normalized, ok := normalizeRoutingStrategy(*body.Value)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid strategy"})
		return
	}
	h.cfg.Routing.Strategy = normalized
	h.persistLocked(c)
}

// Proxy URL
func (h *Handler) GetProxyURL(c *gin.Context) {
	cfg := h.configResponseSnapshot()
	c.JSON(200, gin.H{"proxy-url": cfg.ProxyURL})
}
func (h *Handler) PutProxyURL(c *gin.Context) {
	if !prepareManagementBody(c) {
		return
	}
	h.updateStringField(c, func(v string) { h.cfg.ProxyURL = v })
}
func (h *Handler) DeleteProxyURL(c *gin.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()
	defer h.configMutationLocked()()
	h.cfg.ProxyURL = ""
	h.persistLocked(c)
}
