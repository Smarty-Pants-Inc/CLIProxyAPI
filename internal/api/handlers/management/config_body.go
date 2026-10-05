package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const managementBodyLimit = 8 << 20
const managementBodyReadTimeout = 10 * time.Second

type bodyDeadlineKey struct{}

// WithManagementBodyDeadline bounds inbound management body acquisition only;
// it never installs a deadline on an upstream or streaming response.
func WithManagementBodyDeadline(next http.Handler) http.Handler {
	return withManagementBodyDeadline(next, managementBodyReadTimeout)
}

func withManagementBodyDeadline(next http.Handler, readTimeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v0/management/") {
			next.ServeHTTP(w, r)
			return
		}
		controller := http.NewResponseController(w)
		if err := controller.SetReadDeadline(time.Now().Add(readTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			http.Error(w, "cannot bound management body read", http.StatusBadRequest)
			return
		}
		clear := func() { _ = controller.SetReadDeadline(time.Time{}) }
		defer clear()
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), bodyDeadlineKey{}, clear)))
	})
}

// prepareManagementBody consumes network input before any mutation mutex is held.
// Later binding operates only on a bounded in-memory reader.
func prepareManagementBody(c *gin.Context) bool {
	return prepareManagementBodyMode(c, true)
}

func prepareManagementRawBody(c *gin.Context) bool {
	return prepareManagementBodyMode(c, false)
}

func prepareManagementBodyMode(c *gin.Context, requireJSON bool) bool {
	if _, ok := c.Get("management-body-buffered"); ok {
		return true
	}
	if c.Request.Context().Err() != nil {
		c.JSON(http.StatusRequestTimeout, gin.H{"error": "request cancelled"})
		return false
	}
	body := http.MaxBytesReader(c.Writer, c.Request.Body, managementBodyLimit)
	data, err := io.ReadAll(body)
	if err != nil {
		// Close while the read deadline is still active so net/http cannot
		// block draining an incomplete body after this handler returns.
		_ = body.Close()
		c.Header("Connection", "close")
		c.JSON(http.StatusBadRequest, gin.H{"error": "management body exceeds size/read deadline or cannot be read"})
		return false
	}
	if clear, ok := c.Request.Context().Value(bodyDeadlineKey{}).(func()); ok {
		clear()
	}
	if c.Request.Context().Err() != nil {
		c.JSON(http.StatusRequestTimeout, gin.H{"error": "request cancelled"})
		return false
	}
	if requireJSON && !json.Valid(data) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return false
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(data))
	c.Set("management-body-buffered", true)
	return true
}

func managementRequestContext(c *gin.Context) context.Context {
	if c != nil && c.Request != nil {
		return c.Request.Context()
	}
	return context.Background()
}

func managementRequestActive(c *gin.Context) bool {
	if c != nil && c.Request != nil && c.Request.Context().Err() != nil {
		c.JSON(http.StatusRequestTimeout, gin.H{"error": "request cancelled before publication"})
		return false
	}
	return true
}
