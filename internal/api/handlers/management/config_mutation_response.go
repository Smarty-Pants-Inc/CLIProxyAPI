package management

import (
	"bytes"
	"net/http"

	"github.com/gin-gonic/gin"
)

// configMutationResponse buffers only config mutation responses. Rollback/commit
// and unlock always precede delivery, including validation and persistence errors.
// Input acquisition must already have completed via prepareManagementBody.
func (h *Handler) configMutationResponse(c *gin.Context) func() {
	original := c.Writer
	response := &configMutationWriter{ResponseWriter: original, status: http.StatusOK, size: -1}
	c.Writer = response
	h.mu.Lock()
	finish := h.configMutationLocked()
	return func() {
		finish()
		h.mu.Unlock()
		c.Writer = original
		if response.Written() {
			original.WriteHeader(response.status)
			if response.body.Len() != 0 {
				_, _ = original.Write(response.body.Bytes())
			} else {
				original.WriteHeaderNow()
			}
		}
	}
}

type configMutationWriter struct {
	gin.ResponseWriter
	body         bytes.Buffer
	status, size int
}

func (w *configMutationWriter) WriteHeader(code int) {
	if !w.Written() {
		w.status = code
	}
}
func (w *configMutationWriter) WriteHeaderNow() {
	if !w.Written() {
		w.size = 0
	}
}
func (w *configMutationWriter) Write(b []byte) (int, error) {
	w.WriteHeaderNow()
	n, err := w.body.Write(b)
	w.size += n
	return n, err
}
func (w *configMutationWriter) WriteString(s string) (int, error) { return w.Write([]byte(s)) }
func (w *configMutationWriter) Status() int                       { return w.status }
func (w *configMutationWriter) Size() int                         { return w.size }
func (w *configMutationWriter) Written() bool                     { return w.size >= 0 }
func (w *configMutationWriter) Flush()                            { w.WriteHeaderNow() }
