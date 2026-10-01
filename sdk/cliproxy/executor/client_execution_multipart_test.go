package executor

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestAPIKeySingleAttemptMalformedMultipartFailsClosed(t *testing.T) {
	ctx := WithClientExecutionPolicy(context.Background(), "gpt-6.1-sol", true)
	body := "--boundary\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\ngpt-6.1-sol\r\n--boundary\r\nINVALID HEADER\r\n\r\nvalue\r\n--boundary--\r\n"
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://synthetic.test/images", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	if err := ValidateClientHTTPRequest(req); err == nil {
		t.Fatal("valid first model hid a malformed multipart tail")
	}
}
