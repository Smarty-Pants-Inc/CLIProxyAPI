package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
)

// ReadRequestBody reads the incoming request body and decodes supported
// Content-Encoding values before handlers inspect JSON fields.
func ReadRequestBody(c *gin.Context) ([]byte, error) { return ReadRequestBodyLimit(c, 0) }

// ErrRequestBodyTooLarge reports that the encoded or decoded request body
// exceeded the limit passed to ReadRequestBodyLimit. Callers should answer 413.
var ErrRequestBodyTooLarge = errors.New("request body too large")

// ReadRequestBodyLimit is ReadRequestBody with the encoded body and every
// decoded layer capped at limit bytes while they are read; zero means no cap.
// The cap is enforced on the wire reader, so at most limit+1 bytes are ever
// buffered. Oversized bodies return an error wrapping ErrRequestBodyTooLarge.
func ReadRequestBodyLimit(c *gin.Context, limit int64) ([]byte, error) {
	var (
		raw []byte
		err error
	)
	if limit > 0 && c != nil && c.Request != nil && c.Request.Body != nil {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		raw, err = io.ReadAll(c.Request.Body)
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, fmt.Errorf("%w: request body exceeds %d bytes", ErrRequestBodyTooLarge, limit)
		}
	} else {
		raw, err = c.GetRawData()
	}
	if err != nil {
		return nil, err
	}

	encoding := ""
	if c != nil && c.Request != nil {
		encoding = strings.TrimSpace(c.Request.Header.Get("Content-Encoding"))
	}
	if encoding == "" || strings.EqualFold(encoding, "identity") {
		return raw, nil
	}

	decoded, err := decodeRequestBody(raw, encoding, limit)
	if err != nil {
		if errors.Is(err, ErrRequestBodyTooLarge) {
			return nil, err
		}
		if json.Valid(raw) {
			return raw, nil
		}
		return nil, err
	}
	return decoded, nil
}

func decodeRequestBody(raw []byte, encoding string, limit int64) ([]byte, error) {
	parts := strings.Split(encoding, ",")
	body := raw
	for i := len(parts) - 1; i >= 0; i-- {
		enc := strings.ToLower(strings.TrimSpace(parts[i]))
		switch enc {
		case "", "identity":
			continue
		case "zstd":
			decoded, err := decodeZstdRequestBody(body, limit)
			if err != nil {
				return nil, err
			}
			body = decoded
		default:
			return nil, fmt.Errorf("unsupported request content encoding: %s", enc)
		}
	}
	return body, nil
}

func decodeZstdRequestBody(raw []byte, limit int64) ([]byte, error) {
	var opts []zstd.DOption
	if limit > 0 {
		opts = append(opts, zstd.WithDecoderMaxMemory(uint64(limit)))
	}
	decoder, err := zstd.NewReader(bytes.NewReader(raw), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd request decoder: %w", err)
	}
	defer decoder.Close()

	var src io.Reader = decoder
	if limit > 0 {
		src = io.LimitReader(decoder, limit+1)
	}
	decoded, err := io.ReadAll(src)
	if err != nil {
		if limit > 0 && (errors.Is(err, zstd.ErrDecoderSizeExceeded) || errors.Is(err, zstd.ErrWindowSizeExceeded) || errors.Is(err, zstd.ErrFrameSizeExceeded)) {
			return nil, fmt.Errorf("%w: decoded request body exceeds %d bytes", ErrRequestBodyTooLarge, limit)
		}
		return nil, fmt.Errorf("failed to decode zstd request body: %w", err)
	}
	if limit > 0 && int64(len(decoded)) > limit {
		return nil, fmt.Errorf("%w: decoded request body exceeds %d bytes", ErrRequestBodyTooLarge, limit)
	}
	return decoded, nil
}
