package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
)

// ReadRequestBody reads the incoming request body and decodes supported
// Content-Encoding values before handlers inspect JSON fields.
func ReadRequestBody(c *gin.Context) ([]byte, error) { return ReadRequestBodyLimit(c, 0) }

// ReadRequestBodyLimit is ReadRequestBody with every decoded layer capped at
// limit bytes while it is decoded; zero means no cap.
func ReadRequestBodyLimit(c *gin.Context, limit int64) ([]byte, error) {
	raw, err := c.GetRawData()
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
		return nil, fmt.Errorf("failed to decode zstd request body: %w", err)
	}
	if limit > 0 && int64(len(decoded)) > limit {
		return nil, fmt.Errorf("decoded request body exceeds %d bytes", limit)
	}
	return decoded, nil
}
