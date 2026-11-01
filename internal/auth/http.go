package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"runtime"
	"time"
)

// randRead aliases crypto/rand.Read for test seams.
var randRead = rand.Read

func hexEncode(b []byte) string { return hex.EncodeToString(b) }

func runtimeOS() string { return runtime.GOOS }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// newRequest builds an http.Request with a context and headers.
func newRequest(ctx context.Context, method, url string, body io.Reader, headers map[string]string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// doRequest performs one HTTP round-trip with a hard timeout and returns the
// raw body + status.
func doRequest(req *http.Request) ([]byte, int, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}
