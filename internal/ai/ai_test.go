package ai

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

type mockTransport struct {
	fn func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.fn(req)
}

func TestClientChat(t *testing.T) {
	var gotAuth, gotPath string
	transport := &mockTransport{
		fn: func(req *http.Request) (*http.Response, error) {
			gotAuth = req.Header.Get("Authorization")
			gotPath = req.URL.Path
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(`{"choices":[{"message":{"role":"assistant","content":"hello world"}}]} `)),
			}
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	}

	c, err := New(Config{
		BaseURL:    "http://mock.local/v1",
		APIKey:     "test-key",
		Model:      "test-model",
		HTTPClient: &http.Client{Transport: transport},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Chat(context.Background(), "sys", "user")
	if err != nil {
		t.Fatal(err)
	}
	if out != "hello world" {
		t.Fatalf("unexpected output: %q", out)
	}
	if gotAuth != "Bearer test-key" {
		t.Fatalf("unexpected auth header: %q", gotAuth)
	}
	if gotPath != "/v1/chat/completions" {
		t.Fatalf("unexpected path: %q", gotPath)
	}
}

func TestClientAPIError(t *testing.T) {
	transport := &mockTransport{
		fn: func(req *http.Request) (*http.Response, error) {
			resp := &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBufferString(`{"error":{"message":"bad key"}}`)),
			}
			resp.Header.Set("Content-Type", "application/json")
			return resp, nil
		},
	}

	c, _ := New(Config{
		BaseURL:    "http://mock.local/v1",
		APIKey:     "x",
		Model:      "m",
		HTTPClient: &http.Client{Transport: transport},
	})
	if _, err := c.Chat(context.Background(), "s", "u"); err == nil {
		t.Fatal("expected error")
	}
}

func TestNewRequiresKey(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for missing key")
	}
}
