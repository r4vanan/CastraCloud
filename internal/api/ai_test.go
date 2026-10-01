package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/castracloud/castracloud/internal/ai"
	"github.com/castracloud/castracloud/internal/auth"
	"github.com/castracloud/castracloud/internal/logging"
	"github.com/google/uuid"
)

type mockHTTPTransport struct {
	response string
	status   int
}

func (m *mockHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	status := m.status
	if status == 0 {
		status = http.StatusOK
	}
	resp := &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(m.response)),
	}
	resp.Header.Set("Content-Type", "application/json")
	return resp, nil
}

func createTestAIClient(responseContent string) *ai.Client {
	b, _ := json.Marshal(responseContent)
	respJSON := `{"choices":[{"message":{"role":"assistant","content":` + string(b) + `}}]} `
	transport := &mockHTTPTransport{response: respJSON}
	client, _ := ai.New(ai.Config{
		BaseURL:    "http://mock-ai.local/v1",
		APIKey:     "test-key",
		HTTPClient: &http.Client{Transport: transport},
	})
	return client
}

func TestAIHandlers(t *testing.T) {
	log := logging.New("error")
	secret := "test-secret-key-32-bytes-long!!!"
	tenantID := uuid.New()
	userID := uuid.New()

	token, _, err := auth.IssueToken(secret, time.Hour, userID, tenantID, auth.RoleOwner)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("AI Analyze Finding Endpoint", func(t *testing.T) {
		aiResp := "## Risk assessment\nHigh risk\n## Impact\nData leak\n## Recommended remediation\nRestrict S3 bucket"
		aiClient := createTestAIClient(aiResp)

		srv := NewServer(nil, log, secret, time.Hour)
		srv.EnableAI(aiClient)

		body, _ := json.Marshal(map[string]string{
			"rule_id":     "CASTRA-S3-001",
			"title":       "Public S3 Bucket",
			"severity":    "critical",
			"description": "S3 bucket is publicly accessible",
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/ai/analyze", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		srv.Router().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
		}

		var res map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if res["analysis"] != aiResp {
			t.Fatalf("unexpected analysis: %q", res["analysis"])
		}
	})

	t.Run("AI Disabled Returns 503 Service Unavailable", func(t *testing.T) {
		srvDisabled := NewServer(nil, log, secret, time.Hour)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/ai/analyze", bytes.NewBufferString("{}"))
		req.Header.Set("Authorization", "Bearer "+token)
		srvDisabled.Router().ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", rec.Code)
		}
	})
}
