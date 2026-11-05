//go:build integration

package integration_test

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	httpapi "github.com/akhmed9505/kaspersky-backend-internship/internal/delivery/http"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/delivery/http/generated"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/delivery/http/middleware"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/repository"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/service/threat"
)

// TestHTTPSScenario uses an isolated real database and actual TLS HTTP requests.
func TestHTTPSScenario(t *testing.T) {
	pool, _ := testDatabase(t)
	router := httpapi.NewRouter(httpapi.NewHandler(threat.New(repository.NewThreat(pool))))
	const key = "integration-only-key-00000000000000000000"
	handler, err := middleware.New(router, middleware.Config{APIKey: key, GlobalRPS: 100, GlobalBurst: 200, AuthorizedRPS: 10, AuthorizedBurst: 20, RequestTimeout: 5 * time.Second}, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	client.Timeout = 10 * time.Second
	id, missing := strings.Repeat("a", 32), strings.Repeat("b", 32)
	call := func(method, path, body string, authenticated bool, status int) []byte {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if authenticated {
			req.Header.Set("X-API-Key", key)
		}
		if method != "GET" {
			req.Header.Set("Content-Type", "application/json")
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != status {
			t.Fatalf("%s %s: got %d, want %d: %s", method, path, response.StatusCode, status, raw)
		}
		if response.TLS == nil || response.TLS.Version < tls.VersionTLS12 {
			t.Fatal("TLS is required")
		}
		if response.Header.Get("Content-Type") != "application/json" || response.Header.Get("X-Request-ID") == "" {
			t.Fatal("missing contract headers")
		}
		if status >= 400 {
			var value generated.ErrorResponse
			if json.Unmarshal(raw, &value) != nil || value.Message == "" {
				t.Fatal("invalid ErrorResponse")
			}
		}
		return raw
	}
	decode := func(raw []byte) generated.ThreatResponse {
		t.Helper()
		var value generated.ThreatResponse
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		if value.CreatedAt == nil || value.UpdatedAt == nil {
			t.Fatal("missing system timestamps")
		}
		return value
	}
	call("GET", "/info/"+id, "", false, 401)
	call("GET", "/info/"+id, "", true, 404)
	create := `{"md5":"` + strings.ToUpper(id) + `","name":"HTTPS.Initial","description":"Details","severity":"high","file_type":"pe","first_seen_at":"2099-01-01T12:00:00+03:00"}`
	created := decode(call("POST", "/info", create, true, 201))
	if created.Md5 != id || created.Name != "HTTPS.Initial" || created.Description != "Details" || created.Severity != "high" || created.FileType == nil || *created.FileType != "pe" || created.FirstSeenAt == nil || created.FirstSeenAt.Location() != time.UTC {
		t.Fatal("create mapping failed")
	}
	got := decode(call("GET", "/info/"+strings.ToUpper(id), "", true, 200))
	if got.Md5 != created.Md5 || !got.CreatedAt.Equal(*created.CreatedAt) {
		t.Fatal("GET roundtrip failed")
	}
	updated := decode(call("PUT", "/info/"+strings.ToUpper(id), `{"name":"HTTPS.Updated"}`, true, 200))
	if updated.Name != "HTTPS.Updated" || updated.Description != "" || updated.Severity != "unknown" || updated.FileType != nil || updated.FirstSeenAt != nil || !updated.CreatedAt.Equal(*created.CreatedAt) {
		t.Fatal("PUT replacement failed")
	}
	got = decode(call("GET", "/info/"+id, "", true, 200))
	if got.Name != updated.Name || got.Description != "" || got.Severity != "unknown" || got.FirstSeenAt != nil || got.FileType != nil {
		t.Fatal("replacement not persisted")
	}
	call("POST", "/info", create, true, 409)
	call("GET", "/info/"+missing, "", true, 404)
}
