package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	httpapi "github.com/akhmed9505/kaspersky-backend-internship/internal/delivery/http"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/delivery/http/generated"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/domain"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/service/threat"
)

const testMD5 = "abcdef0123456789abcdef0123456789"

type fakeRepository struct {
	rows    map[string]domain.Threat
	calls   int
	ctx     context.Context
	failure error
}

func (f *fakeRepository) Create(ctx context.Context, id string, data domain.ThreatData) (domain.Threat, error) {
	f.calls++
	f.ctx = ctx
	if f.failure != nil {
		return domain.Threat{}, f.failure
	}
	if _, exists := f.rows[id]; exists {
		return domain.Threat{}, fmt.Errorf("insert: %w", threat.ErrAlreadyExists)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 123456000, time.UTC)
	row := domain.Threat{MD5: id, ThreatData: data, CreatedAt: now, UpdatedAt: now}
	f.rows[id] = row
	return row, nil
}
func (f *fakeRepository) Get(ctx context.Context, id string) (domain.Threat, error) {
	f.calls++
	f.ctx = ctx
	if f.failure != nil {
		return domain.Threat{}, f.failure
	}
	row, ok := f.rows[id]
	if !ok {
		return domain.Threat{}, fmt.Errorf("select: %w", threat.ErrNotFound)
	}
	return row, nil
}
func (f *fakeRepository) Update(ctx context.Context, id string, data domain.ThreatData) (domain.Threat, error) {
	f.calls++
	f.ctx = ctx
	if f.failure != nil {
		return domain.Threat{}, f.failure
	}
	row, ok := f.rows[id]
	if !ok {
		return domain.Threat{}, threat.ErrNotFound
	}
	row.ThreatData = data
	row.UpdatedAt = row.UpdatedAt.Add(time.Second)
	f.rows[id] = row
	return row, nil
}
func setup() (http.Handler, *fakeRepository) {
	repo := &fakeRepository{rows: make(map[string]domain.Threat)}
	return httpapi.NewRouter(httpapi.NewHandler(threat.New(repo))), repo
}
func request(router http.Handler, method, path, body, contentType string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}
func assertStatus(t *testing.T, got *httptest.ResponseRecorder, status int) {
	t.Helper()
	if got.Code != status {
		t.Fatalf("status %d, want %d: %s", got.Code, status, got.Body.String())
	}
	if got.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content type: %s", got.Header().Get("Content-Type"))
	}
	if status >= 400 {
		var response generated.ErrorResponse
		if err := json.Unmarshal(got.Body.Bytes(), &response); err != nil || response.Message == "" {
			t.Fatalf("invalid ErrorResponse: %s (%v)", got.Body.String(), err)
		}
	}
}
func decodeResponse(t *testing.T, got *httptest.ResponseRecorder) generated.ThreatResponse {
	t.Helper()
	var response generated.ThreatResponse
	if err := json.Unmarshal(got.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(got.Body.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"md5", "name", "description", "severity", "created_at", "updated_at"} {
		if value, exists := fields[key]; !exists || string(value) == "null" {
			t.Fatalf("missing required response field %s", key)
		}
	}
	return response
}

func TestHTTPCreateGetPut(t *testing.T) {
	router, repo := setup()
	body := `{"md5":"` + strings.ToUpper(testMD5) + `","name":" Original ","description":"text","severity":"high","file_type":"pe","first_seen_at":"2099-01-01T12:00:00.123456789+03:00"}`
	res := request(router, "POST", "/info", body, "application/json; charset=utf-8")
	assertStatus(t, res, 201)
	created := decodeResponse(t, res)
	if created.Md5 != testMD5 || created.Name != " Original " || created.Description != "text" || created.Severity != "high" || created.FileType == nil || *created.FileType != "pe" {
		t.Fatalf("mapping: %+v", created)
	}
	if created.FirstSeenAt == nil || created.FirstSeenAt.Location() != time.UTC || created.FirstSeenAt.Nanosecond() != 123456000 {
		t.Fatalf("time mapping: %v", created.FirstSeenAt)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	get := httptest.NewRequest("GET", "/info/"+strings.ToUpper(testMD5), nil).WithContext(ctx)
	got := httptest.NewRecorder()
	router.ServeHTTP(got, get)
	assertStatus(t, got, 200)
	if repo.ctx != ctx {
		t.Fatal("request context not propagated")
	}
	if decodeResponse(t, got).Md5 != testMD5 {
		t.Fatal("GET normalization failed")
	}
	duplicate := request(router, "POST", "/info", body, "application/json")
	assertStatus(t, duplicate, 409)
	put := request(router, "PUT", "/info/"+strings.ToUpper(testMD5), `{"name":"Replaced"}`, "application/json")
	assertStatus(t, put, 200)
	updated := decodeResponse(t, put)
	if updated.Name != "Replaced" || updated.Description != "" || updated.Severity != "unknown" || updated.FileType != nil || updated.FirstSeenAt != nil {
		t.Fatalf("PUT reset: %+v", updated)
	}
	if !updated.CreatedAt.Equal(*created.CreatedAt) || !updated.UpdatedAt.After(*created.UpdatedAt) {
		t.Fatal("timestamps lost")
	}
	for _, key := range []string{"file_type", "first_seen_at"} {
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(put.Body.Bytes(), &fields)
		if _, ok := fields[key]; ok {
			t.Fatalf("unknown %s must be omitted", key)
		}
	}
	// A known year-one timestamp must not be dropped as an unknown value.
	known := request(router, "PUT", "/info/"+testMD5, `{"name":"Known","severity":"critical","description":"updated","file_type":"elf","first_seen_at":"0001-01-01T00:00:00Z"}`, "application/json")
	assertStatus(t, known, 200)
	value := decodeResponse(t, known)
	if value.FirstSeenAt == nil || !value.FirstSeenAt.IsZero() || value.Description != "updated" || value.Severity != "critical" || value.FileType == nil || *value.FileType != "elf" {
		t.Fatalf("full PUT mapping: %+v", value)
	}
}

func TestHTTPDefaultsAndNotFound(t *testing.T) {
	router, _ := setup()
	res := request(router, "POST", "/info", `{"md5":"`+testMD5+`","name":"x"}`, "application/json")
	assertStatus(t, res, 201)
	got := decodeResponse(t, res)
	if got.Description != "" || got.Severity != "unknown" || got.FileType != nil || got.FirstSeenAt != nil {
		t.Fatal("wrong defaults")
	}
	assertStatus(t, request(router, "GET", "/info/"+strings.Repeat("0", 32), "", ""), 404)
	assertStatus(t, request(router, "PUT", "/info/"+strings.Repeat("0", 32), `{"name":"x"}`, "application/json"), 404)
}

func TestHTTPInfrastructureErrors(t *testing.T) {
	for _, method := range []string{"POST", "GET", "PUT"} {
		t.Run(method, func(t *testing.T) {
			router, repo := setup()
			repo.failure = errors.New("password=secret SQL internal details")
			path := "/info/" + testMD5
			body := `{"name":"x"}`
			if method == "POST" {
				path = "/info"
				body = `{"md5":"` + testMD5 + `","name":"x"}`
			}
			res := request(router, method, path, body, "application/json")
			assertStatus(t, res, 500)
			if strings.Contains(res.Body.String(), "secret") || strings.Contains(res.Body.String(), "SQL") {
				t.Fatal("internal error leaked")
			}
		})
	}
}

func TestHTTPRoutingAndPriority(t *testing.T) {
	cases := []struct {
		name, method, path, body, contentType string
		status                                int
		allow                                 string
	}{
		{"unknown", "POST", "/missing", "broken", "text/plain", 404, ""},
		{"noncanonical path", "GET", "/info//bad", "", "", 404, ""},
		{"trailing slash", "POST", "/info/", "", "", 404, ""},
		{"collection method", "GET", "/info", "", "", 405, "POST"},
		{"record method before MD5", "DELETE", "/info/bad", "broken", "text/plain", 405, "GET, PUT"},
		{"HEAD collection", "HEAD", "/info", "", "", 405, "POST"},
		{"HEAD record", "HEAD", "/info/" + testMD5, "", "", 405, "GET, PUT"},
		{"GET bad MD5", "GET", "/info/bad", "", "", 400, ""},
		{"path before content type", "PUT", "/info/bad", "broken", "text/plain", 400, ""},
		{"content type before size", "POST", "/info", strings.Repeat("x", 65537), "text/plain", 415, ""},
		{"size before JSON", "POST", "/info", strings.Repeat("x", 65537), "application/json", 413, ""},
		{"JSON before missing", "PUT", "/info/" + testMD5, `{}`, "application/json", 400, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, repo := setup()
			res := request(router, tc.method, tc.path, tc.body, tc.contentType)
			assertStatus(t, res, tc.status)
			if res.Header().Get("Allow") != tc.allow {
				t.Fatalf("Allow=%q", res.Header().Get("Allow"))
			}
			if repo.calls != 0 {
				t.Fatal("invalid request reached repository")
			}
		})
	}
	router, repo := setup()
	body := `{"md5":"` + testMD5 + `","name":"x"}`
	assertStatus(t, request(router, "POST", "/info", body, "application/json"), 201)
	calls := repo.calls
	assertStatus(t, request(router, "POST", "/info", `{"md5":"`+testMD5+`","name":""}`, "application/json"), 400)
	if repo.calls != calls {
		t.Fatal("invalid POST checked duplicate before validation")
	}
}

// failingBody exercises a read failure without a socket or database.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (failingBody) Close() error             { return nil }
func TestHTTPReadFailure(t *testing.T) {
	router, repo := setup()
	req := httptest.NewRequest("POST", "/info", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Body = failingBody{}
	res := httptest.NewRecorder()
	router.ServeHTTP(res, req)
	assertStatus(t, res, 400)
	if repo.calls != 0 {
		t.Fatal("read failure reached repository")
	}
}
