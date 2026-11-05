package middleware_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/delivery/http/middleware"
	applog "github.com/akhmed9505/kaspersky-backend-internship/internal/logger"
)

const apiKey = "0123456789abcdef0123456789abcdef"

func settings() middleware.Config {
	return middleware.Config{APIKey: apiKey, GlobalRPS: 100, GlobalBurst: 200, AuthorizedRPS: 10, AuthorizedBurst: 20, RequestTimeout: time.Second}
}
func wrap(t *testing.T, next http.Handler, c middleware.Config, output io.Writer) http.Handler {
	t.Helper()
	handler, err := middleware.New(next, c, applog.New(output, slog.LevelInfo))
	if err != nil {
		t.Fatal(err)
	}
	return handler
}
func send(handler http.Handler, keys ...string) *httptest.ResponseRecorder {
	request := httptest.NewRequest("POST", "/info?password=query-secret", strings.NewReader("body-secret"))
	for _, key := range keys {
		request.Header.Add("X-API-Key", key)
	}
	request.Header.Set("X-Request-ID", "client-controlled")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
func assertError(t *testing.T, response *httptest.ResponseRecorder, status int) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status %d, want %d", response.Code, status)
	}
	var body struct {
		Message string `json:"message"`
	}
	if response.Header().Get("Content-Type") != "application/json" || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Message == "" {
		t.Fatal("invalid JSON error")
	}
	if response.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing request ID")
	}
}

func TestAuthenticationAndRequestID(t *testing.T) {
	var calls int
	var id string
	handler := wrap(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		id = middleware.RequestID(r.Context())
		if _, ok := r.Context().Deadline(); !ok {
			t.Error("missing request deadline")
		}
		w.WriteHeader(204)
	}), settings(), io.Discard)
	seen := map[string]bool{}
	for _, keys := range [][]string{nil, {"wrong"}, {apiKey, apiKey}, {apiKey, "wrong"}, {""}, {apiKey + ",wrong"}} {
		response := send(handler, keys...)
		assertError(t, response, 401)
		if response.Header().Get("WWW-Authenticate") == "" {
			t.Fatal("missing challenge")
		}
		current := response.Header().Get("X-Request-ID")
		if current == "client-controlled" || seen[current] {
			t.Fatal("request ID reused/trusted client")
		}
		seen[current] = true
	}
	response := send(handler, apiKey)
	if response.Code != 204 || calls != 1 || id != response.Header().Get("X-Request-ID") {
		t.Fatal("authorized request or context failed")
	}
	if middleware.RequestID(context.Background()) != "" {
		t.Fatal("unexpected request ID")
	}
}

func TestLimiterPriority(t *testing.T) {
	c := settings()
	c.GlobalRPS = 0.000001
	c.GlobalBurst = 2
	c.AuthorizedRPS = 0.000001
	c.AuthorizedBurst = 1
	calls := 0
	handler := wrap(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) }), c, io.Discard)
	if response := send(handler, apiKey); response.Code != 204 {
		t.Fatal("first request rejected")
	}
	assertError(t, send(handler, apiKey), 429)
	// Even invalid authentication now receives the global limit error first.
	response := send(handler, "wrong")
	assertError(t, response, 429)
	if response.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("authentication ran before global limiter")
	}
	if seconds, err := strconv.Atoi(response.Header().Get("Retry-After")); err != nil || seconds < 1 {
		t.Fatal("invalid Retry-After")
	}
	if calls != 1 {
		t.Fatal("limited request reached router")
	}
	c.GlobalBurst = 10
	handler = wrap(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }), c, io.Discard)
	assertError(t, send(handler, "wrong"), 401)
	if send(handler, apiKey).Code != 204 {
		t.Fatal("unauthorized request consumed authorized quota")
	}
	assertError(t, send(handler, apiKey), 429)
	assertError(t, send(handler, "wrong"), 401)
}

func TestConcurrentRateLimiting(t *testing.T) {
	c := settings()
	c.GlobalRPS = 0.000001
	c.AuthorizedRPS = 0.000001
	c.AuthorizedBurst = 1
	var successes atomic.Int32
	var invalid atomic.Int32
	handler := wrap(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { successes.Add(1); w.WriteHeader(204) }), c, io.Discard)
	var workers sync.WaitGroup
	for i := 0; i < 80; i++ {
		workers.Go(func() {
			code := send(handler, apiKey).Code
			if code != 204 && code != 429 {
				invalid.Add(1)
			}
		})
	}
	workers.Wait()
	if successes.Load() != 1 || invalid.Load() != 0 {
		t.Fatal("concurrent limiter failed")
	}
}

func TestDeadlineAndSafeLogging(t *testing.T) {
	var output bytes.Buffer
	c := settings()
	c.RequestTimeout = time.Millisecond
	handler := wrap(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Pattern = "POST /info"
		<-r.Context().Done()
		if !errors.Is(r.Context().Err(), context.DeadlineExceeded) {
			t.Error("wrong cancellation")
		}
		w.WriteHeader(500)
	}), c, &output)
	response := send(handler, apiKey)
	if response.Code != 500 {
		t.Fatal("unexpected status")
	}
	log := output.String()
	for _, secret := range []string{apiKey, "query-secret", "body-secret", "client-controlled"} {
		if strings.Contains(log, secret) {
			t.Fatal("secret in logs")
		}
	}
	if !strings.Contains(log, response.Header().Get("X-Request-ID")) || !strings.Contains(log, `"status":500`) {
		t.Fatal("missing structured request fields")
	}
	if !strings.Contains(log, `"route":"POST /info"`) {
		t.Fatal("route pattern was lost across context wrapping")
	}
}

func TestRecovery(t *testing.T) {
	var output bytes.Buffer
	handler := wrap(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("panic-secret") }), settings(), &output)
	response := send(handler, apiKey)
	assertError(t, response, 500)
	if strings.Contains(output.String(), "panic-secret") || strings.Contains(response.Body.String(), "panic-secret") {
		t.Fatal("panic data leaked")
	}
	t.Run("committed response", func(t *testing.T) {
		handler := wrap(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("started")); panic("private") }), settings(), io.Discard)
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("committed response must abort connection")
			}
		}()
		send(handler, apiKey)
		t.Error("expected abort")
	})
}

func TestInvalidConfig(t *testing.T) {
	for _, change := range []func(*middleware.Config){func(c *middleware.Config) { c.APIKey = "short" }, func(c *middleware.Config) { c.GlobalBurst = 0 }, func(c *middleware.Config) { c.AuthorizedRPS = 0 }, func(c *middleware.Config) { c.RequestTimeout = 0 }} {
		c := settings()
		change(&c)
		if _, err := middleware.New(http.NotFoundHandler(), c, applog.New(io.Discard, slog.LevelInfo)); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
}
