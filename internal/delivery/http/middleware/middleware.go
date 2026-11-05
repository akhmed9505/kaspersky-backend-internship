// Package middleware provides API protection and request observability.
package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/delivery/http/generated"
	"golang.org/x/time/rate"
)

// Config configures two process-local token buckets and request context deadlines.
// APIKey is secret and must never be logged.
type Config struct {
	APIKey          string
	GlobalRPS       float64
	GlobalBurst     int
	AuthorizedRPS   float64
	AuthorizedBurst int
	RequestTimeout  time.Duration
}

type requestIDKey struct{}

// RequestID returns the server-generated identifier from a request context.
func RequestID(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey{}).(string)
	return value
}

// New wraps a router in Request ID, access log, recovery, global limiter, API Key,
// authorized limiter and deadline, in that order. The supplied logger must be non-nil.
func New(next http.Handler, c Config, logger *slog.Logger) (http.Handler, error) {
	validRate := func(v float64) bool { return v > 0 && !math.IsNaN(v) && !math.IsInf(v, 0) && !math.IsInf(1/v, 0) }
	if len(c.APIKey) < 32 || !validRate(c.GlobalRPS) || !validRate(c.AuthorizedRPS) || c.GlobalBurst < 1 || c.AuthorizedBurst < 1 || c.RequestTimeout <= 0 {
		return nil, fmt.Errorf("invalid HTTP middleware configuration")
	}
	keyHash := sha256.Sum256([]byte(c.APIKey))
	handler := deadline(next, c.RequestTimeout)
	handler = limit(handler, rate.NewLimiter(rate.Limit(c.AuthorizedRPS), c.AuthorizedBurst), c.AuthorizedRPS)
	handler = authenticate(handler, keyHash)
	handler = limit(handler, rate.NewLimiter(rate.Limit(c.GlobalRPS), c.GlobalBurst), c.GlobalRPS)
	handler = recoverPanic(handler, logger)
	handler = accessLog(handler, logger)
	return requestID(handler), nil
}

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := rand.Text()
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

func authenticate(next http.Handler, expected [32]byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("X-API-Key")
		if len(values) != 1 {
			unauthorized(w)
			return
		}
		actual := sha256.Sum256([]byte(values[0]))
		if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
			unauthorized(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `ApiKey realm="information-exchange"`)
	writeError(w, 401, "Invalid API Key")
}

func limit(next http.Handler, limiter *rate.Limiter, rps float64) http.Handler {
	// With Allow (no queued reservations), one token interval is a conservative
	// upper bound on refill time. Retry-After is an integer and at least one second.
	retry := fmt.Sprintf("%.0f", math.Max(1, math.Ceil(1/rps)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			w.Header().Set("Retry-After", retry)
			writeError(w, 429, "Rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func deadline(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		child := r.WithContext(ctx)
		// ServeMux sets Pattern on the child; retain it for the outer access log.
		defer func() { r.Pattern = child.Pattern }()
		next.ServeHTTP(w, child)
	})
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(generated.ErrorResponse{Message: message})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func accessLog(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		tracked := &statusWriter{ResponseWriter: w}
		defer func() {
			status := tracked.status
			if status == 0 {
				status = 200
			}
			logger.InfoContext(r.Context(), "HTTP request", "request_id", RequestID(r.Context()), "method", r.Method, "route", r.Pattern, "status", status, "duration", time.Since(start))
		}()
		next.ServeHTTP(tracked, r)
	})
}
func recoverPanic(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.ErrorContext(r.Context(), "HTTP handler panic", "request_id", RequestID(r.Context()))
				tracked := w.(*statusWriter)
				if tracked.status != 0 {
					panic(http.ErrAbortHandler)
				}
				writeError(w, 500, "Internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
