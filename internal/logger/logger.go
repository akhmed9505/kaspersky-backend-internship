// Package logger configures structured logging without a custom logging interface.
package logger

import (
	"io"
	"log"
	"log/slog"
)

// New returns a structured JSON logger writing at the requested minimum level.
func New(output io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: level}))
}

// HTTPErrorLog suppresses raw net/http error text, which may contain request or
// panic data, while still recording that a transport-level failure occurred.
func HTTPErrorLog(logger *slog.Logger) *log.Logger { return log.New(transportWriter{logger}, "", 0) }

type transportWriter struct{ logger *slog.Logger }

func (w transportWriter) Write(p []byte) (int, error) {
	w.logger.Warn("HTTP transport error")
	return len(p), nil
}
