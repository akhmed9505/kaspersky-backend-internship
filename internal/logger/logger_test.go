package logger_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/logger"
)

func TestStructuredLogging(t *testing.T) {
	var output bytes.Buffer
	log := logger.New(&output, slog.LevelInfo)
	log.Debug("hidden")
	log.Info("ready", "component", "server")
	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if entry["msg"] != "ready" || entry["component"] != "server" {
		t.Fatal("unexpected structured log")
	}
	output.Reset()
	logger.HTTPErrorLog(log).Print("request-or-panic-secret")
	if strings.Contains(output.String(), "request-or-panic-secret") || !strings.Contains(output.String(), "HTTP transport error") {
		t.Fatal("raw server error leaked")
	}
}
