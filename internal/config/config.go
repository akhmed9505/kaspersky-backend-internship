// Package config loads and validates environment settings without reading .env.
package config

import (
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config contains validated startup settings. APIKey and DatabaseDSN are secrets;
// never log Config or its secret fields.
type Config struct {
	Address                string
	CertificateFile        string
	PrivateKeyFile         string
	APIKey                 string
	DatabaseDSN            string
	DatabaseMaxConns       int32
	DatabaseConnectTimeout time.Duration
	ReadHeaderTimeout      time.Duration
	ReadTimeout            time.Duration
	WriteTimeout           time.Duration
	IdleTimeout            time.Duration
	RequestTimeout         time.Duration
	ShutdownTimeout        time.Duration
	MaxHeaderBytes         int
	GlobalRPS              float64
	GlobalBurst            int
	AuthorizedRPS          float64
	AuthorizedBurst        int
	LogLevel               slog.Level
}

// Load reads process environment, including API_KEY and DB_PASSWORD.
// TLS certificate/key paths are validated; no .env file is loaded.
func Load() (Config, error) { return load(os.LookupEnv) }

func load(lookup func(string) (string, bool)) (Config, error) {
	value := func(key, fallback string) string {
		v, ok := lookup(key)
		if !ok {
			return fallback
		}
		return v
	}
	c := Config{Address: value("HTTPS_ADDR", ":8443"), CertificateFile: value("TLS_CERT_FILE", ""), PrivateKeyFile: value("TLS_KEY_FILE", "")}
	if _, _, err := net.SplitHostPort(c.Address); err != nil {
		return Config{}, fmt.Errorf("HTTPS_ADDR must contain host and port")
	}
	_, port, _ := net.SplitHostPort(c.Address)
	if !validPort(port) {
		return Config{}, fmt.Errorf("HTTPS_ADDR port must be between 1 and 65535")
	}
	for key, path := range map[string]string{"TLS_CERT_FILE": c.CertificateFile, "TLS_KEY_FILE": c.PrivateKeyFile} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return Config{}, fmt.Errorf("%s must name a readable certificate/key file", key)
		}
	}
	var err error
	c.APIKey = value("API_KEY", "")
	if len(c.APIKey) < 32 || strings.IndexFunc(c.APIKey, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return Config{}, fmt.Errorf("API_KEY must contain at least 32 printable ASCII bytes without whitespace")
	}
	password := value("DB_PASSWORD", "")
	if password == "" || strings.ContainsRune(password, '\x00') {
		return Config{}, fmt.Errorf("DB_PASSWORD must be nonempty and must not contain U+0000")
	}
	host, dbPort, user, name := value("DB_HOST", "127.0.0.1"), value("DB_PORT", "5432"), value("DB_USER", ""), value("DB_NAME", "")
	if host == "" || user == "" || name == "" || !validPort(dbPort) {
		return Config{}, fmt.Errorf("DB_HOST, DB_USER, DB_NAME and a valid DB_PORT are required")
	}
	sslMode := value("DB_SSLMODE", "verify-full")
	switch sslMode {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
	default:
		return Config{}, fmt.Errorf("invalid DB_SSLMODE")
	}
	dsn := url.URL{Scheme: "postgres", User: url.UserPassword(user, password), Host: net.JoinHostPort(host, dbPort), Path: "/" + name}
	query := url.Values{"sslmode": {sslMode}}
	dsn.RawQuery = query.Encode()
	c.DatabaseDSN = dsn.String()
	durations := []struct {
		key, fallback string
		target        *time.Duration
	}{
		{"DB_CONNECT_TIMEOUT", "5s", &c.DatabaseConnectTimeout}, {"HTTP_READ_HEADER_TIMEOUT", "5s", &c.ReadHeaderTimeout},
		{"HTTP_READ_TIMEOUT", "10s", &c.ReadTimeout}, {"HTTP_WRITE_TIMEOUT", "10s", &c.WriteTimeout},
		{"HTTP_IDLE_TIMEOUT", "60s", &c.IdleTimeout}, {"REQUEST_TIMEOUT", "5s", &c.RequestTimeout}, {"SHUTDOWN_TIMEOUT", "10s", &c.ShutdownTimeout},
	}
	for _, setting := range durations {
		*setting.target, err = time.ParseDuration(value(setting.key, setting.fallback))
		if err != nil || *setting.target <= 0 {
			return Config{}, fmt.Errorf("%s must be a positive duration", setting.key)
		}
	}
	if c.ReadHeaderTimeout > c.ReadTimeout || c.RequestTimeout >= c.WriteTimeout {
		return Config{}, fmt.Errorf("header timeout must not exceed read timeout; write timeout must exceed request timeout")
	}
	integers := []struct {
		key, fallback string
		target        *int
	}{{"HTTP_MAX_HEADER_BYTES", "16384", &c.MaxHeaderBytes}, {"GLOBAL_BURST", "200", &c.GlobalBurst}, {"AUTHORIZED_BURST", "20", &c.AuthorizedBurst}}
	for _, setting := range integers {
		*setting.target, err = strconv.Atoi(value(setting.key, setting.fallback))
		if err != nil || *setting.target <= 0 {
			return Config{}, fmt.Errorf("%s must be a positive integer", setting.key)
		}
	}
	maxConns, err := strconv.ParseInt(value("DB_MAX_CONNS", "10"), 10, 32)
	if err != nil || maxConns <= 0 {
		return Config{}, fmt.Errorf("DB_MAX_CONNS must be a positive int32")
	}
	c.DatabaseMaxConns = int32(maxConns)
	for _, setting := range []struct {
		key, fallback string
		target        *float64
	}{{"GLOBAL_RPS", "100", &c.GlobalRPS}, {"AUTHORIZED_RPS", "10", &c.AuthorizedRPS}} {
		*setting.target, err = strconv.ParseFloat(value(setting.key, setting.fallback), 64)
		if err != nil || *setting.target <= 0 || math.IsNaN(*setting.target) || math.IsInf(*setting.target, 0) || math.IsInf(1 / *setting.target, 0) {
			return Config{}, fmt.Errorf("%s must be a finite positive rate", setting.key)
		}
	}
	if err := c.LogLevel.UnmarshalText([]byte(value("LOG_LEVEL", "INFO"))); err != nil {
		return Config{}, fmt.Errorf("invalid LOG_LEVEL")
	}
	return c, nil
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port > 0 && port <= 65535
}
