package config

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func environment(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{"cert": "certificate", "key": "private key"}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return map[string]string{"TLS_CERT_FILE": filepath.Join(dir, "cert"), "TLS_KEY_FILE": filepath.Join(dir, "key"), "API_KEY": strings.Repeat("a", 32), "DB_PASSWORD": "p@ss:/word", "DB_USER": "test user", "DB_NAME": "threats"}
}
func fromMap(values map[string]string) (Config, error) {
	return load(func(key string) (string, bool) { v, ok := values[key]; return v, ok })
}

func TestDefaults(t *testing.T) {
	cfg, err := fromMap(environment(t))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != ":8443" || cfg.GlobalRPS != 100 || cfg.GlobalBurst != 200 || cfg.AuthorizedRPS != 10 || cfg.AuthorizedBurst != 20 {
		t.Fatalf("invalid defaults: address or rates")
	}
	if cfg.ReadHeaderTimeout != 5*time.Second || cfg.ReadTimeout != 10*time.Second || cfg.WriteTimeout != 10*time.Second || cfg.IdleTimeout != 60*time.Second || cfg.RequestTimeout != 5*time.Second || cfg.ShutdownTimeout != 10*time.Second || cfg.MaxHeaderBytes != 16384 || cfg.DatabaseMaxConns != 10 {
		t.Fatal("invalid timeout/pool defaults")
	}
	u, err := url.Parse(cfg.DatabaseDSN)
	if err != nil {
		t.Fatal("invalid DSN")
	}
	password, _ := u.User.Password()
	if u.User.Username() != "test user" || password != "p@ss:/word" || u.Query().Get("sslmode") != "verify-full" || cfg.APIKey != strings.Repeat("a", 32) {
		t.Fatal("secret encoding failed")
	}
}

func TestInvalidSettings(t *testing.T) {
	cases := map[string][]string{
		"HTTPS_ADDR": {"missingport", ":0", ":65536"}, "DB_PORT": {"-1", "65536", "invalid"}, "DB_HOST": {""}, "DB_USER": {""}, "DB_NAME": {""}, "DB_SSLMODE": {"insecure"},
		"DB_MAX_CONNS": {"0", "-1", "2147483648"}, "LOG_LEVEL": {"unknown"}, "GLOBAL_RPS": {"0", "-1", "NaN", "Inf", "bad", "1e-320"}, "AUTHORIZED_RPS": {"0"}, "GLOBAL_BURST": {"0"}, "AUTHORIZED_BURST": {"bad"}, "HTTP_MAX_HEADER_BYTES": {"0"},
		"TLS_CERT_FILE": {"/missing/cert"}, "TLS_KEY_FILE": {"/missing/key"}, "API_KEY": {"", "short"}, "DB_PASSWORD": {"", "\x00"},
	}
	for _, key := range []string{"DB_CONNECT_TIMEOUT", "HTTP_READ_HEADER_TIMEOUT", "HTTP_READ_TIMEOUT", "HTTP_WRITE_TIMEOUT", "HTTP_IDLE_TIMEOUT", "REQUEST_TIMEOUT", "SHUTDOWN_TIMEOUT"} {
		cases[key] = []string{"0s", "-1s", "bad"}
	}
	for key, values := range cases {
		for _, value := range values {
			t.Run(key+"="+value, func(t *testing.T) {
				values := environment(t)
				values[key] = value
				_, err := fromMap(values)
				if err == nil {
					t.Fatal("accepted invalid setting")
				}
				if strings.Contains(err.Error(), "p@ss:/word") || strings.Contains(err.Error(), strings.Repeat("a", 32)) {
					t.Fatal("error leaked secrets")
				}
			})
		}
	}
	for _, overrides := range []map[string]string{{"HTTP_READ_HEADER_TIMEOUT": "11s"}, {"REQUEST_TIMEOUT": "10s"}} {
		values := environment(t)
		for key, value := range overrides {
			values[key] = value
		}
		if _, err := fromMap(values); err == nil {
			t.Fatal("inconsistent timeouts accepted")
		}
	}
}

func TestSecretValidation(t *testing.T) {
	for _, secret := range []string{"", "short", strings.Repeat("a", 31), strings.Repeat("a", 32) + "\x00", strings.Repeat("a", 32) + " b", " " + strings.Repeat("a", 32), strings.Repeat("a", 32) + "\n"} {
		values := environment(t)
		values["API_KEY"] = secret
		if _, err := fromMap(values); err == nil {
			t.Fatal("invalid API key accepted")
		}
	}
}

func TestLoadDoesNotReadDotEnv(t *testing.T) {
	values := environment(t)
	for key, value := range values {
		t.Setenv(key, value)
	}
	t.Setenv("GLOBAL_RPS", "100")
	t.Setenv("HTTPS_ADDR", ":8443")
	t.Chdir(t.TempDir())
	if err := os.WriteFile(".env", []byte("HTTPS_ADDR=bad\nGLOBAL_RPS=0\nAPI_KEY=ignored\nDB_PASSWORD=ignored\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != ":8443" || cfg.GlobalRPS != 100 || cfg.APIKey != values["API_KEY"] {
		t.Fatal(".env affected configuration")
	}
}

func TestRequiredSecrets(t *testing.T) {
	for _, key := range []string{"API_KEY", "DB_PASSWORD"} {
		values := environment(t)
		delete(values, key)
		if _, err := fromMap(values); err == nil {
			t.Fatalf("missing %s accepted", key)
		}
	}
}

func TestPasswordIsPreserved(t *testing.T) {
	values := environment(t)
	values["DB_PASSWORD"] = " p@ss:/word$'\" \n"
	cfg, err := fromMap(values)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(cfg.DatabaseDSN)
	if err != nil {
		t.Fatal("invalid DSN")
	}
	password, _ := parsed.User.Password()
	if password != values["DB_PASSWORD"] {
		t.Fatal("password was trimmed or incorrectly encoded")
	}
}
