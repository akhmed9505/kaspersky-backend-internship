//go:build integration

package integration_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/infra/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Each fixture creates its own database; no existing database is migrated or cleared.
func testDatabase(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set TEST_POSTGRES_ADMIN_DSN to a PostgreSQL URL with CREATEDB permission")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		t.Fatal("TEST_POSTGRES_ADMIN_DSN must be a PostgreSQL URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("cannot connect to test administrator database; verify connectivity and credentials")
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		_ = admin.Close(ctx)
		t.Fatal(err)
	}
	database := "ies_test_" + hex.EncodeToString(nonce[:])
	quoted := pgx.Identifier{database}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted+" TEMPLATE template0 ENCODING 'UTF8'"); err != nil {
		_ = admin.Close(ctx)
		t.Fatal("cannot create isolated test database; CREATEDB permission is required")
	}
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		cleanupCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanupCtx, "DROP DATABASE "+quoted+" WITH (FORCE)"); err != nil {
			t.Errorf("failed to remove isolated database %s", database)
		}
		if err := admin.Close(cleanupCtx); err != nil {
			t.Error("failed to close administrator connection")
		}
	})
	parsed.Path = "/" + database
	parsed.RawPath = ""
	query := parsed.Query()
	query.Del("dbname")
	parsed.RawQuery = query.Encode()
	testDSN := parsed.String()
	config, err := pgx.ParseConfig(testDSN)
	if err != nil || config.Database != database {
		t.Fatal("test DSN must point exclusively to the newly created database")
	}
	pool, err = postgres.NewPool(ctx, postgres.Config{DSN: testDSN, MaxConns: 8})
	if err != nil {
		t.Fatal("cannot initialize test pool")
	}
	applyMigration(t, pool, "up")
	return pool, testDSN
}

func applyMigration(t *testing.T, pool *pgxpool.Pool, direction string) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate migration directory")
	}
	sql, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "migrations", "000001_create_threats."+direction+".sql"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, string(sql)); err != nil {
		t.Fatalf("migration %s failed: %v", direction, err)
	}
}
