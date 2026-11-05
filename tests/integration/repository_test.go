//go:build integration

package integration_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/domain"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/infra/postgres"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/repository"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/service/threat"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestRepositoryCRUD(t *testing.T) {
	pool, _ := testDatabase(t)
	repo := repository.NewThreat(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	id := strings.Repeat("a", 32)
	file := "pe"
	seen := time.Date(2099, 1, 1, 12, 0, 0, 123456000, time.FixedZone("MSK", 10800))
	data := domain.ThreatData{Name: "Trojan'; DROP TABLE threats; --", Description: strings.Repeat("я", 4096), Severity: domain.SeverityHigh, FileType: &file, FirstSeenAt: &seen}
	created, err := repo.Create(ctx, id, data)
	if err != nil {
		t.Fatal(err)
	}
	if created.MD5 != id || created.Name != data.Name || created.Description != data.Description || created.Severity != data.Severity || created.FileType == nil || *created.FileType != file {
		t.Fatalf("unexpected row: %+v", created)
	}
	if created.CreatedAt.IsZero() || !created.CreatedAt.Equal(created.UpdatedAt) {
		t.Fatal("invalid creation timestamps")
	}
	if created.FirstSeenAt == nil || !created.FirstSeenAt.Equal(seen) || created.FirstSeenAt.Location() != time.UTC || created.CreatedAt.Location() != time.UTC || created.UpdatedAt.Location() != time.UTC {
		t.Fatal("time roundtrip failed")
	}
	got, err := repo.Get(ctx, id)
	if err != nil || !reflect.DeepEqual(got, created) {
		t.Fatalf("get roundtrip: %+v %v", got, err)
	}
	if _, err := repo.Create(ctx, id, data); !errors.Is(err, threat.ErrAlreadyExists) {
		t.Fatalf("duplicate: %v", err)
	}
	// Deliberately old UpdatedAt makes the test independent of clock resolution and sleeps.
	if _, err := pool.Exec(ctx, "UPDATE threats SET updated_at = '2000-01-01T00:00:00Z' WHERE md5 = $1", id); err != nil {
		t.Fatal(err)
	}
	updated, err := repo.Update(ctx, id, domain.ThreatData{Name: "Replaced", Severity: domain.SeverityUnknown})
	if err != nil {
		t.Fatal(err)
	}
	if updated.MD5 != id || !updated.CreatedAt.Equal(created.CreatedAt) || updated.UpdatedAt.Year() == 2000 || updated.Name != "Replaced" || updated.Description != "" || updated.Severity != domain.SeverityUnknown || updated.FileType != nil || updated.FirstSeenAt != nil {
		t.Fatalf("replacement failed: %+v", updated)
	}
	zero := time.Time{}
	updated, err = repo.Update(ctx, id, domain.ThreatData{Name: "Known year one", Severity: domain.SeverityLow, FirstSeenAt: &zero})
	if err != nil || updated.FirstSeenAt == nil || !updated.FirstSeenAt.IsZero() {
		t.Fatalf("known zero time lost: %+v %v", updated, err)
	}
	missing := strings.Repeat("b", 32)
	if _, err := repo.Get(ctx, missing); !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	if _, err := repo.Update(ctx, missing, data); !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	if _, err := repo.Get(ctx, missing); !errors.Is(err, threat.ErrNotFound) {
		t.Fatal("update performed upsert")
	}
}

func TestConcurrentCreateAndCaseNormalization(t *testing.T) {
	pool, _ := testDatabase(t)
	service := threat.New(repository.NewThreat(pool))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	const count = 16
	start := make(chan struct{})
	results := make(chan error, count)
	var workers sync.WaitGroup
	for i := 0; i < count; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			<-start
			id := strings.Repeat("a", 32)
			if i%2 == 0 {
				id = strings.ToUpper(id)
			}
			_, err := service.Create(ctx, id, threat.Input{Name: "Concurrent"})
			results <- err
		}(i)
	}
	close(start)
	workers.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, threat.ErrAlreadyExists) {
			conflicts++
		} else {
			t.Fatalf("unexpected create error: %v", err)
		}
	}
	if successes != 1 || conflicts != count-1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
	if _, err := service.Get(ctx, strings.Repeat("A", 32)); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM threats").Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("row count %d: %v", rows, err)
	}
}

func TestDatabaseConstraints(t *testing.T) {
	pool, _ := testDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cases := []struct {
		name, sql string
		args      []any
		code      string
	}{
		{"uppercase MD5", "INSERT INTO threats(md5,name) VALUES($1,'x')", []any{strings.Repeat("A", 32)}, "23514"},
		{"short MD5", "INSERT INTO threats(md5,name) VALUES('abc','x')", nil, "23514"},
		{"nonhex MD5", "INSERT INTO threats(md5,name) VALUES($1,'x')", []any{strings.Repeat("g", 32)}, "23514"},
		{"empty name", "INSERT INTO threats(md5,name) VALUES($1,'')", []any{strings.Repeat("a", 32)}, "23514"},
		{"long name", "INSERT INTO threats(md5,name) VALUES($1,$2)", []any{strings.Repeat("a", 32), strings.Repeat("я", 256)}, "23514"},
		{"long description", "INSERT INTO threats(md5,name,description) VALUES($1,'x',$2)", []any{strings.Repeat("a", 32), strings.Repeat("я", 4097)}, "23514"},
		{"severity", "INSERT INTO threats(md5,name,severity) VALUES($1,'x','HIGH')", []any{strings.Repeat("a", 32)}, "23514"},
		{"empty format", "INSERT INTO threats(md5,name,file_type) VALUES($1,'x','')", []any{strings.Repeat("a", 32)}, "23514"},
		{"invalid format", "INSERT INTO threats(md5,name,file_type) VALUES($1,'x','PE')", []any{strings.Repeat("a", 32)}, "23514"},
		{"long format", "INSERT INTO threats(md5,name,file_type) VALUES($1,'x',$2)", []any{strings.Repeat("a", 32), strings.Repeat("a", 33)}, "23514"},
		{"infinite time", "INSERT INTO threats(md5,name,first_seen_at) VALUES($1,'x','infinity')", []any{strings.Repeat("a", 32)}, "23514"},
	}
	for _, column := range []string{"name", "description", "severity", "created_at", "updated_at"} {
		columns := "md5, name, " + column
		values := "$1, 'x', NULL"
		if column == "name" {
			columns = "md5, name"
			values = "$1, NULL"
		}
		cases = append(cases, struct {
			name, sql string
			args      []any
			code      string
		}{"null " + column, "INSERT INTO threats(" + columns + ") VALUES(" + values + ")", []any{strings.Repeat("a", 32)}, "23502"})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, tc.sql, tc.args...)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != tc.code {
				t.Fatalf("expected %s, got %v", tc.code, err)
			}
		})
	}
	var description, severity string
	var fileType *string
	var firstSeen *time.Time
	if err := pool.QueryRow(ctx, "INSERT INTO threats(md5,name) VALUES($1,$2) RETURNING description,severity,file_type,first_seen_at", strings.Repeat("f", 32), strings.Repeat("я", 255)).Scan(&description, &severity, &fileType, &firstSeen); err != nil {
		t.Fatal(err)
	}
	if description != "" || severity != "unknown" || fileType != nil || firstSeen != nil {
		t.Fatal("SQL defaults differ from contract")
	}
}

func TestRepositoryInfrastructureErrors(t *testing.T) {
	pool, dsn := testDatabase(t)
	repo := repository.NewThreat(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id := strings.Repeat("a", 32)
	data := domain.ThreatData{Name: "x", Severity: domain.SeverityUnknown}
	if _, err := repo.Create(ctx, id, data); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, "SELECT md5 FROM threats WHERE md5 = $1 FOR UPDATE", id); err != nil {
		t.Fatal(err)
	}
	blocked, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	_, err = repo.Update(blocked, id, data)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SQL deadline not preserved: %v", err)
	}
	canceled, cancelNow := context.WithCancel(ctx)
	cancelNow()
	if _, err := repo.Get(canceled, id); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not preserved: %v", err)
	}
	// Closing a separate pool simulates infrastructure failure without stopping a shared server.
	closed, err := postgres.NewPool(ctx, postgres.Config{DSN: dsn, MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	failed := repository.NewThreat(closed)
	for name, call := range map[string]func() (domain.Threat, error){
		"create": func() (domain.Threat, error) { return failed.Create(ctx, id, data) },
		"get":    func() (domain.Threat, error) { return failed.Get(ctx, id) },
		"update": func() (domain.Threat, error) { return failed.Update(ctx, id, data) },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := call()
			if err == nil || errors.Is(err, threat.ErrNotFound) || errors.Is(err, threat.ErrAlreadyExists) {
				t.Fatalf("wrong infrastructure error: %v", err)
			}
		})
	}
	// A CHECK failure is not an MD5 conflict.
	_, err = repo.Create(ctx, strings.Repeat("B", 32), data)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" || errors.Is(err, threat.ErrAlreadyExists) {
		t.Fatalf("constraint mapping: %v", err)
	}
}

func TestMigrationRoundTrip(t *testing.T) {
	pool, _ := testDatabase(t)
	applyMigration(t, pool, "down")
	var missing bool
	if err := pool.QueryRow(context.Background(), "SELECT to_regclass('public.threats') IS NULL").Scan(&missing); err != nil || !missing {
		t.Fatalf("down did not remove table: %v", err)
	}
	applyMigration(t, pool, "up")
	if _, err := pool.Exec(context.Background(), "INSERT INTO threats(md5,name) VALUES($1,'x')", fmt.Sprintf("%032x", 1)); err != nil {
		t.Fatal(err)
	}
}
