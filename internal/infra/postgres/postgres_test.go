package postgres_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/infra/postgres"
)

func TestInvalidConfig(t *testing.T) {
	for _, config := range []postgres.Config{
		{},
		{DSN: "postgres://user:secret@localhost/db", MaxConns: -1},
		{DSN: "postgres://user:secret@localhost/db", ConnectTimeout: -time.Second},
		{DSN: "postgres://user:secret@localhost:invalid/db"},
		{DSN: "postgres://user:secret@localhost/db?pool_min_conns=3&pool_max_conns=1"},
	} {
		pool, err := postgres.NewPool(context.Background(), config)
		if err == nil {
			pool.Close()
			t.Fatal("expected invalid configuration")
		}
		if pool != nil {
			t.Fatal("pool returned on failure")
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatal("configuration error leaked password")
		}
	}
}
