// Package postgres configures PostgreSQL connection pools without application wiring.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config contains connection settings. DSN may contain secrets and must not be logged.
// Zero MaxConns preserves pgxpool's configured limit; zero ConnectTimeout uses five seconds.
type Config struct {
	DSN            string
	MaxConns       int32
	ConnectTimeout time.Duration
}

// NewPool parses configuration and checks connectivity before returning a pool.
// The owner must call Close after in-flight operations have completed. Closing
// waits for acquired connections to return. Failed initialization closes the pool.
func NewPool(ctx context.Context, config Config) (*pgxpool.Pool, error) {
	if config.DSN == "" {
		return nil, errors.New("PostgreSQL DSN is required")
	}
	if config.MaxConns < 0 || config.ConnectTimeout < 0 {
		return nil, errors.New("PostgreSQL pool limits and timeout must not be negative")
	}
	parsed, err := pgxpool.ParseConfig(config.DSN)
	if err != nil {
		// pgx parse errors can contain the complete DSN, including its password.
		return nil, errors.New("invalid PostgreSQL connection configuration")
	}
	if config.MaxConns > 0 {
		parsed.MaxConns = config.MaxConns
	}
	if parsed.MinConns > parsed.MaxConns || parsed.MinIdleConns > parsed.MaxConns {
		return nil, errors.New("PostgreSQL minimum connections exceed maximum")
	}
	timeout := config.ConnectTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	parsed.ConnConfig.ConnectTimeout = timeout
	pool, err := pgxpool.NewWithConfig(ctx, parsed)
	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	return pool, nil
}
