// Package repository implements service persistence using PostgreSQL.
package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/domain"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/service/threat"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ThreatRepository persists validated data with canonical lowercase MD5 identifiers.
// Validation and defaults belong to the service; the database enforces structural constraints.
type ThreatRepository struct{ pool *pgxpool.Pool }

var _ threat.Repository = (*ThreatRepository)(nil)

// NewThreat creates a repository with a required, non-nil pool owned by the caller.
func NewThreat(pool *pgxpool.Pool) *ThreatRepository { return &ThreatRepository{pool: pool} }

const columns = `md5, name, description, severity, file_type, first_seen_at, created_at, updated_at`

// The parent request may impose an earlier deadline.
const queryTimeout = 2 * time.Second

// Create inserts atomically; the primary key resolves concurrent MD5 conflicts.
func (r *ThreatRepository) Create(ctx context.Context, md5 string, data domain.ThreatData) (domain.Threat, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	row := r.pool.QueryRow(ctx, `INSERT INTO threats (md5, name, description, severity, file_type, first_seen_at)
 VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+columns,
		md5, data.Name, data.Description, string(data.Severity), data.FileType, data.FirstSeenAt)
	result, err := scanThreat(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "threats_pkey" {
			return domain.Threat{}, fmt.Errorf("insert threat: %w", threat.ErrAlreadyExists)
		}
		return domain.Threat{}, fmt.Errorf("insert threat: %w", err)
	}
	return result, nil
}

// Get retrieves an existing threat, returning ErrNotFound if no row exists.
func (r *ThreatRepository) Get(ctx context.Context, md5 string) (domain.Threat, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	result, err := scanThreat(r.pool.QueryRow(ctx, `SELECT `+columns+` FROM threats WHERE md5 = $1`, md5))
	if err != nil {
		return domain.Threat{}, readError("select threat", err)
	}
	return result, nil
}

// Update replaces every mutable field without upsert and preserves CreatedAt and MD5.
func (r *ThreatRepository) Update(ctx context.Context, md5 string, data domain.ThreatData) (domain.Threat, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	row := r.pool.QueryRow(ctx, `UPDATE threats SET name = $2, description = $3, severity = $4,
 file_type = $5, first_seen_at = $6, updated_at = statement_timestamp()
 WHERE md5 = $1 RETURNING `+columns,
		md5, data.Name, data.Description, string(data.Severity), data.FileType, data.FirstSeenAt)
	result, err := scanThreat(row)
	if err != nil {
		return domain.Threat{}, readError("update threat", err)
	}
	return result, nil
}

func scanThreat(row pgx.Row) (domain.Threat, error) {
	var result domain.Threat
	var fileType pgtype.Text
	var firstSeen pgtype.Timestamptz
	err := row.Scan(&result.MD5, &result.Name, &result.Description, &result.Severity, &fileType, &firstSeen, &result.CreatedAt, &result.UpdatedAt)
	if err != nil {
		return domain.Threat{}, err
	}
	if fileType.Valid {
		result.FileType = &fileType.String
	}
	if firstSeen.Valid {
		value := firstSeen.Time.UTC()
		result.FirstSeenAt = &value
	}
	result.CreatedAt = result.CreatedAt.UTC()
	result.UpdatedAt = result.UpdatedAt.UTC()
	return result, nil
}

func readError(operation string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%s: %w", operation, threat.ErrNotFound)
	}
	return fmt.Errorf("%s: %w", operation, err)
}
