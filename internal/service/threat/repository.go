package threat

import (
	"context"
	"errors"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/domain"
)

// ErrNotFound indicates that the requested threat does not exist.
var ErrNotFound = errors.New("threat not found")

// ErrAlreadyExists indicates an MD5 uniqueness conflict during creation.
var ErrAlreadyExists = errors.New("threat already exists")

// Repository stores canonical MD5 identifiers and returns persisted timestamps.
// Get and Update return ErrNotFound for missing records. Create returns
// ErrAlreadyExists on an atomic uniqueness conflict. Implementations may wrap errors.
// Update replaces all ThreatData fields, preserves MD5 and CreatedAt, and assigns UpdatedAt.
type Repository interface {
	Create(context.Context, string, domain.ThreatData) (domain.Threat, error)
	Get(context.Context, string) (domain.Threat, error)
	Update(context.Context, string, domain.ThreatData) (domain.Threat, error)
}
