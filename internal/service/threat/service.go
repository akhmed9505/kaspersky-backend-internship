// Package threat implements threat use cases independently of HTTP and PostgreSQL.
package threat

import (
	"context"
	"fmt"
	"time"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/domain"
)

// Input contains replaceable client data. Nil means omitted, never explicit JSON null.
// Delivery must reject null and check required field presence before constructing Input.
type Input struct {
	Name        string
	Description *string
	Severity    *domain.Severity
	FileType    *string
	FirstSeenAt *time.Time
}

// Service validates threats and delegates atomic persistence to a Repository.
type Service struct{ repository Repository }

// New constructs a service with a required, non-nil repository.
func New(repository Repository) *Service { return &Service{repository: repository} }

// Create creates a threat with defaults and a normalized MD5.
func (s *Service) Create(ctx context.Context, md5 string, input Input) (domain.Threat, error) {
	id, err := domain.NormalizeMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}
	data, err := prepare(input)
	if err != nil {
		return domain.Threat{}, err
	}
	if err := ctx.Err(); err != nil {
		return domain.Threat{}, err
	}
	result, err := s.repository.Create(ctx, id, data)
	if err != nil {
		return domain.Threat{}, fmt.Errorf("create threat: %w", err)
	}
	return result, nil
}

// Get retrieves a threat using a validated, normalized MD5.
func (s *Service) Get(ctx context.Context, md5 string) (domain.Threat, error) {
	id, err := domain.NormalizeMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}
	if err := ctx.Err(); err != nil {
		return domain.Threat{}, err
	}
	result, err := s.repository.Get(ctx, id)
	if err != nil {
		return domain.Threat{}, fmt.Errorf("get threat: %w", err)
	}
	return result, nil
}

// Update replaces all mutable fields; omissions reset values rather than preserve them.
// System timestamps and the immutable MD5 cannot be supplied through Input.
func (s *Service) Update(ctx context.Context, md5 string, input Input) (domain.Threat, error) {
	id, err := domain.NormalizeMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}
	data, err := prepare(input)
	if err != nil {
		return domain.Threat{}, err
	}
	if err := ctx.Err(); err != nil {
		return domain.Threat{}, err
	}
	result, err := s.repository.Update(ctx, id, data)
	if err != nil {
		return domain.Threat{}, fmt.Errorf("update threat: %w", err)
	}
	return result, nil
}

func prepare(input Input) (domain.ThreatData, error) {
	data := domain.ThreatData{Name: input.Name, Severity: domain.SeverityUnknown}
	if input.Description != nil {
		data.Description = *input.Description
	}
	if input.Severity != nil {
		data.Severity = *input.Severity
	}
	// Copy pointer values so normalization and persistence cannot mutate the caller's input.
	if input.FileType != nil {
		value := *input.FileType
		data.FileType = &value
	}
	if input.FirstSeenAt != nil {
		value := *input.FirstSeenAt
		data.FirstSeenAt = &value
	}
	if err := data.Validate(); err != nil {
		return domain.ThreatData{}, err
	}
	if data.FirstSeenAt != nil {
		value := data.FirstSeenAt.UTC().Truncate(time.Microsecond)
		data.FirstSeenAt = &value
	}
	return data, nil
}
