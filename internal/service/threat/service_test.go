package threat_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/domain"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/service/threat"
)

const md5 = "abcdef0123456789abcdef0123456789"

type fakeRepository struct {
	records map[string]domain.Threat
	calls   int
	ctx     context.Context
	err     error
}

func (r *fakeRepository) Create(ctx context.Context, id string, data domain.ThreatData) (domain.Threat, error) {
	r.calls++
	r.ctx = ctx
	if r.err != nil {
		return domain.Threat{}, r.err
	}
	if _, ok := r.records[id]; ok {
		return domain.Threat{}, fmt.Errorf("unique MD5: %w", threat.ErrAlreadyExists)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	result := domain.Threat{MD5: id, ThreatData: data, CreatedAt: now, UpdatedAt: now}
	r.records[id] = result
	return result, nil
}
func (r *fakeRepository) Get(ctx context.Context, id string) (domain.Threat, error) {
	r.calls++
	r.ctx = ctx
	if r.err != nil {
		return domain.Threat{}, r.err
	}
	result, ok := r.records[id]
	if !ok {
		return domain.Threat{}, fmt.Errorf("lookup: %w", threat.ErrNotFound)
	}
	return result, nil
}
func (r *fakeRepository) Update(ctx context.Context, id string, data domain.ThreatData) (domain.Threat, error) {
	r.calls++
	r.ctx = ctx
	if r.err != nil {
		return domain.Threat{}, r.err
	}
	result, ok := r.records[id]
	if !ok {
		return domain.Threat{}, threat.ErrNotFound
	}
	result.ThreatData = data
	result.UpdatedAt = result.UpdatedAt.Add(time.Second)
	r.records[id] = result
	return result, nil
}
func setup() (*threat.Service, *fakeRepository) {
	r := &fakeRepository{records: make(map[string]domain.Threat)}
	return threat.New(r), r
}
func ptr[T any](v T) *T { return &v }

func TestCreateGetUpdate(t *testing.T) {
	s, r := setup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seen := time.Date(2099, 2, 3, 4, 5, 6, 123456789, time.FixedZone("MSK", 10800))
	input := threat.Input{Name: " Original ", Description: ptr("details"), Severity: ptr(domain.SeverityHigh), FileType: ptr("pe"), FirstSeenAt: &seen}
	created, err := s.Create(ctx, strings.ToUpper(md5), input)
	if err != nil {
		t.Fatal(err)
	}
	if created.MD5 != md5 || created.Name != input.Name || created.Description != "details" || created.Severity != domain.SeverityHigh || *created.FileType != "pe" {
		t.Fatalf("unexpected created: %+v", created)
	}
	want := seen.UTC().Truncate(time.Microsecond)
	if !created.FirstSeenAt.Equal(want) || created.FirstSeenAt.Location() != time.UTC {
		t.Fatal("time not normalized")
	}
	if seen.Location() == time.UTC || seen.Nanosecond() != 123456789 {
		t.Fatal("caller time mutated")
	}
	if created.FileType == input.FileType || created.FirstSeenAt == input.FirstSeenAt {
		t.Fatal("caller pointers retained")
	}
	if r.ctx != ctx {
		t.Fatal("context not propagated")
	}
	got, err := s.Get(ctx, strings.ToUpper(md5))
	if err != nil || !reflect.DeepEqual(got, created) {
		t.Fatalf("get: %+v %v", got, err)
	}
	updated, err := s.Update(ctx, strings.ToUpper(md5), threat.Input{Name: "Replacement"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Replacement" || updated.Description != "" || updated.Severity != domain.SeverityUnknown || updated.FileType != nil || updated.FirstSeenAt != nil {
		t.Fatalf("PUT did not reset: %+v", updated)
	}
	if updated.MD5 != md5 || updated.CreatedAt != created.CreatedAt || !updated.UpdatedAt.After(created.UpdatedAt) {
		t.Fatal("storage timestamps not preserved")
	}
	if r.ctx != ctx {
		t.Fatal("context not propagated")
	}
}

func TestDefaultsAndKnownZeroTime(t *testing.T) {
	s, _ := setup()
	got, err := s.Create(context.Background(), md5, threat.Input{Name: "x"})
	if err != nil || got.Description != "" || got.Severity != domain.SeverityUnknown || got.FileType != nil || got.FirstSeenAt != nil {
		t.Fatalf("defaults: %+v %v", got, err)
	}
	updated, err := s.Update(context.Background(), md5, threat.Input{Name: "x", Description: ptr(""), Severity: ptr(domain.SeverityUnknown), FirstSeenAt: ptr(time.Time{})})
	if err != nil || updated.FirstSeenAt == nil || !updated.FirstSeenAt.IsZero() {
		t.Fatalf("known zero time lost: %+v %v", updated, err)
	}
}

func TestRepositoryErrors(t *testing.T) {
	s, r := setup()
	ctx := context.Background()
	if _, err := s.Create(ctx, md5, threat.Input{Name: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, strings.ToUpper(md5), threat.Input{Name: "x"}); !errors.Is(err, threat.ErrAlreadyExists) {
		t.Fatalf("duplicate: %v", err)
	}
	missing := strings.Repeat("0", 32)
	if _, err := s.Get(ctx, missing); !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	if _, err := s.Update(ctx, missing, threat.Input{Name: "x"}); !errors.Is(err, threat.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	failure := errors.New("storage unavailable")
	r.err = failure
	for name, call := range map[string]func() (domain.Threat, error){"create": func() (domain.Threat, error) { return s.Create(ctx, md5, threat.Input{Name: "x"}) }, "get": func() (domain.Threat, error) { return s.Get(ctx, md5) }, "update": func() (domain.Threat, error) { return s.Update(ctx, md5, threat.Input{Name: "x"}) }} {
		t.Run(name, func(t *testing.T) {
			got, err := call()
			if !errors.Is(err, failure) || !reflect.DeepEqual(got, domain.Threat{}) {
				t.Fatalf("error not preserved: %+v %v", got, err)
			}
		})
	}
}

func TestInvalidInputDoesNotReachRepository(t *testing.T) {
	cases := []struct {
		field string
		input threat.Input
	}{
		{"name", threat.Input{}},
		{"description", threat.Input{Name: "x", Description: ptr(strings.Repeat("a", 4097))}},
		{"severity", threat.Input{Name: "x", Severity: ptr(domain.Severity(""))}},
		{"file_type", threat.Input{Name: "x", FileType: ptr("")}},
		{"first_seen_at", threat.Input{Name: "x", FirstSeenAt: ptr(time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC))}},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			s, r := setup()
			for _, call := range []func() (domain.Threat, error){func() (domain.Threat, error) { return s.Create(context.Background(), md5, tc.input) }, func() (domain.Threat, error) { return s.Update(context.Background(), md5, tc.input) }} {
				_, err := call()
				var invalid *domain.ValidationError
				if !errors.As(err, &invalid) || invalid.Field != tc.field {
					t.Fatalf("validation: %v", err)
				}
			}
			if r.calls != 0 {
				t.Fatal("invalid input reached repository")
			}
		})
	}
	s, r := setup()
	for _, call := range []func() (domain.Threat, error){func() (domain.Threat, error) { return s.Create(context.Background(), "bad", threat.Input{Name: "x"}) }, func() (domain.Threat, error) { return s.Get(context.Background(), "bad") }, func() (domain.Threat, error) { return s.Update(context.Background(), "bad", threat.Input{Name: "x"}) }} {
		_, err := call()
		var invalid *domain.ValidationError
		if !errors.As(err, &invalid) || invalid.Field != "md5" {
			t.Fatalf("MD5 validation: %v", err)
		}
	}
	if r.calls != 0 {
		t.Fatal("invalid MD5 reached repository")
	}
}

func TestCanceledContext(t *testing.T) {
	s, r := setup()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, call := range []func() (domain.Threat, error){func() (domain.Threat, error) { return s.Create(ctx, md5, threat.Input{Name: "x"}) }, func() (domain.Threat, error) { return s.Get(ctx, md5) }, func() (domain.Threat, error) { return s.Update(ctx, md5, threat.Input{Name: "x"}) }} {
		if _, err := call(); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation: %v", err)
		}
	}
	if r.calls != 0 {
		t.Fatal("canceled operation reached repository")
	}
}
