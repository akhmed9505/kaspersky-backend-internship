package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/domain"
)

func TestNormalizeMD5(t *testing.T) {
	for _, in := range []string{strings.Repeat("a", 32), strings.Repeat("A", 32), strings.Repeat("aB", 16)} {
		got, err := domain.NormalizeMD5(in)
		if err != nil || got != strings.ToLower(in) {
			t.Fatalf("NormalizeMD5(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("g", 32), " " + strings.Repeat("a", 32), strings.Repeat("a", 32) + "\n"} {
		_, err := domain.NormalizeMD5(in)
		assertField(t, err, "md5")
	}
}

func TestThreatDataValidation(t *testing.T) {
	cases := []struct {
		name, field string
		change      func(*domain.ThreatData)
	}{
		{"empty name", "name", func(d *domain.ThreatData) { d.Name = "" }},
		{"whitespace name", "name", func(d *domain.ThreatData) { d.Name = " \t\n\u2003" }},
		{"long unicode name", "name", func(d *domain.ThreatData) { d.Name = strings.Repeat("я", 256) }},
		{"invalid name UTF8", "name", func(d *domain.ThreatData) { d.Name = string([]byte{0xff}) }},
		{"NUL name", "name", func(d *domain.ThreatData) { d.Name = "a\x00" }},
		{"long description", "description", func(d *domain.ThreatData) { d.Description = strings.Repeat("я", 4097) }},
		{"invalid description UTF8", "description", func(d *domain.ThreatData) { d.Description = string([]byte{0xff}) }},
		{"NUL description", "description", func(d *domain.ThreatData) { d.Description = "\x00" }},
		{"empty severity", "severity", func(d *domain.ThreatData) { d.Severity = "" }},
		{"uppercase severity", "severity", func(d *domain.ThreatData) { d.Severity = "HIGH" }},
		{"unknown enum", "severity", func(d *domain.ThreatData) { d.Severity = "urgent" }},
	}
	for _, v := range []string{"", "PE", " pe", ".pe", "pdf/zip", strings.Repeat("a", 33), "файл", "pe\n", string([]byte{0xff})} {
		cases = append(cases, struct {
			name, field string
			change      func(*domain.ThreatData)
		}{"file " + v, "file_type", func(d *domain.ThreatData) { d.FileType = &v }})
	}
	for _, v := range []time.Time{time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 1, 0, 0, 0, 0, time.FixedZone("invalid", 24*3600)), time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("offset", 3600))} {
		cases = append(cases, struct {
			name, field string
			change      func(*domain.ThreatData)
		}{"time " + v.String(), "first_seen_at", func(d *domain.ThreatData) { d.FirstSeenAt = &v }})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := domain.ThreatData{Name: "Threat", Severity: domain.SeverityUnknown}
			tc.change(&d)
			assertField(t, d.Validate(), tc.field)
		})
	}
}

func TestThreatDataValidBoundaries(t *testing.T) {
	for _, severity := range []domain.Severity{domain.SeverityUnknown, domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical} {
		file := strings.Repeat("a", 32)
		future := time.Date(9999, 1, 1, 12, 0, 0, 123456789, time.FixedZone("offset", 3*3600))
		d := domain.ThreatData{Name: strings.Repeat("я", 255), Description: strings.Repeat("я", 4096), Severity: severity, FileType: &file, FirstSeenAt: &future}
		if err := d.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"a", "pe", "elf", "a._+-9"} {
		d := domain.ThreatData{Name: " x ", Severity: domain.SeverityUnknown, FileType: &file}
		if err := d.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	zero := time.Time{}
	d := domain.ThreatData{Name: "x", Severity: domain.SeverityUnknown, FirstSeenAt: &zero}
	if err := d.Validate(); err != nil {
		t.Fatalf("known year 1 rejected: %v", err)
	}
	d.FirstSeenAt = nil
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
}

func assertField(t *testing.T, err error, field string) {
	t.Helper()
	var validation *domain.ValidationError
	if !errors.As(err, &validation) || validation.Field != field {
		t.Fatalf("expected validation error for %s, got %v", field, err)
	}
	if validation.Error() == "" {
		t.Fatal("empty error message")
	}
}
