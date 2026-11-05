// Package domain defines threat data and validation independent of transport and storage.
package domain

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Severity is a threat's danger level.
type Severity string

// Supported severity levels; unknown means no assessment is available.
const (
	SeverityUnknown  Severity = "unknown"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ThreatData contains all replaceable fields. Nil pointers represent unknown values.
// A non-nil FirstSeenAt may contain the zero time (year 1), which is a known value.
type ThreatData struct {
	Name        string
	Description string
	Severity    Severity
	FileType    *string
	FirstSeenAt *time.Time
}

// Threat is a stored threat. Storage assigns and preserves its system timestamps.
type Threat struct {
	MD5 string
	ThreatData
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ValidationError identifies an invalid field without transport-specific status codes.
type ValidationError struct {
	Field   string
	Message string
}

// Error describes the invalid field and its constraint.
func (e *ValidationError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Message) }

var md5Pattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
var fileTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,31}$`)

// NormalizeMD5 validates an MD5 identifier and returns its lowercase representation.
// Whitespace is not removed.
func NormalizeMD5(value string) (string, error) {
	if !md5Pattern.MatchString(value) {
		return "", &ValidationError{"md5", "must contain exactly 32 hexadecimal characters"}
	}
	return strings.ToLower(value), nil
}

// Validate checks replaceable data after the service has applied defaults.
func (d ThreatData) Validate() error {
	if err := validateText("name", d.Name, 255); err != nil {
		return err
	}
	if strings.TrimSpace(d.Name) == "" {
		return &ValidationError{"name", "must not be empty or whitespace only"}
	}
	if err := validateText("description", d.Description, 4096); err != nil {
		return err
	}
	switch d.Severity {
	case SeverityUnknown, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
	default:
		return &ValidationError{"severity", "must be unknown, low, medium, high or critical"}
	}
	if d.FileType != nil && !fileTypePattern.MatchString(*d.FileType) {
		return &ValidationError{"file_type", "must be a lowercase format label of 1 to 32 ASCII characters"}
	}
	if d.FirstSeenAt != nil {
		// MarshalText checks RFC3339 representability, not whether the time is in the past.
		if _, err := d.FirstSeenAt.MarshalText(); err != nil {
			return &ValidationError{"first_seen_at", "must be representable as RFC3339"}
		}
		year := d.FirstSeenAt.UTC().Year()
		if year < 1 || year > 9999 || d.FirstSeenAt.Year() < 1 {
			return &ValidationError{"first_seen_at", "year must be between 1 and 9999, including in UTC"}
		}
	}
	return nil
}

func validateText(field, value string, maxLength int) error {
	if !utf8.ValidString(value) {
		return &ValidationError{field, "must be valid UTF-8"}
	}
	if strings.ContainsRune(value, '\x00') {
		return &ValidationError{field, "must not contain U+0000"}
	}
	if utf8.RuneCountInString(value) > maxLength {
		return &ValidationError{field, fmt.Sprintf("must contain at most %d Unicode code points", maxLength)}
	}
	return nil
}
