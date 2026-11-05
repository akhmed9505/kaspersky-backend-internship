// Package httpapi adapts the generated OpenAPI contract to threat service operations.
package httpapi

import (
	"net/http"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/delivery/http/generated"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/domain"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/service/threat"
)

// Handler implements the generated server interface using the concrete threat service.
type Handler struct{ service *threat.Service }

var _ generated.ServerInterface = (*Handler)(nil)

// NewHandler creates HTTP adapters; service must be non-nil.
func NewHandler(service *threat.Service) *Handler { return &Handler{service: service} }

// CreateThreat handles POST /info after strict request decoding.
func (h *Handler) CreateThreat(w http.ResponseWriter, r *http.Request) {
	var dto generated.ThreatCreateRequest
	if !decodeBody(w, r, true, &dto) {
		return
	}
	input := threat.Input{Name: dto.Name, Description: dto.Description, FileType: dto.FileType, FirstSeenAt: dto.FirstSeenAt}
	if dto.Severity != nil {
		value := domain.Severity(*dto.Severity)
		input.Severity = &value
	}
	result, err := h.service.Create(r.Context(), dto.Md5, input)
	if err != nil {
		writeServiceError(w, err, true)
		return
	}
	writeJSON(w, http.StatusCreated, response(result))
}

// GetInfoByMd5 handles GET /info/{md5}; no Content-Type is required.
func (h *Handler) GetInfoByMd5(w http.ResponseWriter, r *http.Request, md5 string) {
	result, err := h.service.Get(r.Context(), md5)
	if err != nil {
		writeServiceError(w, err, false)
		return
	}
	writeJSON(w, http.StatusOK, response(result))
}

// UpdateThreat replaces all mutable data of an existing threat.
func (h *Handler) UpdateThreat(w http.ResponseWriter, r *http.Request, md5 string) {
	// Path errors precede Content-Type and body errors, independently of service validation.
	if _, err := domain.NormalizeMD5(md5); err != nil {
		writeServiceError(w, err, false)
		return
	}
	var dto generated.ThreatUpdateRequest
	if !decodeBody(w, r, false, &dto) {
		return
	}
	input := threat.Input{Name: dto.Name, Description: dto.Description, FileType: dto.FileType, FirstSeenAt: dto.FirstSeenAt}
	if dto.Severity != nil {
		value := domain.Severity(*dto.Severity)
		input.Severity = &value
	}
	result, err := h.service.Update(r.Context(), md5, input)
	if err != nil {
		writeServiceError(w, err, false)
		return
	}
	writeJSON(w, http.StatusOK, response(result))
}

func response(value domain.Threat) generated.ThreatResponse {
	created, updated := value.CreatedAt.UTC(), value.UpdatedAt.UTC()
	return generated.ThreatResponse{Md5: value.MD5, Name: value.Name, Description: value.Description, Severity: generated.ThreatResponseSeverity(value.Severity), FileType: value.FileType, FirstSeenAt: value.FirstSeenAt, CreatedAt: &created, UpdatedAt: &updated}
}
