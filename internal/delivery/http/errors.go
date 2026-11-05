package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/delivery/http/generated"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/domain"
	"github.com/akhmed9505/kaspersky-backend-internship/internal/service/threat"
)

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, generated.ErrorResponse{Message: message})
}

func writeServiceError(w http.ResponseWriter, err error, create bool) {
	var invalid *domain.ValidationError
	switch {
	case errors.As(err, &invalid):
		details := invalid.Error()
		writeJSON(w, http.StatusBadRequest, generated.ErrorResponse{Message: "Invalid request", Details: &details})
	case !create && errors.Is(err, threat.ErrNotFound):
		writeError(w, http.StatusNotFound, "Threat not found")
	case create && errors.Is(err, threat.ErrAlreadyExists):
		writeError(w, http.StatusConflict, "Threat already exists")
	default:
		writeError(w, http.StatusInternalServerError, "Internal server error")
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	// Encode before committing headers; an encoding error must not produce a partial success.
	data, err := json.Marshal(value)
	if err != nil {
		status = http.StatusInternalServerError
		data = []byte(`{"message":"Internal server error"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}
