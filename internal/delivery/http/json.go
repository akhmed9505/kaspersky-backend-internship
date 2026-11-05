package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

const maxBodyBytes = 64 * 1024

var timestampPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

func decodeBody(w http.ResponseWriter, r *http.Request, create bool, destination any) bool {
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	media, params, err := mime.ParseMediaType(contentTypes[0])
	charset, hasCharset := params["charset"]
	if err != nil || media != "application/json" || (hasCharset && !strings.EqualFold(charset, "utf-8")) {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json with UTF-8 encoding")
		return false
	}
	body := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer body.Close()
	raw, err := io.ReadAll(body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "Request body exceeds 65536 bytes")
		} else {
			writeError(w, http.StatusBadRequest, "Cannot read request body")
		}
		return false
	}
	if !utf8.Valid(raw) || !validObject(raw, create) {
		writeError(w, http.StatusBadRequest, "Invalid JSON request")
		return false
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON field value")
		return false
	}
	return true
}

func validObject(raw []byte, create bool) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, 7)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return false
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return false
		}
		switch key {
		case "md5":
			if !create {
				return false
			}
		case "name", "description", "severity", "file_type", "first_seen_at":
		default:
			return false
		}
		seen[key] = true
		// Every input property is a string. This also rejects null, arrays and objects.
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
		var text string
		if json.Unmarshal(value, &text) != nil {
			return false
		}
		if key == "first_seen_at" && !timestampPattern.MatchString(text) {
			return false
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return false
	}
	if _, err = decoder.Token(); err != io.EOF {
		return false
	}
	return seen["name"] && (!create || seen["md5"])
}
