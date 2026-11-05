package httpapi

import (
	"net/http"
	"path"

	"github.com/akhmed9505/kaspersky-backend-internship/internal/delivery/http/generated"
)

// NewRouter registers generated routes with JSON fallbacks for unknown paths and
// unsupported methods, including HEAD. App wraps this router with security middleware.
func NewRouter(handler *Handler) http.Handler {
	mux := http.NewServeMux()
	generated.HandlerWithOptions(handler, generated.StdHTTPServerOptions{
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			writeError(w, http.StatusBadRequest, "Invalid path parameter")
		},
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) { methodNotAllowed(w, "POST") })
	mux.HandleFunc("/info/{md5}", func(w http.ResponseWriter, r *http.Request) { methodNotAllowed(w, "GET, PUT") })
	// A GET registration implicitly accepts HEAD in ServeMux; override it explicitly.
	mux.HandleFunc("HEAD /info/{md5}", func(w http.ResponseWriter, r *http.Request) { methodNotAllowed(w, "GET, PUT") })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { writeError(w, http.StatusNotFound, "Route not found") })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Keep noncanonical paths as JSON 404s rather than ServeMux redirects.
		// EscapedPath preserves encoded slashes inside an MD5 path parameter.
		if path.Clean(r.URL.EscapedPath()) != r.URL.EscapedPath() {
			writeError(w, http.StatusNotFound, "Route not found")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
}
