package mock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	horizonclient "github.com/evertrust/horizon-go/v2"
)

const (
	// ValidAPIID is the expected value for the X-API-ID header.
	ValidAPIID = "api-id"
	// ValidAPIKey is the expected value for the X-API-KEY header.
	ValidAPIKey = "api-key"
)

// NewHorizonMockServer creates a lightweight Horizon mock that serves useful endpoints
// over HTTPS (matching the real Horizon API scheme).
func NewHorizonMockServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/security/principals/self", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if r.Header.Get("X-API-ID") != ValidAPIID || r.Header.Get("X-API-KEY") != ValidAPIKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			response := horizonclient.NewSecAuth002("SEC-AUTH-002", "Invalid credentials or principal does not exist", "Invalid credentials or principal does not exist", 401)
			_ = json.NewEncoder(w).Encode(response)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		identity := horizonclient.NewIdentity("unit-test-principal")

		response := horizonclient.PrincipalResponse{
			Identity: *identity,
		}

		_ = json.NewEncoder(w).Encode(response)
	})

	return httptest.NewTLSServer(mux)
}
