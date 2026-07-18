package scep

import (
	"net/http"

	"github.com/griefersutherland/pimptune/internal/utils"
)

// handleGetCACert handles the SCEP GetCACert operation and returns the CA certificate bundle
func (s *SCEPServer) handleGetCACert(w http.ResponseWriter, r *http.Request) {
	s.log.Debug().
		Str("method", r.Method).
		Str("url", r.URL.String()).
		Str("user_agent", r.UserAgent()).
		Msg("Handling GetCACert Request")

	bundle, err := utils.BuildBundle(s.raCrt, s.caChain)
	if err != nil {
		s.log.Error().Err(err).Msg("Error building CA bundle")
		http.Error(w, "Failed to create CA cert response", http.StatusInternalServerError)
		return
	}

	// Return CA bundle
	w.Header().Set("Content-Type", "application/x-x509-ca-ra-cert")
	w.WriteHeader(http.StatusOK)
	w.Write(bundle)
}
