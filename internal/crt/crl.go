package crt

import (
	"fmt"
	"net/http"

	"github.com/griefersutherland/pimptune/internal/utils"
)

// CrlServer is an HTTP server that serves the Certificate Revocation List (CRL).
type CrlServer struct {
	signer utils.Signer
}

func NewCrlServer(signer utils.Signer) *CrlServer {
	return &CrlServer{
		signer: signer,
	}
}

// Implement http.Handler
func (s *CrlServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	crl, err := s.signer.GetCRL(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get CRL: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.WriteHeader(http.StatusOK)
	w.Write(crl.Raw)
}
