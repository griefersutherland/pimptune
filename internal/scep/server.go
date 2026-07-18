package scep

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/griefersutherland/pimptune/internal/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/smallstep/scep"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

type SCEPServer struct {
	raCrt     *x509.Certificate
	raKey     crypto.PrivateKey
	caChain   []*x509.Certificate
	log       zerolog.Logger
	signer    utils.Signer
	verifier  utils.Verifier
	store     utils.Store
	muPurge   sync.Mutex
	isPurging bool
}

type SCEPServerParams struct {
	RACert   *x509.Certificate
	RAKey    crypto.PrivateKey
	CAChain  []*x509.Certificate
	Verifier utils.Verifier
	Signer   utils.Signer
	Store    utils.Store
}

// NewSCEPServerWindows creates a new SCEP server instance
func NewSCEPServer(params *SCEPServerParams) *SCEPServer {
	return &SCEPServer{
		raCrt:    params.RACert,
		raKey:    params.RAKey,
		caChain:  params.CAChain,
		verifier: params.Verifier,
		signer:   params.Signer,
		store:    params.Store,
		log:      log.Logger.With().Str("component", "scep_server").Logger(),
	}
}

func isErrorBusy(err error) bool {
	if err == nil {
		return false
	}

	var liteErr *sqlite.Error
	if errors.As(err, &liteErr) {
		// Check if the error code is SQLITE_BUSY (which has a value of 5)
		if liteErr.Code() == sqlite3.SQLITE_BUSY {
			return true
		}
	}
	return false
}

func (s *SCEPServer) StartPurging(ctx context.Context) {
	const retries = 3
	const backoffDefault = time.Millisecond * 100

	s.muPurge.Lock()
	if s.isPurging {
		s.muPurge.Unlock()
		return
	}
	s.isPurging = true
	s.muPurge.Unlock()

	go func() {
		// Purge expired certificates every hour
		timer := time.NewTicker(time.Hour)
		defer func() {
			timer.Stop()
			s.muPurge.Lock()
			s.isPurging = false
			s.muPurge.Unlock()
		}()

		for {
			select {
			case <-timer.C:
				var backoff = backoffDefault
				for range retries {
					_, err := s.store.PurgeExpired(ctx)
					if err == nil {
						break
					}
					if isErrorBusy(err) {
						time.Sleep(backoff)
						backoff *= 2
						continue
					}
					s.log.Error().Err(err).Msg("Error purging expired certificates")
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// ServeHTTP implements the http.Handler interface
func (s *SCEPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Parse operation from query parameters
	operation := r.URL.Query().Get("operation")
	s.log.Debug().Str("operation", operation).Str("remote_addr", r.RemoteAddr).Msgf("Received %s request", r.Method)

	switch operation {
	case "GetCACaps":
		s.handleGetCACaps(w, r)
	case "GetCACert":
		s.handleGetCACert(w, r)
	case "PKIOperation":
		s.handlePKIOperation(w, r)
	default:
		s.log.Warn().Str("operation", operation).Msg("Unknown operation")
		http.Error(w, "Unknown operation", http.StatusBadRequest)
	}
}

// logCSRDetails logs detailed information about the CSR
func (s *SCEPServer) logCSRDetails(csr *x509.CertificateRequest) {
	s.log.Trace().
		Str("subject_common_name", csr.Subject.CommonName).
		Strs("subject_organization", csr.Subject.Organization).
		Strs("subject_organizational_unit", csr.Subject.OrganizationalUnit).
		Strs("subject_country", csr.Subject.Country).
		Strs("subject_locality", csr.Subject.Locality).
		Strs("subject_province", csr.Subject.Province).
		Str("public_key_algorithm", csr.PublicKeyAlgorithm.String()).
		Str("signature_algorithm", csr.SignatureAlgorithm.String()).
		Strs("dns_names", csr.DNSNames).
		Strs("email_addresses", csr.EmailAddresses).
		Msg("Logging CSR details")
}

// sendFailureResponse sends a SCEP failure response
func (s *SCEPServer) sendFailureResponse(w http.ResponseWriter, msg *scep.PKIMessage, failInfo scep.FailInfo) {
	s.log.Warn().Str("fail_info", failInfo.String()).Msg("Sending failure response")

	if msg == nil {
		log.Error().Msg("Original message is nil")
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Create failure response
	certRep, err := msg.Fail(s.raCrt, s.raKey, failInfo)
	if err != nil {
		s.log.Error().Err(err).Msg("Error creating failure response")
		http.Error(w, "Failed to create response", http.StatusInternalServerError)
		return
	}

	// Send the response
	w.Header().Set("Content-Type", "application/x-pki-message")
	w.WriteHeader(http.StatusOK)
	w.Write(certRep.Raw)
	s.log.Debug().Msg("Sent failure response")
}
