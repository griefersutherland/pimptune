package scep

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/griefersutherland/pimptune/internal/ms"
	"github.com/griefersutherland/pimptune/internal/utils"
	"github.com/smallstep/scep"
)

// handlePKIOperation processes SCEP PKI operations (CSR enrollment, etc.)
func (s *SCEPServer) handlePKIOperation(w http.ResponseWriter, r *http.Request) {
	s.log.Debug().
		Str("method", r.Method).
		Str("url", r.URL.String()).
		Str("user_agent", r.UserAgent()).
		Msg("Handling PKIOperation Request")

	// Read the request body
	r.Body = http.MaxBytesReader(w, r.Body, 5<<20) // 5 MB limit
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.log.Error().Err(err).Msg("Error reading request body")
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}

	// Parse the SCEP PKI message
	msg, err := scep.ParsePKIMessage(body)
	if err != nil {
		s.log.Error().Err(err).Msg("Error parsing PKI message")
		http.Error(w, "Failed to parse SCEP message", http.StatusBadRequest)
		return
	}

	s.log.Info().
		Str("message_type", msg.MessageType.String()).
		Str("transaction_id", string(msg.TransactionID)).
		Msg("Parsed PKI message successfully")

	// Handle different message types
	switch msg.MessageType {
	// Intune handles both new enrollments and renewals through the same PKIOperation with a CSR and fresh challenge
	case scep.RenewalReq, scep.UpdateReq, scep.PKCSReq:
		s.handleCSRRequest(w, r, msg)
	case scep.GetCRL:
		s.handleGetCRL(w, r)
	case scep.GetCert:
		// Intune does not use GetCert, it just requests a new one
		s.log.Error().Msg("GetCert not implemented")
		s.sendFailureResponse(w, msg, scep.BadRequest)
	case scep.CertPoll:
		// Intune does not use CertPoll
		s.log.Error().Msg("CertPoll not implemented")
		s.sendFailureResponse(w, msg, scep.BadRequest)
	default:
		s.log.Error().Msgf("Unknown message type: %s", msg.MessageType)
		s.sendFailureResponse(w, msg, scep.BadRequest)
	}
}

// handleCSRRequest processes a certificate signing request
func (s *SCEPServer) handleCSRRequest(w http.ResponseWriter, r *http.Request, msg *scep.PKIMessage) {
	s.log.Info().Msg("Handling CSR Request")
	if msg == nil {
		s.log.Error().Msg("Received nil PKI message")
		s.sendFailureResponse(w, msg, scep.BadRequest)
		return
	}

	// Use the RA cert/key to decrypt the PKI envelope to extract the CSR
	if err := msg.DecryptPKIEnvelope(s.raCrt, s.raKey); err != nil {
		s.log.Error().Err(err).Msg("Error decrypting PKI envelope")
		s.sendFailureResponse(w, msg, scep.BadMessageCheck)
		return
	}

	// Extract CSR and challenge password
	if msg.CSRReqMessage == nil || msg.CSRReqMessage.CSR == nil {
		s.log.Error().Msg("No CSR request message found")
		s.sendFailureResponse(w, msg, scep.BadMessageCheck)
		return
	}

	csr := msg.CSRReqMessage.CSR
	challenge := msg.CSRReqMessage.ChallengePassword

	// Validate CSR
	if failInfo, err := validateCsr(csr); err != nil {
		s.log.Error().Err(err).Msg("Invalid CSR")
		s.sendFailureResponse(w, msg, failInfo)
		return
	}

	// Log CSR details for debugging
	s.logCSRDetails(csr)

	csrBase64 := base64.StdEncoding.EncodeToString(csr.Raw)
	dbid := utils.CreateDBID(csrBase64, challenge)

	// Check if certificate already exists in store
	crt, notified, err := s.store.GetCert(r.Context(), csrBase64, challenge)
	if err != nil {
		s.log.Error().Err(err).Msg("Error checking existing certificate in store")
		s.sendFailureResponse(w, msg, scep.BadRequest)
		return
	}

	var msgCrt *scep.PKIMessage

	if crt != nil {
		// Certificate already exists
		sn := crt.SerialNumber.Text(16)

		s.log.Info().Str("serial_number", sn).Msg("Certificate already exists in store")

		// Check if the existing certificate is expired
		if time.Now().After(crt.NotAfter) {
			s.log.Warn().
				Str("serial_number", sn).
				Str("dbid", dbid).
				Msg("Existing certificate is expired, treating as a new request")
			crt = nil
			notified = false
		} else {
			// Existing valid certificate found

			if !notified {
				if err := s.verifier.NotifySuccess(r.Context(), csrBase64, challenge, crt, s.caChain[0]); err != nil {
					// Intune notification failed, log and send failure response
					s.log.Error().Err(err).
						Str("serial_number", sn).
						Str("dbid", dbid).
						Msg("Error notifying Intune of existing certificate")
					s.sendFailureResponse(w, msg, scep.BadRequest)
					return
				}

				// Mark as notified in the certificate store
				_, err := s.store.MarkIntuneNotified(r.Context(), csrBase64, challenge)
				if err != nil {
					s.log.Warn().Err(err).
						Str("serial_number", sn).
						Str("dbid", dbid).
						Msg("Error marking certificate as notified in store")
				}
			}

			// Create success response with existing certificate
			msgCrt, err = msg.Success(s.raCrt, s.raKey, crt)
			if err != nil {
				s.log.Error().Err(err).
					Str("serial_number", sn).
					Str("dbid", dbid).
					Msg("Error creating success response from existing cert")
				s.sendFailureResponse(w, msg, scep.BadRequest)
				return
			}
		}
	}
	if crt == nil {
		// New CSR, proceed with verification

		// Verify CSR and challenge (with Intune API)
		valid, err := s.verifier.VerifyCSR(r.Context(), csrBase64, challenge)
		if err != nil {
			s.log.Error().Err(err).Msg("Error verifying CSR with Intune")
			s.sendFailureResponse(w, msg, scep.BadRequest)
			return
		}

		// Invalid CSR/Challenge combination
		if !valid {
			s.log.Warn().Msg("CSR verification failed for Transaction ID.")
			s.sendFailureResponse(w, msg, scep.BadRequest)
			return
		}

		// From this point on, all failues must be reported back to Intune
		s.log.Info().Msg("CSR/Challenge verified successfully.")

		// Sign the CSR
		signedCrt, err := s.signer.SignCSR(r.Context(), csr)
		if err != nil {
			s.log.Error().Err(err).Msg("Error signing CSR")
			s.verifier.NotifyFailure(r.Context(), csrBase64, challenge, ms.HResultCAUnavailable, "Certificate Authority Unavailable")
			s.sendFailureResponse(w, msg, scep.BadRequest)
			return
		}
		sn := signedCrt.SerialNumber.Text(16)

		// Store the signed certificate
		if err := s.store.StoreCert(r.Context(), csrBase64, challenge, signedCrt); err != nil {
			s.log.Warn().Err(err).
				Str("serial_number", sn).
				Str("dbid", dbid).
				Msg("Error storing signed certificate")
		}

		// Notify Intune of success, if notification fails, do not send cert to client
		err = s.verifier.NotifySuccess(r.Context(), csrBase64, challenge, signedCrt, s.caChain[0])
		if err != nil {
			s.log.Error().Err(err).
				Str("serial_number", sn).
				Str("dbid", dbid).
				Msg("Error notifying Intune of successful CSR signing, not sending response to client")
			s.sendFailureResponse(w, msg, scep.BadRequest)
			return
		}

		// Mark as notified in the certificate store
		_, err = s.store.MarkIntuneNotified(r.Context(), csrBase64, challenge)
		if err != nil {
			s.log.Warn().Err(err).
				Str("serial_number", sn).
				Str("dbid", dbid).
				Msg("Error marking certificate as notified in store")
		}

		// Create success response
		msgCrt, err = msg.Success(s.raCrt, s.raKey, signedCrt)
		if err != nil {
			s.log.Error().Err(err).Msg("Error creating a success response from new cert")
			s.verifier.NotifyFailure(r.Context(), csrBase64, challenge, ms.HResultFail, "Certificate Processing Error")
			s.sendFailureResponse(w, msg, scep.BadRequest)
			return
		}
	}

	w.Header().Set("Content-Type", "application/x-pki-message")
	w.WriteHeader(http.StatusOK)
	w.Write(msgCrt.Raw)
	s.log.Info().Msgf("Returned signed certificate for DBID %s", dbid)
}

func validateCsr(csr *x509.CertificateRequest) (scep.FailInfo, error) {
	if csr == nil {
		return scep.BadRequest, fmt.Errorf("CSR is nil")
	}

	// Check CSR signature validity
	if err := csr.CheckSignature(); err != nil {
		return scep.BadMessageCheck, fmt.Errorf("invalid CSR signature: %w", err)
	}

	// Check CSR signature algorithm
	switch csr.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		// Supported algorithms
	default:
		return scep.BadAlg, fmt.Errorf("unsupported CSR signature algorithm: %s", csr.SignatureAlgorithm)
	}

	// Check key size for RSA
	if csr.PublicKeyAlgorithm == x509.RSA {
		if rsaPubKey, ok := csr.PublicKey.(*rsa.PublicKey); ok {
			if rsaPubKey.N.BitLen() < 2048 {
				return scep.BadRequest, fmt.Errorf("RSA key size is too small: %d bits", rsaPubKey.N.BitLen())
			}
		}
	}

	// Check CSR subject
	if csr.Subject.CommonName == "" {
		return scep.BadRequest, fmt.Errorf("CSR subject common name is empty")
	}

	return scep.FailInfo(""), nil
}

func (s *SCEPServer) handleGetCRL(w http.ResponseWriter, r *http.Request) {
	s.log.Info().Msg("Handling GetCRL Request")

	// Get the CRL from the Step client
	crl, err := s.signer.GetCRL(r.Context())
	if err != nil {
		s.log.Error().Err(err).Msg("Error getting CRL from Step client")
		http.Error(w, "Failed to get CRL", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.WriteHeader(http.StatusOK)
	w.Write(crl.Raw)
}
