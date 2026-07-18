package step

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/griefersutherland/pimptune/internal/utils"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
)

type StepClient struct {
	apiUrl          string
	provisionerName string
	caFingerprint   string
	jwk             jose.SigningKey
	client          *ca.Client
	kid             string
	httpClient      *http.Client
}

func NewStepClient(apiUrl, provisionerName, caFingerprint string, chain []*x509.Certificate, jwk *jose.JSONWebKey) (*StepClient, error) {
	// Validate Step CA API URL
	url, err := url.Parse(apiUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid Step CA API URL: %w", err)
	}

	// Only HTTP and HTTPS schemes are supported
	if url.Scheme != "http" && url.Scheme != "https" {
		return nil, fmt.Errorf("invalid Step CA API URL: unsupported scheme %q", url.Scheme)
	}
	if url.Host == "" {
		return nil, fmt.Errorf("invalid Step CA API URL: missing host")
	}

	apiUrl = strings.TrimRight(apiUrl, "/")

	// Create Step CA client
	client, err := ca.NewClient(
		apiUrl,
		ca.WithRootSHA256(caFingerprint),
		ca.WithTimeout(10*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Step CA client: %w", err)
	}

	certPool := x509.NewCertPool()
	for _, cert := range chain {
		certPool.AddCert(cert)
	}

	return &StepClient{
		apiUrl:          apiUrl,
		provisionerName: provisionerName,
		caFingerprint:   caFingerprint,
		client:          client,
		kid:             jwk.KeyID,
		jwk:             jose.SigningKey{Algorithm: jose.ES256, Key: jwk.Key},
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    certPool,
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}, nil
}

func (c *StepClient) GetCRL(ctx context.Context) (*x509.RevocationList, error) {
	url := c.apiUrl + "/1.0/crl"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL request: %w", err)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send CRL request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get CRL: %s", res.Status)
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL response: %w", err)
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}

	return crl, nil
}

func (c *StepClient) CreateToken(subject string, sans []string) (string, error) {
	now := time.Now()
	nowMinus30 := now.Add(-30 * time.Second) // allow for clock skew
	nowPlus300 := now.Add(5 * time.Minute)   // token valid for 5 minutes

	// Create basic JWT claims
	claims := jwt.Claims{
		Issuer:    c.provisionerName,
		Subject:   subject,
		Audience:  jwt.Audience{c.apiUrl + "/sign"},
		IssuedAt:  jwt.NewNumericDate(nowMinus30),
		NotBefore: jwt.NewNumericDate(nowMinus30),
		Expiry:    jwt.NewNumericDate(nowPlus300),
		ID:        utils.GenerateActivityID(),
	}

	// Add custom Step CA claims
	type stepClaims struct {
		jwt.Claims
		SHA  string   `json:"sha"`
		SANs []string `json:"sans,omitempty"`
	}

	// Combine standard and custom claims
	fullClaims := stepClaims{
		Claims: claims,
		SHA:    c.caFingerprint,
		SANs:   sans,
	}

	// Create JWT signer using the JWK
	signerOpts := &jose.SignerOptions{}
	signerOpts.WithHeader("kid", c.kid)

	signer, err := jose.NewSigner(c.jwk, signerOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT signer: %w", err)
	}

	// Sign and serialize the JWT
	token, err := jwt.Signed(signer).Claims(fullClaims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return token, nil
}

func (c *StepClient) SignCSR(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	// Extract subject and SANs from CSR
	subject := csr.Subject.CommonName
	sans := utils.ExtractSANsFromCSR(csr)

	// Create JWT token for Step CA, signed with the JWK
	token, err := c.CreateToken(subject, sans)
	if err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	// Create sign request to Step CA
	signRequest := &api.SignRequest{
		CsrPEM: api.NewCertificateRequest(csr),
		OTT:    token,
	}

	// Sign the CSR with Step CA
	signResponse, err := c.client.SignWithContext(ctx, signRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR with Step CA: %w", err)
	}

	// Verify that a certificate was returned
	if signResponse.ServerPEM.Certificate == nil {
		return nil, fmt.Errorf("no certificate returned from Step CA")
	}

	// Return the signed certificate
	return signResponse.ServerPEM.Certificate, nil
}
