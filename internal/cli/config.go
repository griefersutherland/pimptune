package cli

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/griefersutherland/pimptune/internal/utils"
	"github.com/urfave/cli/v3"
)

type Params struct {
	Port                uint16
	ScepPath            string
	CRTPath             string
	CRLPath             string
	OAuthIssuerUrl      string
	OAuthClientID       string
	OAuthClientSecret   string
	IntuneTenantID      string
	IntuneClientID      string
	IntuneClientSecret  string
	RootCaCrt           *x509.Certificate
	IssuingCaCrt        *x509.Certificate
	RaCrt               *x509.Certificate
	RaKey               crypto.PrivateKey
	CaChain             []*x509.Certificate
	StepApiUrl          string
	StepProvisionerName string
	StepJWK             *jose.JSONWebKey
	DatabasePath        string
}

func loadParams(c *cli.Command) (*Params, error) {
	// Parse the server settings
	port := c.Uint16("port")
	scepPath := c.String("scep-path")
	crtPath := c.String("crt-path")
	crlPath := c.String("crl-path")

	if !strings.HasPrefix(scepPath, "/") {
		return nil, fmt.Errorf("SCEP path must start with a leading slash '/'")
	}

	if !strings.HasPrefix(crtPath, "/") {
		return nil, fmt.Errorf("CRT path must start with a leading slash '/'")
	}

	if !strings.HasPrefix(crlPath, "/") {
		return nil, fmt.Errorf("CRL path must start with a leading slash '/'")
	}

	var oauthIssuerUrl, oauthClientID, oauthClientSecret string

	/*
		oauthIssuerUrl := c.String("oauth-issuer-url")
		if oauthIssuerUrl == "" {
			return nil, fmt.Errorf("OAuth issuer URL is required")
		}

		oauthClientID := c.String("oauth-client-id")
		if oauthClientID == "" {
			return nil, fmt.Errorf("OAuth client ID is required")
		}

		oauthClientSecret := c.String("oauth-client-secret")
		oauthClientSecretFile := c.String("oauth-client-secret-file")

		if oauthClientSecret == "" {
			if oauthClientSecretFile == "" {
				return nil, fmt.Errorf("OAuth client secret or client secret file is required")
			}
			secretBytes, err := os.ReadFile(oauthClientSecretFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read OAuth client secret file: %w", err)
			}
			oauthClientSecret = string(secretBytes)
			if oauthClientSecret == "" {
				return nil, fmt.Errorf("OAuth client secret file is empty")
			}
		} else {
			if oauthClientSecretFile != "" {
				return nil, fmt.Errorf("cannot specify both --oauth-client-secret and --oauth-client-secret-file")
			}
		}
	*/

	// Parse the Intune application settings used to verify SCEP challengs
	intuneTenantID := c.String("intune-tenant-id")
	if intuneTenantID == "" {
		return nil, fmt.Errorf("Intune tenant ID is required")
	}

	intuneClientID := c.String("intune-client-id")
	if intuneClientID == "" {
		return nil, fmt.Errorf("Intune client ID is required")
	}

	intuneClientSecret := c.String("intune-client-secret")
	intuneClientSecretFile := c.String("intune-client-secret-file")

	if intuneClientSecret == "" {
		if intuneClientSecretFile == "" {
			return nil, fmt.Errorf("Intune client secret or client secret file is required")
		}
		secretBytes, err := os.ReadFile(intuneClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read Intune client secret file: %w", err)
		}
		intuneClientSecret = string(secretBytes)
		if intuneClientSecret == "" {
			return nil, fmt.Errorf("Intune client secret file is empty")
		}
	} else {
		if intuneClientSecretFile != "" {
			return nil, fmt.Errorf("cannot specify both --intune-client-secret and --intune-client-secret-file")
		}
	}

	// Parse the trust anchor Root CA
	/*
		rootCaCrtFile := c.String("root-ca-crt")
		if rootCaCrtFile == "" || !utils.IsFile(rootCaCrtFile) {
			return nil, fmt.Errorf("Root CA certificate file is required")
		}
		rootCaCrtBytes, err := os.ReadFile(rootCaCrtFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read Root CA certificate file: %w", err)
		}
		rootCaCrt, err := utils.TryParseCertificate(rootCaCrtBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Root CA certificate: %w", err)
		}
	*/

	// Parse the SCEP server RA certificate and key
	raCrtFile := c.String("ra-crt")
	if raCrtFile == "" || !utils.IsFile(raCrtFile) {
		return nil, fmt.Errorf("RA certificate file is required")
	}

	raCrtBytes, err := os.ReadFile(raCrtFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read RA certificate file: %w", err)
	}

	raCrt, err := utils.TryParseCertificate(raCrtBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RA certificate: %w", err)
	}

	raKeyFile := c.String("ra-key")
	if raKeyFile == "" || !utils.IsFile(raKeyFile) {
		return nil, fmt.Errorf("RA key file is required")
	}

	raKeyPassword := c.String("ra-key-password")
	raKeyPasswordFile := c.String("ra-key-password-file")
	if raKeyPasswordFile != "" {
		if raKeyPassword != "" {
			return nil, fmt.Errorf("cannot specify both --ra-key-password and --ra-key-password-file")
		}
		raKeyPassword, err = utils.ReadTextFile(raKeyPasswordFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read RA key password file: %w", err)
		}
	}

	raKeyBytes, err := os.ReadFile(raKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read RA key file: %w", err)
	}

	raKey, err := utils.TryParseKey(raKeyBytes, &raKeyPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RA private key: %w", err)
	}

	switch keyType := raKey.(type) {
	case *rsa.PrivateKey:
	default:
		return nil, fmt.Errorf("only RSA keys are supported for the SCEP server RA certificate, got %T", keyType)
	}

	match, err := utils.CheckCrtKeyMatch(raCrt, raKey)
	if err != nil {
		return nil, fmt.Errorf("failed to verify matching CA certificate and key: %w", err)
	}
	if !match {
		return nil, fmt.Errorf("CA certificate and key do not match")
	}

	// Parse the full CA chain, last cert should be the root CA
	caChainFile := c.String("ca-chain")
	if caChainFile == "" || !utils.IsFile(caChainFile) {
		return nil, fmt.Errorf("CA chain file is required")
	}

	chainBytes, err := os.ReadFile(caChainFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA chain file: %w", err)
	}

	chain, err := utils.TryParseChain(chainBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA chain: %w", err)
	}
	for _, cert := range chain {
		if !cert.IsCA {
			return nil, fmt.Errorf("CA chain file contains non-CA certificate")
		}
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("CA chain file contains no certificates")
	}

	rootCaCrt := chain[len(chain)-1]
	issuingCaCrt := chain[0]

	// Parse the Step CA settings
	stepApiUrl := c.String("step-api-url")
	if stepApiUrl == "" {
		return nil, fmt.Errorf("Step API URL is required")
	}

	stepProvisionerName := c.String("step-provisioner-name")
	if stepProvisionerName == "" {
		return nil, fmt.Errorf("Step provisioner name is required")
	}

	// Parse the Step CA JWK authentication settings
	jwkFile := c.String("step-json-web-key-file")
	if jwkFile == "" || !utils.IsFile(jwkFile) {
		return nil, fmt.Errorf("JSON Web Key file is required")
	}

	jwkPassword := c.String("step-json-web-key-password")
	jwkPasswordFile := c.String("step-json-web-key-password-file")

	if jwkPassword == "" {
		if jwkPasswordFile != "" {
			if !utils.IsFile(jwkPasswordFile) {
				return nil, fmt.Errorf("JWK password file does not exist")
			}
			jwkPassword, err = utils.ReadTextFile(jwkPasswordFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read JWK password file: %w", err)
			}
		}
	}

	jwkBytes, err := os.ReadFile(jwkFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWK file: %w", err)
	}

	jwk, err := utils.ParseJWK(jwkBytes, jwkPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK file: %w", err)
	}

	if jwk.IsPublic() {
		return nil, fmt.Errorf("JWK must contain a private key for signing, but only a public key was found")
	}

	dbPath := c.String("database-path")
	if dbPath == "" {
		return nil, fmt.Errorf("A valid database path is required")
	}

	return &Params{
		Port:                port,
		ScepPath:            "/" + strings.TrimLeft(scepPath, "/"),
		CRTPath:             "/" + strings.TrimLeft(crtPath, "/"),
		CRLPath:             "/" + strings.TrimLeft(crlPath, "/"),
		OAuthIssuerUrl:      oauthIssuerUrl,
		OAuthClientID:       oauthClientID,
		OAuthClientSecret:   oauthClientSecret,
		IntuneTenantID:      intuneTenantID,
		IntuneClientID:      intuneClientID,
		IntuneClientSecret:  intuneClientSecret,
		RootCaCrt:           rootCaCrt,
		IssuingCaCrt:        issuingCaCrt,
		RaCrt:               raCrt,
		RaKey:               raKey,
		CaChain:             chain,
		StepApiUrl:          stepApiUrl,
		StepProvisionerName: stepProvisionerName,
		StepJWK:             jwk,
		DatabasePath:        dbPath,
	}, nil
}
