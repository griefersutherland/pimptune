package ms

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/griefersutherland/pimptune/internal/utils"
	msgraph "github.com/microsoftgraph/msgraph-sdk-go"
)

const (
	RESOURCE_GRAPH     = "https://graph.microsoft.com/"
	SCOPE_GRAPH        = RESOURCE_GRAPH + ".default"
	RESOURCE_INTUNE    = "https://api.manage.microsoft.com/"
	SCOPE_INTUNE       = RESOURCE_INTUNE + "/.default"          // note there are two slashes in this scope... idk why it be like that but it do
	appIdIntune        = "0000000a-0000-0000-c000-000000000000" // Intune App ID
	apiVersionIntune   = "2018-02-20"                           // Intune API version
	expirationInterval = time.Minute * 30                       // 30 minutes cache expiration
	// URL endpoints for SCEP actions
	endpointNotifySuccess = "/ScepActions/successNotification"
	endpointNotifyFailure = "/ScepActions/failureNotification"
	endpointVerify        = "/ScepActions/validateRequest"
)

// Microsoft (Graph and Intune) client
type MSClient struct {
	cred                  *azidentity.ClientSecretCredential // Azure credential
	httpClient            *http.Client                       // HTTP client for making requests
	graphClient           *msgraph.GraphServiceClient        // Microsoft Graph API client
	muEndpointScep        sync.Mutex                         // mutex for synchronizing access to SCEP endpoint
	endpointScepLastFetch time.Time                          // last fetch time for SCEP endpoint
	endpointScepUri       string                             // cached SCEP endpoint URI
	muToken               sync.Mutex                         // mutex for synchronizing access to Intune token
	intuneToken           *azcore.AccessToken                // cached Intune token
}

func NewMSClient(tenantID, clientID, clientSecret string) (*MSClient, error) {
	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		return nil, err
	}
	var scope = []string{"https://graph.microsoft.com/.default"}

	graphClient, err := msgraph.NewGraphServiceClientWithCredentials(cred, scope)
	if err != nil {
		return nil, err
	}

	return &MSClient{
		cred:        cred,
		graphClient: graphClient,
		httpClient:  &http.Client{Timeout: time.Second * 10},
	}, nil
}

// PopulateScepEndpoint fetches the Intune SCEP endpoint from Microsoft Graph
func (c *MSClient) PopulateScepEndpoint(ctx context.Context) error {
	c.muEndpointScep.Lock()
	defer c.muEndpointScep.Unlock()

	if (c.endpointScepUri != "" && !c.endpointScepLastFetch.IsZero()) && time.Since(c.endpointScepLastFetch) < expirationInterval {
		log.Trace().Msg("Cached SCEP endpoint is still valid, skipping fetch")
		return nil // still valid
	}

	endpoint, err := getGraphEndpointByProvider(ctx, c.graphClient, appIdIntune, "ScepRequestValidationFEService")
	if err != nil {
		c.endpointScepLastFetch = time.Time{}
		c.endpointScepUri = ""
		return err
	}
	log.Debug().Str("endpoint", endpoint).Msg("Fetched SCEP endpoint from Microsoft Graph")

	c.endpointScepLastFetch = time.Now()
	c.endpointScepUri = endpoint
	return nil
}

func (c *MSClient) GetScepEndpoint(ctx context.Context) (string, error) {
	if err := c.PopulateScepEndpoint(ctx); err != nil {
		return "", err
	}

	c.muEndpointScep.Lock()
	defer c.muEndpointScep.Unlock()
	return c.endpointScepUri, nil
}

func (c *MSClient) populateIntuneToken(ctx context.Context) error {
	c.muToken.Lock()
	defer c.muToken.Unlock()
	if c.isIntuneTokenValid() {
		log.Debug().Msg("Using cached Intune access token")
		return nil
	}
	c.intuneToken = nil

	tok, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://api.manage.microsoft.com//.default"}, // note the double slash...
	})
	if err != nil {
		return err
	}
	log.Debug().Msg("Fetched new Intune access token")

	if !utils.TokenHasRole(tok.Token, "scep_challenge_provider") {
		return fmt.Errorf("Intune token missing required role: scep_challenge_provider")
	}

	c.intuneToken = &tok
	return nil
}

func (c *MSClient) isIntuneTokenValid() bool {
	if c.intuneToken == nil {
		return false
	}
	if c.intuneToken.ExpiresOn.Before(time.Now().Add(time.Minute * 5)) {
		return false
	}
	return true
}

func (c *MSClient) GetIntuneToken(ctx context.Context) (string, error) {
	if err := c.populateIntuneToken(ctx); err != nil {
		return "", err
	}

	c.muToken.Lock()
	defer c.muToken.Unlock()
	return c.intuneToken.Token, nil
}

func (c *MSClient) intuneInfo(ctx context.Context) (endpoint string, headers map[string]string, activityId string, err error) {
	var token string

	activityId = utils.GenerateActivityID()

	token, err = c.GetIntuneToken(ctx)
	if err != nil {
		return "", nil, activityId, fmt.Errorf("failed to get Intune token: %w", err)
	}

	endpoint, err = c.GetScepEndpoint(ctx)
	if err != nil {
		return "", nil, activityId, fmt.Errorf("failed to get SCEP endpoint: %w", err)
	}

	headers = map[string]string{
		"Authorization":     "Bearer " + token,
		"api-version":       apiVersionIntune,
		"UserAgent":         utils.GetPimptuneName(), // java implementation uses "UserAgent" instead of "User-Agent"
		"User-Agent":        utils.GetPimptuneName(), // include both just in case
		"client-request-id": activityId,
	}

	return endpoint, headers, activityId, nil
}

func (c *MSClient) NotifyFailure(ctx context.Context, csr, txid string, hResult int64, errorDescription string) error {
	endpoint, headers, activityId, err := c.intuneInfo(ctx)
	if err != nil {
		return err
	}

	notification := NotifyFailureRequest{
		Notification: NotifyFailure{
			CertificateRequest: csr,
			TransactionID:      txid,
			HResult:            hResult,
			ErrorDescription:   errorDescription,
			CallerInfo:         utils.GetPimptuneName(),
		},
	}

	var resBody IntuneResponse

	status, _, res, err := c.postJsonWithRetry(
		ctx,
		endpoint+endpointNotifyFailure,
		headers,
		notification,
		&resBody,
	)

	if err != nil {
		if status != 0 {
			log.Error().Err(err).
				Int("status_code", status).
				Str("activity_id", activityId).
				Str("response_body", string(res)).
				Msg("Intune NotifyFailure HTTP response error")
		} else {
			log.Error().Err(err).
				Str("activity_id", activityId).
				Msg("Intune NotifyFailure request error")
		}
	}

	if status >= 200 && status <= 299 {
		log.Info().
			Str("activity_id", activityId).
			Msg("Intune NotifyFailure succeeded")
		return nil
	}
	log.Error().Int("status_code", status).
		Str("code", resBody.Code).
		Str("error_description", resBody.ErrorDescription).
		Str("activity_id", activityId).
		Msg("Intune NotifyFailure failed")

	return fmt.Errorf("Intune NotifyFailure failed with status code %d", status)
}

func (c *MSClient) NotifySuccess(ctx context.Context, csr, txid string, crt, root *x509.Certificate) error {
	endpoint, headers, activityId, err := c.intuneInfo(ctx)
	if err != nil {
		return err
	}

	notification := NotifySuccessRequest{
		Notification: NotifySuccess{
			CertificateRequest:           csr,
			TransactionID:                txid,
			CertificateThumbprint:        utils.FingerprintSha1(crt),
			CertificateSerialNumber:      crt.SerialNumber.Text(16),
			CertificateExpirationDateUTC: crt.NotAfter.UTC().Format(time.RFC3339),
			IssuingCertificateAuthority:  crt.Issuer.String(),
			CAConfiguration:              "",
			CertificateAuthority:         root.Subject.CommonName,
			CallerInfo:                   utils.GetPimptuneName(),
		},
	}

	var resBody IntuneResponse

	status, _, res, err := c.postJsonWithRetry(
		ctx,
		endpoint+endpointNotifySuccess,
		headers,
		notification,
		&resBody,
	)

	if err != nil {
		if status != 0 {
			log.Error().Err(err).
				Int("status_code", status).
				Str("activity_id", activityId).
				Str("response_body", string(res)).
				Msg("Intune NotifySuccess HTTP response error")
		} else {
			log.Error().Err(err).
				Str("activity_id", activityId).
				Msg("Intune NotifySuccess request error")
		}
	}

	if status >= 200 && status <= 299 {
		log.Info().
			Str("activity_id", activityId).
			Msg("Intune NotifySuccess succeeded")
		return nil
	}
	log.Error().Int("status_code", status).
		Str("code", resBody.Code).
		Str("error_description", resBody.ErrorDescription).
		Str("activity_id", activityId).
		Msg("Intune NotifySuccess failed")

	return fmt.Errorf("Intune NotifySuccess failed with status code %d", status)
}

func (c *MSClient) VerifyCSR(ctx context.Context, csr string, txid string) (bool, error) {
	endpoint, headers, activityId, err := c.intuneInfo(ctx)
	if err != nil {
		return false, err
	}

	var reqBody ValidateCSRRequest
	reqBody.Request.CertificateRequest = csr
	reqBody.Request.TransactionID = txid
	reqBody.Request.CallerInfo = utils.GetPimptuneName()

	var resBody IntuneResponse

	url := endpoint + endpointVerify
	statusCode, header, resBytes, err := c.postJsonWithRetry(
		ctx,
		url,
		headers,
		reqBody,
		&resBody,
	)
	if err != nil {
		if statusCode != 0 {
			log.Warn().
				Int("status_code", statusCode).
				Str("activity_id", activityId).
				Str("header", fmt.Sprintf("%v", header)).
				Str("response_body", string(resBytes)).
				Msg("Intune CSR verification failed HTTP response")
		} else {
			log.Error().Err(err).
				Str("activity_id", activityId).
				Msg("Intune CSR verification request error")
		}
		return false, err
	}

	success := strings.EqualFold(resBody.Code, "success")
	if !success {
		log.Warn().
			Str("code", resBody.Code).
			Str("error_description", resBody.ErrorDescription).
			Str("activity_id", activityId).
			Msg("Intune CSR verification failed")
	} else {
		log.Info().
			Str("activity_id", activityId).
			Msg("Intune CSR verification succeeded")
	}

	return success, nil
}
