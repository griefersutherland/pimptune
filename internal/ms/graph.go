package ms

import (
	"context"
	"fmt"
	"strings"

	"github.com/griefersutherland/pimptune/internal/utils"
	msgraph "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
	"github.com/rs/zerolog/log"
)

// getGraphEndpointByProvider fetches the endpoint URI from Microsoft Graph by App ID and Provider Name
func getGraphEndpointByProvider(ctx context.Context, client *msgraph.GraphServiceClient, appId string, providerName string) (string, error) {
	log.Debug().Msg("Fetching SCEP endpoint from Microsoft Graph...")

	spGetCfg := &serviceprincipals.ServicePrincipalsRequestBuilderGetRequestConfiguration{
		QueryParameters: &serviceprincipals.ServicePrincipalsRequestBuilderGetQueryParameters{
			Filter: utils.Ptr(fmt.Sprintf("appId eq '%s'", appId)),
			Select: []string{"id", "appId", "displayName"},
			Top:    utils.Ptr(int32(5)),
		},
	}

	sps, err := client.ServicePrincipals().Get(ctx, spGetCfg)
	if err != nil {
		return "", err
	}

	if sps.GetValue() == nil || len(sps.GetValue()) == 0 {
		return "", fmt.Errorf("no servicePrincipals found for appId %s", appId)
	}

	sp := sps.GetValue()[0]
	spID := utils.Deref(sp.GetId())
	if sp.GetId() == nil || spID == "" {
		return "", fmt.Errorf("servicePrincipal missing id or appId")
	}

	log.Debug().
		Str("principal_name", utils.Deref(sp.GetDisplayName())).
		Str("app_id", utils.Deref(sp.GetAppId())).
		Str("principal_id", spID).
		Msgf("Found ServicePrincipal!")

	eps, err := client.ServicePrincipals().ByServicePrincipalId(spID).Endpoints().Get(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get endpoints for servicePrincipal id %s: %w", spID, err)
	}

	for _, ep := range eps.GetValue() {
		if strings.EqualFold(utils.Deref(ep.GetProviderName()), providerName) {
			uri := utils.Deref(ep.GetUri())
			if uri == "" {
				return "", fmt.Errorf("endpoint %s has empty uri", providerName)
			}
			return uri, nil
		}
	}

	return "", fmt.Errorf("endpoint with providerName %s not found", providerName)
}
