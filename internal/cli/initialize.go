package cli

import (
	"context"
	"fmt"

	"github.com/griefersutherland/pimptune/internal/ms"
	"github.com/griefersutherland/pimptune/internal/step"
	"github.com/griefersutherland/pimptune/internal/store"
	"github.com/griefersutherland/pimptune/internal/utils"
	"github.com/rs/zerolog/log"
)

func initialize(ctx context.Context, params *Params) (utils.Verifier, utils.Signer, utils.Store, error) {
	// Create a microsoft client to interact with Graph and Intune APIs
	clientMs, err := ms.NewMSClient(
		params.IntuneTenantID,
		params.IntuneClientID,
		params.IntuneClientSecret,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create MS client: %w", err)
	}

	// Initial population of SCEP endpoint
	err = clientMs.PopulateScepEndpoint(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to populate Intune SCEP endpoint from Microsoft Graph: %w", err)
	}
	log.Info().Msg("[+] Confirmed ability to Populate Intune SCEP endpoint from Microsoft Graph")

	// Warm up the token cache
	_, err = clientMs.GetIntuneToken(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to verify test CSR with Intune: %w", err)
	}
	log.Info().Msg("[+] Confirmed ability to Verify CSR with Intune")

	// Create a Step client to sign CSRs
	clientStep, err := step.NewStepClient(
		params.StepApiUrl,
		params.StepProvisionerName,
		utils.FingerprintSha256(params.RootCaCrt),
		params.CaChain,
		params.StepJWK,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create Step client: %w", err)
	}
	log.Info().Msg("[+] Initialized Step client for signing CSRs")

	// Create a data store for issued certificates
	certStore, err := store.NewCertificateStore(ctx, params.DatabasePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to initialize certificate store: %w", err)
	}

	log.Info().Msg("[+] Initialized certificate store database")

	return clientMs, clientStep, certStore, nil
}
