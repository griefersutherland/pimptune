package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/griefersutherland/pimptune/internal/crt"
	"github.com/griefersutherland/pimptune/internal/scep"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
)

func run(ctx context.Context, c *cli.Command) error {
	if c.Bool("verbose") {
		log.Logger = log.Logger.Level(zerolog.DebugLevel)
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Enabled verbose logging output")
	}

	// load the configuration parameters from CLI flags
	params, err := loadParams(c)
	if err != nil {
		return err
	}

	// create a new muxer
	mux := chi.NewMux()

	// TODO: implement SCEP server for non-Windows platforms
	verifier, signer, store, err := initialize(ctx, params)
	if err != nil {
		return err
	}

	// Create a SCEP server for Windows Intune clients
	scepServer := scep.NewSCEPServer(&scep.SCEPServerParams{
		RACert:   params.RaCrt,
		RAKey:    params.RaKey,
		CAChain:  params.CaChain,
		Verifier: verifier,
		Signer:   signer,
		Store:    store,
	})

	// Create a CRL server backed by the Step CA server
	crlServer := crt.NewCrlServer(signer)
	crtServer := crt.NewCrtServer(params.IssuingCaCrt)

	mux.Route(params.ScepPath, func(r chi.Router) {
		// Handlers for Windows SCEP clients
		r.Get("/pkiclient.exe", scepServer.ServeHTTP)
		r.Post("/pkiclient.exe", scepServer.ServeHTTP)
		r.Get("/", scepServer.ServeHTTP)
		r.Post("/", scepServer.ServeHTTP)
	})

	// CRT endpoint
	mux.Route(params.CRTPath, func(r chi.Router) {
		r.Get("/", crtServer.ServeHTTP)
	})

	// CRL endpoint
	mux.Route(params.CRLPath, func(r chi.Router) {
		r.Get("/", crlServer.ServeHTTP)
	})

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", params.Port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		log.Warn().Msg("Shutting down SCEP server and cleaning up resources...")

		// Shutdown the HTTP server gracefully
		ctxShutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		httpServer.Shutdown(ctxShutdown)

		// Close the certificate store after in-flight requests are completed
		if err := store.Close(); err != nil {
			log.Error().Err(err).Msg("Error closing certificate store")
		}
	}()

	// Start purging revoked certificates
	scepServer.StartPurging(ctx)

	log.Info().Str("address", httpServer.Addr).Msg("Starting SCEP server...")
	err = httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("SCEP server error: %w", err)
	}

	return nil
}
