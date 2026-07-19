package cli

import (
	"fmt"

	"github.com/griefersutherland/pimptune/internal/utils"
	"github.com/urfave/cli/v3"
)

var App = cli.Command{
	Name:    "pimptune",
	Usage:   "A SCEP server for intune SCEP profile enrollment",
	Version: utils.GetPimptuneVersion(),
	Commands: []*cli.Command{
		{
			Name:    "run",
			Usage:   "Run the Pimptune server",
			Aliases: []string{"start"},
			Action:  run,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    "verbose",
					Usage:   "Enable verbose logging output",
					Sources: cli.EnvVars("PIMPTUNE_VERBOSE"),
				},
				// Server listener configuration
				&cli.Uint16Flag{
					Name:    "port",
					Usage:   "The port for the Pimptune server to listen on.",
					Value:   8080,
					Sources: cli.EnvVars("PIMPTUNE_PORT"),
					Validator: func(u uint16) error {
						if !(u > 0) {
							return fmt.Errorf("Port must be > 0, got '%d'", u)
						}
						return nil
					},
				},
				&cli.StringFlag{
					Name:    "scep-path",
					Usage:   "The URL path to serve SCEP requests on.",
					Value:   "/scep",
					Sources: cli.EnvVars("PIMPTUNE_SCEP_PATH"),
				},
				&cli.StringFlag{
					Name:    "crt-path",
					Usage:   "The URL path to serve the issuing CA CRT.",
					Value:   "/crt",
					Sources: cli.EnvVars("PIMPTUNE_CRT_PATH"),
				},
				&cli.StringFlag{
					Name:    "crl-path",
					Usage:   "The URL path to serve the CRL from Step CA.",
					Value:   "/crl",
					Sources: cli.EnvVars("PIMPTUNE_CRL_PATH"),
				},
				/*
					// OAuth configuration to allow managers to sign into the web application
					&cli.StringFlag{
						Name:    "oauth-issuer-url",
						Usage:   "The OAuth Issuere URL used to authenticate managers.",
						Value:   "",
						Sources: cli.EnvVars("PIMPTUNE_OAUTH_ISSUER_URL"),
					},
					&cli.StringFlag{
						Name:    "oauth-client-id",
						Usage:   "The Azure AD application ID used to authenticate managers.",
						Value:   "",
						Sources: cli.EnvVars("PIMPTUNE_OAUTH_CLIENT_ID"),
					},
					&cli.StringFlag{
						Name:    "oauth-client-secret",
						Usage:   "The Azure AD application secret used to authenticate managers.",
						Value:   "",
						Sources: cli.EnvVars("PIMPTUNE_OAUTH_CLIENT_SECRET"),
					},
					&cli.StringFlag{
						Name:    "oauth-client-secret-file",
						Usage:   "File containing the Azure AD application secret used to authenticate managers.",
						Value:   "",
						Sources: cli.EnvVars("PIMPTUNE_OAUTH_CLIENT_SECRET_FILE"),
					},
				*/
				// Intune verification application with permissions to verify SCEP requests
				&cli.StringFlag{
					Name:    "intune-tenant-id",
					Usage:   "The Azure AD tenant ID where the Intune instance is located.",
					Value:   "",
					Sources: cli.EnvVars("PIMPTUNE_INTUNE_TENANT_ID"),
				},
				&cli.StringFlag{
					Name:    "intune-client-id",
					Usage:   "The Azure AD client ID of the application with SCEP permissions.",
					Value:   "",
					Sources: cli.EnvVars("PIMPTUNE_INTUNE_CLIENT_ID"),
				},
				&cli.StringFlag{
					Name:    "intune-client-secret",
					Usage:   "The Azure AD client secret of the application with SCEP permissions.",
					Value:   "",
					Sources: cli.EnvVars("PIMPTUNE_INTUNE_CLIENT_SECRET"),
				},
				&cli.StringFlag{
					Name:    "intune-client-secret-file",
					Usage:   "File containing the Azure AD client secret of the application with SCEP permissions.",
					Value:   "",
					Sources: cli.EnvVars("PIMPTUNE_INTUNE_CLIENT_SECRET_FILE"),
				},
				// Certificates and keys configuration
				&cli.StringFlag{
					Name:      "ra-crt",
					TakesFile: true,
					Usage:     "Path to the RA certificate file (must be RSA) in PEM/DER format.",
					Sources:   cli.EnvVars("PIMPTUNE_RA_CRT"),
				},
				&cli.StringFlag{
					Name:      "ra-key",
					TakesFile: true,
					Usage:     "Path to the RA private key file (must be RSA) in PEM format.",
					Sources:   cli.EnvVars("PIMPTUNE_RA_KEY"),
				},
				&cli.StringFlag{
					Name:    "ra-key-password",
					Usage:   "RA private key password.",
					Sources: cli.EnvVars("PIMPTUNE_RA_KEY_PASSWORD"),
				},
				&cli.StringFlag{
					Name:      "ra-key-password-file",
					TakesFile: true,
					Usage:     "Path to the RA private key password.",
					Sources:   cli.EnvVars("PIMPTUNE_RA_KEY_PASSWORD_FILE"),
				},
				&cli.StringFlag{
					Name:      "ca-chain",
					TakesFile: true,
					Usage:     "Path to the CA certificate chain file in PEM format.",
					Sources:   cli.EnvVars("PIMPTUNE_CA_CHAIN"),
				},
				// Step CA configuration
				&cli.StringFlag{
					Name:    "step-api-url",
					Usage:   "The URL of the Step API.",
					Sources: cli.EnvVars("PIMPTUNE_STEP_API_URL"),
				},
				&cli.StringFlag{
					Name:    "step-provisioner-name",
					Usage:   "The name of the Step provisioner to use.",
					Sources: cli.EnvVars("PIMPTUNE_STEP_PROVISIONER_NAME"),
				},
				&cli.StringFlag{
					Name:      "step-json-web-key-file",
					TakesFile: true,
					Usage:     "Path to the JSON Web Key (JWK) file for signing Step requests.",
					Sources:   cli.EnvVars("PIMPTUNE_STEP_JSON_WEB_KEY_FILE"),
				},
				&cli.StringFlag{
					Name:    "step-json-web-key-password",
					Usage:   "Password value to decrypt the JSON Web Key file.",
					Sources: cli.EnvVars("PIMPTUNE_STEP_JSON_WEB_KEY_PASSWORD"),
				},
				&cli.StringFlag{
					Name:      "step-json-web-key-password-file",
					TakesFile: true,
					Usage:     "Path to the JSON Web Key (JWK) password file for signing SCEP responses.",
					Sources:   cli.EnvVars("PIMPTUNE_STEP_JSON_WEB_KEY_PASSWORD_FILE"),
				},
				// Database configuration
				&cli.StringFlag{
					Name:    "database-path",
					Usage:   "Path to the SQLite database file for storing certificate records.",
					Value:   "./pimptune.db",
					Sources: cli.EnvVars("PIMPTUNE_DATABASE_PATH"),
				},
			},
		},
	},
}
