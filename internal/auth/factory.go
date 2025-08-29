package auth

import (
	"context"
	"log/slog"

	"github.com/pawciobiel/golubsmtpd/internal/config"
)

// AuthenticatorFactory creates an authenticator from configuration
type AuthenticatorFactory func(ctx context.Context, config map[string]interface{}, logger *slog.Logger) (Authenticator, error)

// Registry of available authenticator factories
var AuthenticatorRegistry = map[string]AuthenticatorFactory{
	"file":   NewFileAuthenticatorFromConfig,
	"memory": NewMemoryAuthenticatorFromConfig,
}

// CreateAuthenticator creates an authentication chain from configuration
func CreateAuthenticator(ctx context.Context, cfg *config.AuthConfig, logger *slog.Logger) (Authenticator, error) {
	return NewAuthChainFromConfig(ctx, cfg, logger)
}
