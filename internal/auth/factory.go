package auth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/pawciobiel/golubsmtpd/internal/config"
)

// AuthenticatorFactory creates an authenticator from configuration
type AuthenticatorFactory func(ctx context.Context, config map[string]interface{}, logger *slog.Logger) (Authenticator, error)

// Registry of available authenticator factories
var authenticatorRegistry = map[string]AuthenticatorFactory{
	"file":   NewFileAuthenticatorFromConfig,
	"memory": NewMemoryAuthenticatorFromConfig,
}

// CreateAuthenticator creates an authenticator based on configuration
func CreateAuthenticator(ctx context.Context, cfg *config.AuthConfig, logger *slog.Logger) (Authenticator, error) {
	factory, exists := authenticatorRegistry[cfg.Plugin]
	if !exists {
		return nil, fmt.Errorf("unsupported authentication plugin: %s", cfg.Plugin)
	}

	pluginConfig, exists := cfg.Plugins[cfg.Plugin]
	if !exists {
		return nil, fmt.Errorf("%s plugin configuration not found", cfg.Plugin)
	}

	return factory(ctx, pluginConfig, logger)
}
