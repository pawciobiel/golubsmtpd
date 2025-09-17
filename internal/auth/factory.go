package auth

import (
	"context"

	"github.com/pawciobiel/golubsmtpd/internal/config"
)

// AuthenticatorFactory creates an authenticator from configuration
type AuthenticatorFactory func(ctx context.Context, config map[string]interface{}) (Authenticator, error)

// Registry of available authenticator factories
var AuthenticatorRegistry = map[string]AuthenticatorFactory{
	"file":   NewFileAuthenticatorFromConfig,
	"memory": NewMemoryAuthenticatorFromConfig,
}

// CreateAuthenticator creates an authentication chain from configuration
func CreateAuthenticator(ctx context.Context, cfg *config.AuthConfig) (Authenticator, error) {
	return NewAuthChainFromConfig(ctx, cfg)
}
