package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"

	"github.com/pawciobiel/golubsmtpd/internal/config"
)

// AuthChain implements authentication using a chain of plugins
type AuthChain struct {
	plugins      []Authenticator
	logger       *slog.Logger
	authCount    int64 // authentication attempts (atomic)
	successCount int64 // successful authentications (atomic)
}

// NewAuthChainFromConfig creates an authentication chain from configuration
func NewAuthChainFromConfig(ctx context.Context, cfg *config.AuthConfig, logger *slog.Logger) (*AuthChain, error) {
	// Check context before processing
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if len(cfg.PluginChain) == 0 {
		return nil, fmt.Errorf("no authentication plugins configured in chain")
	}

	// Check for duplicate plugins in chain
	seen := make(map[string]struct{})
	for _, pluginName := range cfg.PluginChain {
		if _, exists := seen[pluginName]; exists {
			return nil, fmt.Errorf("duplicate plugin '%s' in chain", pluginName)
		}
		seen[pluginName] = struct{}{}
	}

	var plugins []Authenticator

	// Create each plugin in chain order
	for i, pluginName := range cfg.PluginChain {
		pluginConfig, exists := cfg.Plugins[pluginName]
		if !exists {
			return nil, fmt.Errorf("plugin '%s' referenced in chain but not configured in plugins section", pluginName)
		}

		factory, exists := AuthenticatorRegistry[pluginName]
		if !exists {
			return nil, fmt.Errorf("unknown authentication plugin: %s", pluginName)
		}

		plugin, err := factory(ctx, pluginConfig, logger)
		if err != nil {
			// Clean up already created plugins
			for _, p := range plugins {
				p.Close()
			}
			return nil, fmt.Errorf("failed to create plugin '%s' at position %d: %w", pluginName, i, err)
		}

		plugins = append(plugins, plugin)
	}

	chain := &AuthChain{
		plugins: plugins,
		logger:  logger,
	}

	pluginNames := make([]string, len(plugins))
	for i, plugin := range plugins {
		pluginNames[i] = plugin.Name()
	}

	logger.Info("Authentication chain initialized", "plugins", pluginNames, "count", len(plugins))
	return chain, nil
}

// Authenticate tries each plugin in order until one succeeds
func (c *AuthChain) Authenticate(ctx context.Context, username, password string) *AuthResult {
	atomic.AddInt64(&c.authCount, 1)

	if username == "" || password == "" {
		return &AuthResult{
			Success: false,
			Error:   fmt.Errorf("username and password required"),
		}
	}

	// Try each plugin in chain order
	for _, plugin := range c.plugins {
		// Check context before trying next plugin
		select {
		case <-ctx.Done():
			return &AuthResult{
				Success: false,
				Error:   ctx.Err(),
			}
		default:
		}

		c.logger.Debug("Attempting authentication",
			"username", username,
			"plugin", plugin.Name())

		result := plugin.Authenticate(ctx, username, password)

		if result.Success {
			atomic.AddInt64(&c.successCount, 1)
			c.logger.Info("Authentication successful",
				"username", username,
				"plugin", plugin.Name())
			return result
		}

		// Log failure but continue to next plugin
		if result.Error != nil {
			c.logger.Debug("Authentication plugin error",
				"username", username,
				"plugin", plugin.Name(),
				"error", result.Error)
		} else {
			c.logger.Debug("Authentication failed",
				"username", username,
				"plugin", plugin.Name())
		}
	}

	c.logger.Debug("Authentication failed: all plugins exhausted", "username", username)
	return &AuthResult{Success: false}
}

// ValidateUser tries each plugin in order until one validates the user
func (c *AuthChain) ValidateUser(ctx context.Context, email string) bool {
	if email == "" {
		return false
	}

	// Try each plugin in chain order
	for _, plugin := range c.plugins {
		// Check context before trying next plugin
		select {
		case <-ctx.Done():
			return false
		default:
		}

		c.logger.Debug("Attempting user validation",
			"email", email,
			"plugin", plugin.Name())

		if plugin.ValidateUser(ctx, email) {
			c.logger.Debug("User validation successful",
				"email", email,
				"plugin", plugin.Name())
			return true
		}

		c.logger.Debug("User validation failed",
			"email", email,
			"plugin", plugin.Name())
	}

	c.logger.Debug("User validation failed: all plugins exhausted", "email", email)
	return false
}

// Name returns the chain name with plugin list
func (c *AuthChain) Name() string {
	names := make([]string, len(c.plugins))
	for i, plugin := range c.plugins {
		names[i] = plugin.Name()
	}

	return fmt.Sprintf("chain[%s]", strings.Join(names, ","))
}

// Close cleans up all plugins in the chain
func (c *AuthChain) Close() error {
	for _, plugin := range c.plugins {
		if err := plugin.Close(); err != nil {
			c.logger.Error("Error closing auth plugin",
				"plugin", plugin.Name(),
				"error", err)
		}
	}
	return nil
}

// GetStats returns authentication statistics for the chain
func (c *AuthChain) GetStats() (attempts, successes int64) {
	return atomic.LoadInt64(&c.authCount), atomic.LoadInt64(&c.successCount)
}
