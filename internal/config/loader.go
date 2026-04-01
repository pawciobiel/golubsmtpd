package config

import (
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"
)

func Load(configPath string) (*Config, error) {
	config := DefaultConfig()

	if configPath == "" {
		return config, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

func validateConfig(config *Config) error {
	// Normalize: if no listeners configured, promote legacy Port field
	if len(config.Server.Listeners) == 0 {
		if config.Server.Port <= 0 || config.Server.Port > 65535 {
			return fmt.Errorf("invalid port: %d", config.Server.Port)
		}
		config.Server.Listeners = []ListenerConfig{
			{Port: config.Server.Port, Mode: ListenerModePlain},
		}
	}

	validModes := map[ListenerMode]bool{
		ListenerModePlain:    true,
		ListenerModeSTARTTLS: true,
		ListenerModeTLS:      true,
	}
	for _, l := range config.Server.Listeners {
		if l.Port <= 0 || l.Port > 65535 {
			return fmt.Errorf("invalid listener port: %d", l.Port)
		}
		if !validModes[l.Mode] {
			return fmt.Errorf("invalid listener mode %q for port %d (valid: plain, starttls, tls)", l.Mode, l.Port)
		}
		if (l.Mode == ListenerModeSTARTTLS || l.Mode == ListenerModeTLS) && !config.TLS.Enabled {
			return fmt.Errorf("listener port %d uses mode %q but tls is not enabled", l.Port, l.Mode)
		}
	}

	if config.Server.MaxConnections <= 0 {
		return fmt.Errorf("max_connections must be positive: %d", config.Server.MaxConnections)
	}

	if config.Server.MaxConnectionsPerIP <= 0 {
		return fmt.Errorf("max_connections_per_ip must be positive: %d", config.Server.MaxConnectionsPerIP)
	}

	if config.Server.Hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}

	if config.Maildir.BasePath == "" {
		return fmt.Errorf("maildir base_path cannot be empty")
	}

	if len(config.Auth.PluginChain) == 0 {
		return fmt.Errorf("auth plugin_chain cannot be empty")
	}

	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if !validLogLevels[config.Logging.Level] {
		return fmt.Errorf("invalid log level: %s", config.Logging.Level)
	}

	validLogFormats := map[string]bool{
		"text": true, "json": true,
	}
	if !validLogFormats[config.Logging.Format] {
		return fmt.Errorf("invalid log format: %s", config.Logging.Format)
	}

	// Validate security settings
	validDNSBLActions := map[string]bool{
		"log": true, "reject": true,
	}
	if config.Security.DNSBL.Enabled && !validDNSBLActions[config.Security.DNSBL.Action] {
		return fmt.Errorf("invalid dnsbl action: %s", config.Security.DNSBL.Action)
	}

	// Validate outbound delivery TLS and timeout settings
	validOutboundPolicies := map[string]bool{"opportunistic": true, "required": true}
	if p := config.Delivery.Outbound.TLS.Policy; !validOutboundPolicies[p] {
		return fmt.Errorf("invalid outbound tls policy %q: must be opportunistic or required", p)
	}
	validMinVersions := map[string]bool{"tls12": true, "tls13": true}
	if v := config.Delivery.Outbound.TLS.MinVersion; !validMinVersions[v] {
		return fmt.Errorf("invalid outbound tls min_version %q: must be tls12 or tls13", v)
	}
	if config.Delivery.Outbound.TLS.SkipVerify {
		slog.Warn("outbound TLS certificate verification disabled — only use in test environments")
	}
	applyDefaultOutboundTimeouts(&config.Delivery.Outbound.Timeouts)

	return nil
}

// applyDefaultOutboundTimeouts fills zero-value timeout fields with safe defaults.
// This handles partial YAML config where only some timeouts are overridden.
func applyDefaultOutboundTimeouts(t *OutboundTimeouts) {
	defaults := DefaultConfig().Delivery.Outbound.Timeouts
	if t.Dial <= 0 {
		t.Dial = defaults.Dial
	}
	if t.Greeting <= 0 {
		t.Greeting = defaults.Greeting
	}
	if t.Command <= 0 {
		t.Command = defaults.Command
	}
	if t.TLSHandshake <= 0 {
		t.TLSHandshake = defaults.TLSHandshake
	}
	if t.DataTransfer <= 0 {
		t.DataTransfer = defaults.DataTransfer
	}
}

