package config

import (
	"fmt"
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
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid port: %d", config.Server.Port)
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

	return nil
}
