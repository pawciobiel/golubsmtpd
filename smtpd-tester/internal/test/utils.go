package test

import (
	"strings"
	"time"

	"github.com/pawciobiel/golubsmtpd/smtpd-tester/internal/client"
)

// ParseRecipients parses a comma-separated list of email addresses
func ParseRecipients(recipients string) []string {
	if recipients == "" {
		return []string{client.DefaultRecipient}
	}

	parts := strings.Split(recipients, ",")
	// Pre-allocate slice capacity for efficiency
	result := make([]string, 0, len(parts))

	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}

	if len(result) == 0 {
		return []string{client.DefaultRecipient}
	}

	return result
}

// ValidateConfig validates and sets defaults for client configuration
func ValidateConfig(config *client.Config) {
	if config.Host == "" {
		config.Host = "127.0.0.1"
	}

	if config.Port <= 0 || config.Port > 65535 {
		config.Port = 2525
	}

	if config.From == "" {
		config.From = "sender@example.com"
	}

	if len(config.Recipients) == 0 {
		config.Recipients = []string{client.DefaultRecipient}
	}

	if config.Subject == "" {
		config.Subject = "Test Message"
	}

	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Second
	}
}
