package smtp

import (
	"strings"
	"testing"

	"github.com/pawciobiel/golubsmtpd/internal/config"
)

func TestEmailValidation(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		validation    []string
		shouldPass    bool
		expectedError string
	}{
		// Basic validation tests
		{
			name:       "valid simple email",
			email:      "test@example.com",
			validation: []string{ValidationBasic},
			shouldPass: true,
		},
		{
			name:          "empty email",
			email:         "",
			validation:    []string{ValidationBasic},
			shouldPass:    false,
			expectedError: "email address cannot be empty",
		},
		{
			name:          "no @ symbol",
			email:         "testexample.com",
			validation:    []string{ValidationBasic},
			shouldPass:    false,
			expectedError: "invalid email format",
		},
		{
			name:          "multiple @ symbols",
			email:         "test@test@example.com",
			validation:    []string{ValidationBasic},
			shouldPass:    false,
			expectedError: "invalid email format",
		},
		{
			name:       "email with angle brackets",
			email:      "<test@example.com>",
			validation: []string{ValidationBasic},
			shouldPass: true,
		},

		// Local/development addresses that pass basic but may fail extended
		{
			name:       "local dev address - basic validation only",
			email:      "g@t",
			validation: []string{ValidationBasic},
			shouldPass: true,
		},
		{
			name:          "local dev address - with extended validation",
			email:         "g@t",
			validation:    []string{ValidationBasic, ValidationExtended},
			shouldPass:    false,
			expectedError: "domain must contain at least one dot",
		},
		{
			name:       "localhost address - basic validation only",
			email:      "user@localhost",
			validation: []string{ValidationBasic},
			shouldPass: true,
		},
		{
			name:          "localhost address - with extended validation",
			email:         "user@localhost",
			validation:    []string{ValidationBasic, ValidationExtended},
			shouldPass:    false,
			expectedError: "domain must contain at least one dot",
		},
		{
			name:       "internal server address - basic validation only",
			email:      "admin@dev",
			validation: []string{ValidationBasic},
			shouldPass: true,
		},
		{
			name:          "internal server address - with extended validation",
			email:         "admin@dev",
			validation:    []string{ValidationBasic, ValidationExtended},
			shouldPass:    false,
			expectedError: "domain must contain at least one dot",
		},

		// Extended validation tests
		{
			name:       "valid ccTLD domain",
			email:      "test@example.co.uk",
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:       "valid multi-part domain",
			email:      "user@mail.example.com.au",
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:       "valid subdomain",
			email:      "admin@mail-server.example.org",
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:          "consecutive dots",
			email:         "test..user@example.com",
			validation:    []string{ValidationBasic, ValidationExtended},
			shouldPass:    false,
			expectedError: "invalid email format",
		},
		{
			name:          "email starting with dot",
			email:         ".test@example.com",
			validation:    []string{ValidationBasic, ValidationExtended},
			shouldPass:    false,
			expectedError: "invalid email format",
		},
		{
			name:          "email ending with dot",
			email:         "test@example.com.",
			validation:    []string{ValidationBasic, ValidationExtended},
			shouldPass:    false,
			expectedError: "invalid email format",
		},
		{
			name:          "invalid domain format",
			email:         "test@-example.com",
			validation:    []string{ValidationBasic, ValidationExtended},
			shouldPass:    false,
			expectedError: "invalid domain format",
		},
		{
			name:          "domain ending with hyphen",
			email:         "test@example-.com",
			validation:    []string{ValidationBasic, ValidationExtended},
			shouldPass:    false,
			expectedError: "invalid domain format",
		},
		{
			name:          "local part starting with dot",
			email:         ".test@example.com",
			validation:    []string{ValidationBasic, ValidationExtended},
			shouldPass:    false,
			expectedError: "invalid email format",
		},
		{
			name:          "local part ending with dot",
			email:         "test.@example.com",
			validation:    []string{ValidationBasic, ValidationExtended},
			shouldPass:    false,
			expectedError: "invalid email format",
		},

		// Length validation tests
		{
			name:          "email too long",
			email:         "very-long-local-part-that-exceeds-the-maximum-allowed-length-for-email-addresses-according-to-rfc-5321-specifications@very-long-domain-name-that-also-exceeds-the-maximum-allowed-length-for-domain-names-according-to-rfc-specifications.com",
			validation:    []string{ValidationBasic},
			shouldPass:    false,
			expectedError: "local part too long",
		},

		// Specific domain tests requested
		{
			name:       "domain with hyphen and ccTLD",
			email:      "user@some-domain.co.uk",
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:       "short ccTLD domain",
			email:      "contact@mo.cc",
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:          "single character TLD (should fail extended)",
			email:         "test@domain.t",
			validation:    []string{ValidationBasic, ValidationExtended},
			shouldPass:    false,
			expectedError: "invalid domain format",
		},
		{
			name:       "single character TLD (passes basic)",
			email:      "test@domain.t",
			validation: []string{ValidationBasic},
			shouldPass: true,
		},

		// Additional ccTLD tests
		{
			name:       "UK domain",
			email:      "support@company.co.uk",
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:       "Australian domain",
			email:      "info@business.com.au",
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:       "German domain",
			email:      "kontakt@firma.de",
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:       "Japanese domain",
			email:      "contact@company.co.jp",
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:       "Indian domain",
			email:      "info@company.co.in",
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:       "Brazilian domain",
			email:      "contato@empresa.com.br",
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:       "French domain",
			email:      "contact@societe.fr",
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:       "Canadian domain",
			email:      "info@company.ca",
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Server: config.ServerConfig{
					EmailValidation: tt.validation,
				},
			}

			validator := NewEmailValidator(cfg)
			result, err := validator.ParseEmailAddress(tt.email)

			if tt.shouldPass {
				if err != nil {
					t.Errorf("Expected email '%s' to pass validation but got error: %v", tt.email, err)
				}
				if result == nil {
					t.Errorf("Expected non-nil result for valid email '%s'", tt.email)
				} else {
					// Verify the parsed components are reasonable
					if result.Full == "" {
						t.Errorf("Expected non-empty Full field for email '%s'", tt.email)
					}
					if result.Local == "" {
						t.Errorf("Expected non-empty Local field for email '%s'", tt.email)
					}
					if result.Domain == "" {
						t.Errorf("Expected non-empty Domain field for email '%s'", tt.email)
					}
				}
			} else {
				if err == nil {
					t.Errorf("Expected email '%s' to fail validation but it passed", tt.email)
				}
				if tt.expectedError != "" && !containsSubstring(err.Error(), tt.expectedError) {
					t.Errorf("Expected error containing '%s' but got: %v", tt.expectedError, err)
				}
			}
		})
	}
}

func TestMailFromCommandParsing(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		validation  []string
		shouldPass  bool
		expectedErr string
	}{
		{
			name:       "valid MAIL FROM with FROM: prefix",
			args:       []string{"FROM:<test@example.com>"},
			validation: []string{ValidationBasic},
			shouldPass: true,
		},
		{
			name:       "valid MAIL FROM without brackets",
			args:       []string{"FROM:", "test@example.com"},
			validation: []string{ValidationBasic},
			shouldPass: true,
		},
		{
			name:       "valid MAIL FROM with spaces",
			args:       []string{"FROM:", "<test@example.com>"},
			validation: []string{ValidationBasic},
			shouldPass: true,
		},
		{
			name:       "valid MAIL FROM with ccTLD",
			args:       []string{"FROM:<sender@some-domain.co.uk>"},
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:       "valid MAIL FROM with short ccTLD",
			args:       []string{"FROM:<user@mo.cc>"},
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:       "local dev MAIL FROM - basic validation",
			args:       []string{"FROM:<dev@local>"},
			validation: []string{ValidationBasic},
			shouldPass: true,
		},
		{
			name:       "local dev MAIL FROM - minimal address",
			args:       []string{"FROM:<g@t>"},
			validation: []string{ValidationBasic},
			shouldPass: true,
		},
		{
			name:        "empty args",
			args:        []string{},
			validation:  []string{ValidationBasic},
			shouldPass:  false,
			expectedErr: "MAIL FROM requires an email address",
		},
		{
			name:        "empty email after FROM:",
			args:        []string{"FROM:"},
			validation:  []string{ValidationBasic},
			shouldPass:  false,
			expectedErr: "MAIL FROM requires an email address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Server: config.ServerConfig{
					EmailValidation: tt.validation,
				},
			}

			validator := NewEmailValidator(cfg)
			result, err := validator.ParseMailFromCommand(tt.args)

			if tt.shouldPass {
				if err != nil {
					t.Errorf("Expected MAIL FROM command to pass but got error: %v", err)
				}
				if result == nil {
					t.Errorf("Expected non-nil result for valid MAIL FROM command")
				}
			} else {
				if err == nil {
					t.Errorf("Expected MAIL FROM command to fail but it passed")
				}
				if tt.expectedErr != "" && !containsSubstring(err.Error(), tt.expectedErr) {
					t.Errorf("Expected error containing '%s' but got: %v", tt.expectedErr, err)
				}
			}
		})
	}
}

func TestRcptToCommandParsing(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		validation  []string
		shouldPass  bool
		expectedErr string
	}{
		{
			name:       "valid RCPT TO with TO: prefix",
			args:       []string{"TO:<recipient@example.com>"},
			validation: []string{ValidationBasic},
			shouldPass: true,
		},
		{
			name:       "valid RCPT TO without brackets",
			args:       []string{"TO:", "recipient@example.com"},
			validation: []string{ValidationBasic},
			shouldPass: true,
		},
		{
			name:       "valid RCPT TO with ccTLD",
			args:       []string{"TO:<user@company.co.uk>"},
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:       "valid RCPT TO with hyphenated domain",
			args:       []string{"TO:<recipient@some-domain.co.uk>"},
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:       "valid RCPT TO with short ccTLD",
			args:       []string{"TO:<contact@mo.cc>"},
			validation: []string{ValidationBasic, ValidationExtended},
			shouldPass: true,
		},
		{
			name:       "local dev RCPT TO - basic validation",
			args:       []string{"TO:<user@localhost>"},
			validation: []string{ValidationBasic},
			shouldPass: true,
		},
		{
			name:       "local dev RCPT TO - minimal address",
			args:       []string{"TO:<g@t>"},
			validation: []string{ValidationBasic},
			shouldPass: true,
		},
		{
			name:        "empty args",
			args:        []string{},
			validation:  []string{ValidationBasic},
			shouldPass:  false,
			expectedErr: "RCPT TO requires an email address",
		},
		{
			name:        "empty email after TO:",
			args:        []string{"TO:"},
			validation:  []string{ValidationBasic},
			shouldPass:  false,
			expectedErr: "RCPT TO requires an email address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Server: config.ServerConfig{
					EmailValidation: tt.validation,
				},
			}

			validator := NewEmailValidator(cfg)
			result, err := validator.ParseRcptToCommand(tt.args)

			if tt.shouldPass {
				if err != nil {
					t.Errorf("Expected RCPT TO command to pass but got error: %v", err)
				}
				if result == nil {
					t.Errorf("Expected non-nil result for valid RCPT TO command")
				}
			} else {
				if err == nil {
					t.Errorf("Expected RCPT TO command to fail but it passed")
				}
				if tt.expectedErr != "" && !containsSubstring(err.Error(), tt.expectedErr) {
					t.Errorf("Expected error containing '%s' but got: %v", tt.expectedErr, err)
				}
			}
		})
	}
}

// Helper function to check if a string contains a substring
func containsSubstring(str, substr string) bool {
	return strings.Contains(str, substr)
}
