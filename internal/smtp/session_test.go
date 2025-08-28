package smtp

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
)

func TestSMTPMailFlow(t *testing.T) {
	// Setup test configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			Hostname:        "test.example.com",
			MaxRecipients:   10,
			MaxMessageSize:  1024,
			EmailValidation: []string{ValidationBasic},
		},
	}

	// Create a mock authenticator
	mockAuth, err := auth.NewMemoryAuthenticatorFromConfig(
		context.Background(),
		map[string]interface{}{
			"users": []interface{}{
				map[string]interface{}{"username": "testuser", "password": "testpass"},
			},
		},
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
	)
	if err != nil {
		t.Fatalf("Failed to create mock authenticator: %v", err)
	}

	tests := []struct {
		name     string
		commands []string
		expected []string
	}{
		{
			name: "basic mail flow",
			commands: []string{
				"EHLO client.example.com",
				"MAIL FROM:<sender@example.com>",
				"RCPT TO:<recipient@example.com>",
				"DATA",
				"Subject: Test Message",
				"",
				"This is a test message.",
				".",
				"QUIT",
			},
			expected: []string{
				"250-test.example.com Hello client.example.com",
				"250 Sender accepted",
				"250 Recipient accepted",
				"354 Start mail input",
				"250 Message accepted for delivery",
				"221",
			},
		},
		{
			name: "multiple recipients",
			commands: []string{
				"EHLO client.example.com",
				"MAIL FROM:<sender@example.com>",
				"RCPT TO:<recipient1@example.com>",
				"RCPT TO:<recipient2@example.com>",
				"DATA",
				"Subject: Test Message",
				"",
				"This is a test message to multiple recipients.",
				".",
				"QUIT",
			},
			expected: []string{
				"250-test.example.com Hello client.example.com",
				"250 Sender accepted",
				"250 Recipient accepted",
				"250 Recipient accepted",
				"354 Start mail input",
				"250 Message accepted for delivery",
				"221",
			},
		},
		{
			name: "reject DATA without RCPT TO",
			commands: []string{
				"EHLO client.example.com",
				"MAIL FROM:<sender@example.com>",
				"DATA",
				"QUIT",
			},
			expected: []string{
				"250-test.example.com Hello client.example.com",
				"250 Sender accepted",
				"503 RCPT TO required before DATA",
				"221",
			},
		},
		{
			name: "reject RCPT TO without MAIL FROM",
			commands: []string{
				"EHLO client.example.com",
				"RCPT TO:<recipient@example.com>",
				"QUIT",
			},
			expected: []string{
				"250-test.example.com Hello client.example.com",
				"503 MAIL FROM required before RCPT TO",
				"221",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create pipe for testing
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			// Start session in goroutine
			session := NewSession(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)), serverConn, "127.0.0.1", mockAuth)


			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			go func() {
				session.Handle(ctx)
			}()

			// Read greeting
			scanner := bufio.NewScanner(clientConn)
			scanner.Scan()
			greeting := scanner.Text()
			if !strings.HasPrefix(greeting, "220") {
				t.Errorf("Expected greeting to start with 220, got: %s", greeting)
			}

			// Send commands and check responses
			writer := bufio.NewWriter(clientConn)
			expectedIdx := 0

			for _, cmd := range tt.commands {
				// Send command
				writer.WriteString(cmd + "\r\n")
				writer.Flush()

				// Skip data content lines (they don't get responses)
				if cmd == "DATA" || cmd == "." ||
					(cmd != "EHLO" && cmd != "MAIL FROM:<sender@example.com>" &&
						cmd != "RCPT TO:<recipient@example.com>" &&
						cmd != "RCPT TO:<recipient1@example.com>" &&
						cmd != "RCPT TO:<recipient2@example.com>" &&
						cmd != "QUIT" && !strings.HasPrefix(cmd, "DATA")) {
					continue
				}

				// Read response
				scanner.Scan()
				response := scanner.Text()

				if expectedIdx < len(tt.expected) {
					expected := tt.expected[expectedIdx]
					if !strings.HasPrefix(response, expected) {
						t.Errorf("Command %q: expected response starting with %q, got %q", cmd, expected, response)
					}
					expectedIdx++
				}
			}
		})
	}
}

func TestSMTPDotStuffing(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			Hostname:        "test.example.com",
			MaxRecipients:   10,
			MaxMessageSize:  1024,
			EmailValidation: []string{ValidationBasic},
		},
	}

	mockAuth, err := auth.NewMemoryAuthenticatorFromConfig(
		context.Background(),
		map[string]interface{}{
			"users": []interface{}{
				map[string]interface{}{"username": "testuser", "password": "testpass"},
			},
		},
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
	)
	if err != nil {
		t.Fatalf("Failed to create mock authenticator: %v", err)
	}

	// Create pipe for testing
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	session := NewSession(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil)), serverConn, "127.0.0.1", mockAuth)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		session.Handle(ctx)
	}()

	writer := bufio.NewWriter(clientConn)
	scanner := bufio.NewScanner(clientConn)

	// Read greeting
	scanner.Scan()

	// Setup mail transaction
	commands := []string{
		"EHLO client.example.com",
		"MAIL FROM:<sender@example.com>",
		"RCPT TO:<recipient@example.com>",
		"DATA",
	}

	for _, cmd := range commands {
		writer.WriteString(cmd + "\r\n")
		writer.Flush()
		scanner.Scan() // Read response
	}

	// Send message with dot-stuffing test
	messageLines := []string{
		"Subject: Dot Stuffing Test",
		"",
		"This line starts with a single dot:",
		".",
		"This line starts with double dots:",
		"..",
		"This is a normal line.",
		".",
	}

	for _, line := range messageLines {
		writer.WriteString(line + "\r\n")
		writer.Flush()
	}

	// Read final response
	scanner.Scan()
	response := scanner.Text()
	if !strings.HasPrefix(response, "250") {
		t.Errorf("Expected 250 response for message acceptance, got: %s", response)
	}
}
