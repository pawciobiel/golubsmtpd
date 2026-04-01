package smtp

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/delivery"
)

// mockAuthWithSenders returns fixed allowed senders per username
type mockAuthWithSenders struct {
	senders map[string][]string
}

func (m *mockAuthWithSenders) Authenticate(_ context.Context, username, _ string) *auth.AuthResult {
	return &auth.AuthResult{Success: false, Username: username}
}

func (m *mockAuthWithSenders) ValidateUser(_ context.Context, _ string) bool { return false }
func (m *mockAuthWithSenders) Name() string                                   { return "mock" }
func (m *mockAuthWithSenders) Close() error                                   { return nil }
func (m *mockAuthWithSenders) GetAllowedSenders(username string) []string {
	return m.senders[username]
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func isValidationError(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve)
}

// --- RelayValidator ---

func TestRelayValidator_ValidateSender(t *testing.T) {
	cfg := config.DefaultConfig()
	v := NewRelayValidator(cfg)
	ctx := ValidationContext{}

	if err := v.ValidateSender("", ctx); err != nil {
		t.Errorf("null sender should be accepted (bounce/DSN): %v", err)
	}
	if err := v.ValidateSender("sender@external.com", ctx); err != nil {
		t.Errorf("any MTA sender should be accepted: %v", err)
	}
}

func TestRelayValidator_ValidateRecipient_RelayDisabled(t *testing.T) {
	cfg := config.DefaultConfig() // Relay.Enabled = false
	v := NewRelayValidator(cfg)

	err := v.ValidateRecipient("user@relaydomain.com", ValidationContext{Authenticated: false})
	if err == nil {
		t.Error("expected rejection when relay disabled, got nil")
	}
	if !isValidationError(err) {
		t.Errorf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestRelayValidator_ValidateRecipient_RelayEnabled_Unauthenticated(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Relay.Enabled = true
	v := NewRelayValidator(cfg)

	if err := v.ValidateRecipient("user@relaydomain.com", ValidationContext{Authenticated: false}); err != nil {
		t.Errorf("unauthenticated relay should be accepted when enabled: %v", err)
	}
}

func TestRelayValidator_ValidateRecipient_RelayEnabled_Authenticated(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Relay.Enabled = true
	v := NewRelayValidator(cfg)

	err := v.ValidateRecipient("user@relaydomain.com", ValidationContext{Authenticated: true, Username: "alice"})
	if err == nil {
		t.Error("expected rejection for authenticated session on relay queue, got nil")
	}
	if !isValidationError(err) {
		t.Errorf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestRelayValidator_IsAuthenticated(t *testing.T) {
	v := NewRelayValidator(config.DefaultConfig())
	if v.IsAuthenticated() {
		t.Error("IsAuthenticated() should be false")
	}
	if v.GetUsername() != "" {
		t.Errorf("GetUsername() should be empty, got %q", v.GetUsername())
	}
}

// --- SubmissionValidator ---

func TestSubmissionValidator_ValidateSender_NotAuthenticated(t *testing.T) {
	v := NewSubmissionValidator(&mockAuthWithSenders{}, config.DefaultConfig())

	err := v.ValidateSender("alice@example.com", ValidationContext{Authenticated: false})
	if err == nil {
		t.Error("expected rejection when not authenticated, got nil")
	}
	if !isValidationError(err) {
		t.Errorf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestSubmissionValidator_ValidateSender_NullSender(t *testing.T) {
	v := NewSubmissionValidator(&mockAuthWithSenders{}, config.DefaultConfig())

	err := v.ValidateSender("", ValidationContext{Authenticated: true, Username: "alice"})
	if err == nil {
		t.Error("expected rejection for null sender on submission port, got nil")
	}
	if !isValidationError(err) {
		t.Errorf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestSubmissionValidator_ValidateSender_AllowedSender(t *testing.T) {
	mockAuth := &mockAuthWithSenders{
		senders: map[string][]string{
			"alice": {"alice@example.com", "alice@alias.example.com"},
		},
	}
	v := NewSubmissionValidator(mockAuth, config.DefaultConfig())
	ctx := ValidationContext{Authenticated: true, Username: "alice"}

	if err := v.ValidateSender("alice@example.com", ctx); err != nil {
		t.Errorf("primary address should be allowed: %v", err)
	}
	if err := v.ValidateSender("Alice@Example.COM", ctx); err != nil {
		t.Errorf("case-insensitive match should be allowed: %v", err)
	}
	if err := v.ValidateSender("alice@alias.example.com", ctx); err != nil {
		t.Errorf("alias address should be allowed: %v", err)
	}
}

func TestSubmissionValidator_ValidateSender_DisallowedSender(t *testing.T) {
	mockAuth := &mockAuthWithSenders{
		senders: map[string][]string{
			"alice": {"alice@example.com"},
		},
	}
	v := NewSubmissionValidator(mockAuth, config.DefaultConfig())
	ctx := ValidationContext{Authenticated: true, Username: "alice"}

	err := v.ValidateSender("bob@example.com", ctx)
	if err == nil {
		t.Error("expected rejection for sender not in allowed list, got nil")
	}
	if !isValidationError(err) {
		t.Errorf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestSubmissionValidator_ValidateRecipient_ExternalRejected(t *testing.T) {
	v := NewSubmissionValidator(&mockAuthWithSenders{}, config.DefaultConfig())
	ctx := ValidationContext{Authenticated: true, Username: "alice", RecipientType: delivery.RecipientExternal}

	err := v.ValidateRecipient("bob@external.com", ctx)
	if err == nil {
		t.Error("expected rejection for external recipient on submission port, got nil")
	}
	if !isValidationError(err) {
		t.Errorf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestSubmissionValidator_ValidateRecipient_LocalVirtualAllowed(t *testing.T) {
	v := NewSubmissionValidator(&mockAuthWithSenders{}, config.DefaultConfig())

	for _, recipientType := range []delivery.RecipientType{delivery.RecipientLocal, delivery.RecipientVirtual, delivery.RecipientRelay} {
		ctx := ValidationContext{Authenticated: true, Username: "alice", RecipientType: recipientType}
		if err := v.ValidateRecipient("user@local.com", ctx); err != nil {
			t.Errorf("recipient type %s should be allowed, got: %v", recipientType, err)
		}
	}
}

// --- SocketValidator ---

func TestSocketValidator_ValidateSender_TrustedUser(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.TrustedUsers = []string{"root"}
	cfg.Server.LocalDomains = []string{"localhost"}

	creds := &SocketCredentials{UID: os.Getuid()}
	currentUser, err := getUsernameFromUID(creds.UID)
	if err != nil {
		t.Skipf("cannot resolve current UID: %v", err)
	}

	// Make current user trusted
	cfg.Server.TrustedUsers = []string{currentUser}
	v := NewSocketValidator(creds, cfg, newTestLogger())

	// Trusted user can send as anyone including null sender
	if err := v.ValidateSender("", ValidationContext{}); err != nil {
		t.Errorf("trusted user: null sender should be allowed: %v", err)
	}
	if err := v.ValidateSender("anyone@anywhere.com", ValidationContext{}); err != nil {
		t.Errorf("trusted user: any sender should be allowed: %v", err)
	}
}

func TestSocketValidator_ValidateSender_RegularUser(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.TrustedUsers = []string{"root"}
	cfg.Server.LocalDomains = []string{"localhost"}

	creds := &SocketCredentials{UID: os.Getuid()}
	currentUser, err := getUsernameFromUID(creds.UID)
	if err != nil {
		t.Skipf("cannot resolve current UID: %v", err)
	}

	v := NewSocketValidator(creds, cfg, newTestLogger())

	// Own address allowed
	ownAddr := currentUser + "@localhost"
	if err := v.ValidateSender(ownAddr, ValidationContext{}); err != nil {
		t.Errorf("own address should be allowed: %v", err)
	}

	// Null sender rejected for non-trusted user
	err = v.ValidateSender("", ValidationContext{})
	if err == nil {
		t.Error("null sender should be rejected for non-trusted user, got nil")
	}
	if !isValidationError(err) {
		t.Errorf("expected ValidationError, got %T: %v", err, err)
	}

	// Someone else's address rejected
	err = v.ValidateSender("other@localhost", ValidationContext{})
	if err == nil {
		t.Error("other user address should be rejected, got nil")
	}
	if !isValidationError(err) {
		t.Errorf("expected ValidationError, got %T: %v", err, err)
	}
}

func TestSocketValidator_ValidateRecipient(t *testing.T) {
	cfg := config.DefaultConfig()
	creds := &SocketCredentials{UID: os.Getuid()}
	v := NewSocketValidator(creds, cfg, newTestLogger())

	// Socket validator has no recipient restrictions
	for _, rt := range []delivery.RecipientType{delivery.RecipientLocal, delivery.RecipientVirtual, delivery.RecipientRelay, delivery.RecipientExternal} {
		ctx := ValidationContext{RecipientType: rt}
		if err := v.ValidateRecipient("user@example.com", ctx); err != nil {
			t.Errorf("socket validator should accept all recipient types, got error for %s: %v", rt, err)
		}
	}
}

func TestSocketValidator_IsAuthenticated(t *testing.T) {
	cfg := config.DefaultConfig()
	creds := &SocketCredentials{UID: os.Getuid()}
	v := NewSocketValidator(creds, cfg, newTestLogger())

	if !v.IsAuthenticated() {
		t.Error("IsAuthenticated() should be true for socket connections")
	}
}
