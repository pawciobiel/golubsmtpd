package smtp

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pawciobiel/golubsmtpd/internal/aliases"
	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/logging"
)

func TestMain(m *testing.M) {
	logging.InitTestLogging()
	code := m.Run()
	os.Exit(code)
}

// mockAuthenticator is a simple mock for testing
type mockAuthenticator struct{}

func (m *mockAuthenticator) Authenticate(ctx context.Context, username, password string) *auth.AuthResult {
	return &auth.AuthResult{Success: false, Username: username}
}

func (m *mockAuthenticator) ValidateUser(ctx context.Context, email string) bool {
	return false
}

func (m *mockAuthenticator) Name() string {
	return "mock"
}

func (m *mockAuthenticator) GetAllowedSenders(username string) []string {
	return nil
}

func (m *mockAuthenticator) Close() error {
	return nil
}

func TestRcptValidator_ResolveLocalAlias(t *testing.T) {
	// Get current user for valid system user
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("Cannot get current user for test: %v", err)
	}

	// Create temporary aliases file
	tmpDir := t.TempDir()
	aliasesFile := filepath.Join(tmpDir, "aliases")

	aliasesContent := fmt.Sprintf(`postmaster: %s
webmaster: %s,%s
`, currentUser.Username, currentUser.Username, currentUser.Username)

	err = os.WriteFile(aliasesFile, []byte(aliasesContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test aliases file: %v", err)
	}

	// Setup config
	cfg := &config.Config{
		Server: config.ServerConfig{
			LocalAliasesFilePath: aliasesFile,
		},
		Cache: config.CacheConfig{
			SystemUsers: config.UserCacheConfig{
				Capacity: 100,
				TTL:      300 * time.Second,
			},
			VirtualUsers: config.UserCacheConfig{
				Capacity: 100,
				TTL:      300 * time.Second,
			},
		},
	}

	// Create and load aliases
	localAliasesMaps := aliases.NewLocalAliasesMaps(cfg)
	ctx := context.Background()

	err = localAliasesMaps.LoadAliasesMaps(ctx)
	if err != nil {
		t.Fatalf("LoadAliasesMaps failed: %v", err)
	}

	// Create mock authenticator
	mockAuth := &mockAuthenticator{}

	// Create RcptValidator
	validator := NewRcptValidator(cfg, mockAuth, localAliasesMaps)

	// Test alias resolution
	aliases := validator.ResolveLocalAlias("postmaster")
	expectedEmail := currentUser.Username + "@localhost"
	expected := []string{expectedEmail}
	if diff := cmp.Diff(expected, aliases); diff != "" {
		t.Errorf("Single alias resolution mismatch (-want +got):\n%s", diff)
	}

	// Test multiple recipients alias
	aliases = validator.ResolveLocalAlias("webmaster")
	expected = []string{expectedEmail, expectedEmail}
	if diff := cmp.Diff(expected, aliases); diff != "" {
		t.Errorf("Multiple alias resolution mismatch (-want +got):\n%s", diff)
	}

	// Test non-existent alias
	aliases = validator.ResolveLocalAlias("nonexistent")
	expected = nil
	if diff := cmp.Diff(expected, aliases); diff != "" {
		t.Errorf("Non-existent alias should return empty (-want +got):\n%s", diff)
	}
}

func TestRcptValidator_ResolveLocalAlias_NoMaps(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			LocalAliasesFilePath: "",
		},
		Cache: config.CacheConfig{
			SystemUsers: config.UserCacheConfig{
				Capacity: 100,
				TTL:      300 * time.Second,
			},
			VirtualUsers: config.UserCacheConfig{
				Capacity: 100,
				TTL:      300 * time.Second,
			},
		},
	}

	// Create mock authenticator
	mockAuth := &mockAuthenticator{}

	// Create RcptValidator with nil aliases maps
	validator := NewRcptValidator(cfg, mockAuth, nil)

	// Test alias resolution should return nil
	aliases := validator.ResolveLocalAlias("postmaster")
	if aliases != nil {
		t.Errorf("Expected nil for no aliases maps, got %v", aliases)
	}
}