package smtp

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

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
	if len(aliases) != 1 || aliases[0] != expectedEmail {
		t.Errorf("Expected [%s], got %v", expectedEmail, aliases)
	}

	// Test multiple recipients alias
	aliases = validator.ResolveLocalAlias("webmaster")
	if len(aliases) != 2 {
		t.Errorf("Expected 2 recipients, got %d: %v", len(aliases), aliases)
	}
	for _, alias := range aliases {
		if alias != expectedEmail {
			t.Errorf("Expected all aliases to be %s, got %v", expectedEmail, aliases)
		}
	}

	// Test non-existent alias
	aliases = validator.ResolveLocalAlias("nonexistent")
	if len(aliases) != 0 {
		t.Errorf("Expected no aliases for nonexistent, got %v", aliases)
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