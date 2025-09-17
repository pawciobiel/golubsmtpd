package aliases

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/logging"
)

func TestMain(m *testing.M) {
	logging.InitTestLogging()
	code := m.Run()
	os.Exit(code)
}

func TestNewLocalAliasesMaps(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			LocalAliasesFilePath: "/etc/aliases",
		},
	}
	aliasesMaps := NewLocalAliasesMaps(cfg)

	if aliasesMaps == nil {
		t.Fatal("NewLocalAliasesMaps returned nil")
	}

	if aliasesMaps.config != cfg {
		t.Error("Config not set correctly")
	}

	if aliasesMaps.aliases == nil {
		t.Error("Aliases map not initialized")
	}
}

func TestLoadAliasesMaps_EmptyPath(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			LocalAliasesFilePath: "",
		},
	}
	aliasesMaps := NewLocalAliasesMaps(cfg)
	ctx := context.Background()

	err := aliasesMaps.LoadAliasesMaps(ctx)
	if err != nil {
		t.Errorf("LoadAliasesMaps with empty path should succeed, got error: %v", err)
	}

	// Should have no aliases
	aliases := aliasesMaps.ResolveAlias("test")
	if len(aliases) != 0 {
		t.Errorf("Expected no aliases, got %v", aliases)
	}
}

func TestLoadAliasesMaps_MissingFile(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			LocalAliasesFilePath: "/nonexistent/aliases",
		},
	}
	aliasesMaps := NewLocalAliasesMaps(cfg)
	ctx := context.Background()

	err := aliasesMaps.LoadAliasesMaps(ctx)
	if err == nil {
		t.Error("LoadAliasesMaps with missing file should return error")
	}
}

func TestLoadAliasesMaps_ValidFile(t *testing.T) {
	// Create temporary aliases file
	tmpDir := t.TempDir()
	aliasesFile := filepath.Join(tmpDir, "aliases")

	// Use the current user as a valid system user for testing
	currentUser := getCurrentUser(t)

	aliasesContent := fmt.Sprintf(`# Test aliases file
postmaster: %s
webmaster: %s,%s
abuse: %s
# Empty line and comments should be ignored

mailer-daemon: %s
`, currentUser, currentUser, currentUser, currentUser, currentUser)

	err := os.WriteFile(aliasesFile, []byte(aliasesContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test aliases file: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			LocalAliasesFilePath: aliasesFile,
		},
	}
	aliasesMaps := NewLocalAliasesMaps(cfg)
	ctx := context.Background()

	err = aliasesMaps.LoadAliasesMaps(ctx)
	if err != nil {
		t.Fatalf("LoadAliasesMaps failed: %v", err)
	}

	// Test single recipient alias - expect @localhost to be appended
	expectedSingle := currentUser + "@localhost"
	aliases := aliasesMaps.ResolveAlias("postmaster")
	if len(aliases) != 1 || aliases[0] != expectedSingle {
		t.Errorf("Expected [%s], got %v", expectedSingle, aliases)
	}

	// Test multiple recipients alias
	aliases = aliasesMaps.ResolveAlias("webmaster")
	if len(aliases) != 2 {
		t.Errorf("Expected 2 recipients, got %d: %v", len(aliases), aliases)
	}
	// All should be the same user with @localhost
	for _, alias := range aliases {
		if alias != expectedSingle {
			t.Errorf("Expected all aliases to be %s, got %v", expectedSingle, aliases)
		}
	}

	// Test non-existent alias
	aliases = aliasesMaps.ResolveAlias("nonexistent")
	if len(aliases) != 0 {
		t.Errorf("Expected no aliases for nonexistent, got %v", aliases)
	}
}

// getCurrentUser returns current username for testing
func getCurrentUser(t *testing.T) string {
	t.Helper()
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("Cannot get current user for test: %v", err)
	}
	return currentUser.Username
}

func TestLoadAliasesMaps_InvalidFormat(t *testing.T) {
	// Create temporary aliases file with invalid format
	tmpDir := t.TempDir()
	aliasesFile := filepath.Join(tmpDir, "aliases")

	// Use current user for valid system user
	currentUser := getCurrentUser(t)

	aliasesContent := fmt.Sprintf(`postmaster: %s
invalid_line_without_colon
webmaster: %s
`, currentUser, currentUser)

	err := os.WriteFile(aliasesFile, []byte(aliasesContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test aliases file: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			LocalAliasesFilePath: aliasesFile,
		},
	}
	aliasesMaps := NewLocalAliasesMaps(cfg)
	ctx := context.Background()

	err = aliasesMaps.LoadAliasesMaps(ctx)
	if err != nil {
		t.Fatalf("LoadAliasesMaps should skip invalid lines, got error: %v", err)
	}

	// Valid aliases should still be loaded with @localhost appended
	expectedEmail := currentUser + "@localhost"
	aliases := aliasesMaps.ResolveAlias("postmaster")
	if len(aliases) != 1 || aliases[0] != expectedEmail {
		t.Errorf("Expected [%s], got %v", expectedEmail, aliases)
	}

	aliases = aliasesMaps.ResolveAlias("webmaster")
	if len(aliases) != 1 || aliases[0] != expectedEmail {
		t.Errorf("Expected [%s], got %v", expectedEmail, aliases)
	}
}

func TestLoadAliasesMaps_Timeout(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			LocalAliasesFilePath: "/etc/aliases", // Use system file that might be large
		},
	}
	aliasesMaps := NewLocalAliasesMaps(cfg)

	// Create a context with very short timeout to test timeout handling
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Give context time to expire
	time.Sleep(1 * time.Millisecond)

	// This should either succeed quickly or handle timeout gracefully
	err := aliasesMaps.LoadAliasesMaps(ctx)
	if err != nil && ctx.Err() != nil {
		// Timeout occurred, which is acceptable for this test
		t.Logf("Timeout occurred as expected: %v", err)
	}
}

func TestResolveAlias_NilMaps(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			LocalAliasesFilePath: "",
		},
	}
	aliasesMaps := NewLocalAliasesMaps(cfg)
	// Don't call LoadAliasesMaps

	aliases := aliasesMaps.ResolveAlias("test")
	if len(aliases) != 0 {
		t.Errorf("Expected no aliases from unloaded maps, got %v", aliases)
	}
}

func TestResolveAlias_CaseSensitive(t *testing.T) {
	// Create temporary aliases file
	tmpDir := t.TempDir()
	aliasesFile := filepath.Join(tmpDir, "aliases")

	// Use current user for valid system user
	currentUser := getCurrentUser(t)

	aliasesContent := fmt.Sprintf(`PostMaster: %s
webmaster: %s
`, currentUser, currentUser)

	err := os.WriteFile(aliasesFile, []byte(aliasesContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test aliases file: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			LocalAliasesFilePath: aliasesFile,
		},
	}
	aliasesMaps := NewLocalAliasesMaps(cfg)
	ctx := context.Background()

	err = aliasesMaps.LoadAliasesMaps(ctx)
	if err != nil {
		t.Fatalf("LoadAliasesMaps failed: %v", err)
	}

	expectedEmail := currentUser + "@localhost"

	// Test exact case match should work
	aliases := aliasesMaps.ResolveAlias("PostMaster")
	if len(aliases) != 1 || aliases[0] != expectedEmail {
		t.Errorf("Exact case lookup failed: expected [%s], got %v", expectedEmail, aliases)
	}

	aliases = aliasesMaps.ResolveAlias("webmaster")
	if len(aliases) != 1 || aliases[0] != expectedEmail {
		t.Errorf("Exact case lookup failed: expected [%s], got %v", expectedEmail, aliases)
	}

	// Test different cases should not match (case-sensitive)
	aliases = aliasesMaps.ResolveAlias("postmaster")
	if len(aliases) != 0 {
		t.Errorf("Case-sensitive lookup should fail for different case: expected [], got %v", aliases)
	}

	aliases = aliasesMaps.ResolveAlias("POSTMASTER")
	if len(aliases) != 0 {
		t.Errorf("Case-sensitive lookup should fail for different case: expected [], got %v", aliases)
	}
}