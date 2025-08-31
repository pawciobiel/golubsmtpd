package auth

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/config"
)

func TestAuthChain_SinglePlugin(t *testing.T) {
	cfg := &config.AuthConfig{
		PluginChain: []string{"memory"},
		Plugins: map[string]map[string]interface{}{
			"memory": {
				"users": []interface{}{
					map[string]interface{}{"username": "user1", "password": "pass1"},
					map[string]interface{}{"username": "user2", "password": "pass2"},
				},
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	chain, err := NewAuthChainFromConfig(context.Background(), cfg, logger)
	if err != nil {
		t.Fatalf("Failed to create auth chain: %v", err)
	}
	defer chain.Close()

	// Test successful authentication
	result := chain.Authenticate(context.Background(), "user1", "pass1")
	if !result.Success {
		t.Error("Expected authentication to succeed")
	}
	if result.Username != "user1" {
		t.Errorf("Expected username 'user1', got '%s'", result.Username)
	}

	// Test failed authentication
	result = chain.Authenticate(context.Background(), "user1", "wrongpass")
	if result.Success {
		t.Error("Expected authentication to fail")
	}

	// Test user validation
	if !chain.ValidateUser(context.Background(), "user2") {
		t.Error("Expected user validation to succeed")
	}
	if chain.ValidateUser(context.Background(), "nonexistent") {
		t.Error("Expected user validation to fail")
	}

	// Test chain name
	expectedName := "chain[memory]"
	if chain.Name() != expectedName {
		t.Errorf("Expected chain name '%s', got '%s'", expectedName, chain.Name())
	}
}

func TestAuthChain_MultiplePlugins(t *testing.T) {
	// Create temporary file for file auth
	tmpFile, err := os.CreateTemp("", "auth_test_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Write test users to file
	if _, err := tmpFile.WriteString("fileuser1:filepass1\nfileuser2:filepass2\n"); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}

	cfg := &config.AuthConfig{
		PluginChain: []string{"memory", "file"},
		Plugins: map[string]map[string]interface{}{
			"memory": {
				"users": []interface{}{
					map[string]interface{}{"username": "memuser1", "password": "mempass1"},
				},
			},
			"file": {
				"users_file": tmpFile.Name(),
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	chain, err := NewAuthChainFromConfig(context.Background(), cfg, logger)
	if err != nil {
		t.Fatalf("Failed to create auth chain: %v", err)
	}
	defer chain.Close()

	// Test authentication from first plugin (memory)
	result := chain.Authenticate(context.Background(), "memuser1", "mempass1")
	if !result.Success {
		t.Error("Expected memory plugin authentication to succeed")
	}

	// Test authentication from second plugin (file)
	result = chain.Authenticate(context.Background(), "fileuser1", "filepass1")
	if !result.Success {
		t.Error("Expected file plugin authentication to succeed")
	}

	// Test user validation across plugins
	if !chain.ValidateUser(context.Background(), "memuser1") {
		t.Error("Expected memory user validation to succeed")
	}
	if !chain.ValidateUser(context.Background(), "fileuser2") {
		t.Error("Expected file user validation to succeed")
	}

	// Test chain name with multiple plugins
	expectedName := "chain[memory,file]"
	if chain.Name() != expectedName {
		t.Errorf("Expected chain name '%s', got '%s'", expectedName, chain.Name())
	}
}

func TestAuthChain_DuplicatePlugins(t *testing.T) {
	cfg := &config.AuthConfig{
		PluginChain: []string{"memory", "memory"}, // Duplicate!
		Plugins: map[string]map[string]interface{}{
			"memory": {
				"users": []interface{}{
					map[string]interface{}{"username": "user1", "password": "pass1"},
				},
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	_, err := NewAuthChainFromConfig(context.Background(), cfg, logger)
	if err == nil {
		t.Error("Expected error for duplicate plugins")
	}
	if err.Error() != "duplicate plugin 'memory' in chain" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestAuthChain_MissingPluginConfig(t *testing.T) {
	cfg := &config.AuthConfig{
		PluginChain: []string{"memory"},
		Plugins:     map[string]map[string]interface{}{}, // No plugin config
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	_, err := NewAuthChainFromConfig(context.Background(), cfg, logger)
	if err == nil {
		t.Error("Expected error for missing plugin config")
	}
}

func TestAuthChain_UnknownPlugin(t *testing.T) {
	cfg := &config.AuthConfig{
		PluginChain: []string{"unknown"},
		Plugins: map[string]map[string]interface{}{
			"unknown": {},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	_, err := NewAuthChainFromConfig(context.Background(), cfg, logger)
	if err == nil {
		t.Error("Expected error for unknown plugin")
	}
}

func TestAuthChain_EmptyChain(t *testing.T) {
	cfg := &config.AuthConfig{
		PluginChain: []string{}, // Empty chain
		Plugins:     map[string]map[string]interface{}{},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	_, err := NewAuthChainFromConfig(context.Background(), cfg, logger)
	if err == nil {
		t.Error("Expected error for empty plugin chain")
	}
}

func TestAuthChain_ContextCancellation(t *testing.T) {
	cfg := &config.AuthConfig{
		PluginChain: []string{"memory"},
		Plugins: map[string]map[string]interface{}{
			"memory": {
				"users": []interface{}{
					map[string]interface{}{"username": "user1", "password": "pass1"},
				},
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	chain, err := NewAuthChainFromConfig(context.Background(), cfg, logger)
	if err != nil {
		t.Fatalf("Failed to create auth chain: %v", err)
	}
	defer chain.Close()

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := chain.Authenticate(ctx, "user1", "pass1")
	if result.Success {
		t.Error("Expected authentication to fail with cancelled context")
	}
	if result.Error != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", result.Error)
	}

	// Test user validation with cancelled context
	if chain.ValidateUser(ctx, "user1") {
		t.Error("Expected user validation to fail with cancelled context")
	}
}

func TestAuthChain_Stats(t *testing.T) {
	cfg := &config.AuthConfig{
		PluginChain: []string{"memory"},
		Plugins: map[string]map[string]interface{}{
			"memory": {
				"users": []interface{}{
					map[string]interface{}{"username": "user1", "password": "pass1"},
				},
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	chain, err := NewAuthChainFromConfig(context.Background(), cfg, logger)
	if err != nil {
		t.Fatalf("Failed to create auth chain: %v", err)
	}
	defer chain.Close()

	// Initial stats should be zero
	attempts, successes := chain.GetStats()
	if attempts != 0 || successes != 0 {
		t.Errorf("Expected initial stats to be 0,0, got %d,%d", attempts, successes)
	}

	// Perform successful authentication
	chain.Authenticate(context.Background(), "user1", "pass1")
	attempts, successes = chain.GetStats()
	if attempts != 1 || successes != 1 {
		t.Errorf("Expected stats 1,1 after success, got %d,%d", attempts, successes)
	}

	// Perform failed authentication
	chain.Authenticate(context.Background(), "user1", "wrongpass")
	attempts, successes = chain.GetStats()
	if attempts != 2 || successes != 1 {
		t.Errorf("Expected stats 2,1 after failure, got %d,%d", attempts, successes)
	}
}

func TestAuthChain_PluginFailureDuringCreation(t *testing.T) {
	cfg := &config.AuthConfig{
		PluginChain: []string{"file"},
		Plugins: map[string]map[string]interface{}{
			"file": {
				"users_file": "/nonexistent/path/file.txt", // Invalid path
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	_, err := NewAuthChainFromConfig(context.Background(), cfg, logger)
	if err == nil {
		t.Error("Expected error for invalid file path")
	}
}

func TestAuthChain_WithTimeout(t *testing.T) {
	cfg := &config.AuthConfig{
		PluginChain: []string{"memory"},
		Plugins: map[string]map[string]interface{}{
			"memory": {
				"users": []interface{}{
					map[string]interface{}{"username": "user1", "password": "pass1"},
				},
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	chain, err := NewAuthChainFromConfig(context.Background(), cfg, logger)
	if err != nil {
		t.Fatalf("Failed to create auth chain: %v", err)
	}
	defer chain.Close()

	// Test with timeout context (should succeed quickly)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	result := chain.Authenticate(ctx, "user1", "pass1")
	if !result.Success {
		t.Error("Expected authentication to succeed within timeout")
	}
}
