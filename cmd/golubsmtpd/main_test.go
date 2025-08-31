package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/queue"
	"github.com/pawciobiel/golubsmtpd/internal/storage"
)

func TestInitializeSpoolDirectories(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &config.ServerConfig{
		SpoolDir: tempDir,
	}

	err := storage.InitializeSpoolDirectories(cfg.SpoolDir)
	if err != nil {
		t.Fatalf("InitializeSpoolDirectories failed: %v", err)
	}

	// Verify all required directories exist
	for _, state := range queue.GetRequiredSpoolDirectories() {
		dir := filepath.Join(tempDir, string(state))
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("Directory %s was not created", dir)
		}
	}
}

func TestInitializeSpoolDirectoriesPermissions(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.ServerConfig{SpoolDir: tempDir}

	err := storage.InitializeSpoolDirectories(cfg.SpoolDir)
	if err != nil {
		t.Fatalf("initializeSpoolDirectories failed: %v", err)
	}

	// Check each directory has secure permissions (0700 = rwx------)
	for _, state := range queue.GetRequiredSpoolDirectories() {
		dir := filepath.Join(tempDir, string(state))
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("Failed to stat directory %s: %v", dir, err)
		}

		expectedPerm := os.FileMode(0700)
		actualPerm := info.Mode().Perm()
		if actualPerm != expectedPerm {
			t.Errorf("Directory %s has permissions %o, expected %o (secure permissions required for email data)",
				dir, actualPerm, expectedPerm)
		}
	}
}

func TestInitializeSpoolDirectoriesWithCustomPath(t *testing.T) {
	tempDir := t.TempDir()
	customSpoolDir := filepath.Join(tempDir, "custom", "spool", "path")

	cfg := &config.ServerConfig{
		SpoolDir: customSpoolDir,
	}

	err := storage.InitializeSpoolDirectories(cfg.SpoolDir)
	if err != nil {
		t.Fatalf("initializeSpoolDirectories with custom path failed: %v", err)
	}

	// Verify directories were created at custom path with secure permissions
	for _, state := range queue.GetRequiredSpoolDirectories() {
		dir := filepath.Join(customSpoolDir, string(state))
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("Directory %s was not created at custom path", dir)
			continue
		}

		// Verify secure permissions on custom path too
		if info.Mode().Perm() != 0700 {
			t.Errorf("Custom path directory %s has insecure permissions %o", dir, info.Mode().Perm())
		}
	}
}

func TestInitializeSpoolDirectoriesIdempotent(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.ServerConfig{
		SpoolDir: tempDir,
	}

	// First call
	err := storage.InitializeSpoolDirectories(cfg.SpoolDir)
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	// Second call should not error (idempotent)
	err = storage.InitializeSpoolDirectories(cfg.SpoolDir)
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}

	// Directories should still exist with correct permissions
	for _, state := range queue.GetRequiredSpoolDirectories() {
		dir := filepath.Join(tempDir, string(state))
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("Directory %s missing after second call", dir)
			continue
		}

		if info.Mode().Perm() != 0700 {
			t.Errorf("Directory %s has wrong permissions after second call: %o", dir, info.Mode().Perm())
		}
	}
}

func TestInitializeSpoolDirectoriesInvalidPath(t *testing.T) {
	cfg := &config.ServerConfig{
		SpoolDir: "/dev/null/invalid",
	}

	err := storage.InitializeSpoolDirectories(cfg.SpoolDir)
	if err == nil {
		t.Fatal("Expected error for invalid path, got nil")
	}
}
