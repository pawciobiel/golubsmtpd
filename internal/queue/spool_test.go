package queue

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/config"
)

func createSpoolTestConfig(t *testing.T) (*config.Config, string) {
	t.Helper()

	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "golubsmtpd-spool-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			SpoolDir:       tempDir,
			MaxMessageSize: 10 * 1024 * 1024, // 10MB
		},
	}

	// Initialize spool directories
	err = InitializeSpoolDirectories(tempDir)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to initialize spool directories: %v", err)
	}

	return cfg, tempDir
}

func createTestSpoolMessage() *Message {
	return &Message{
		ID:      GenerateID(),
		Created: time.Now().UTC(),
		From:    "test@example.com",
		LocalRecipients: map[string]struct{}{
			"user@localhost": {},
		},
	}
}

func TestStreamEmailContent_BasicMessage(t *testing.T) {
	cfg, tempDir := createSpoolTestConfig(t)
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	message := createTestSpoolMessage()

	// Simulate SMTP DATA content with proper termination
	smtpData := "Subject: Test Message\r\n\r\nHello World!\r\nThis is a test.\r\n.\r\n"
	reader := strings.NewReader(smtpData)

	// Stream the message
	totalSize, err := StreamEmailContent(ctx, cfg, message, reader)
	if err != nil {
		t.Fatalf("StreamEmailContent failed: %v", err)
	}

	// Verify file was created
	expectedFile := filepath.Join(tempDir, "incoming", message.Filename())
	if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
		t.Fatalf("Message file was not created: %s", expectedFile)
	}

	// Read and verify content
	content, err := os.ReadFile(expectedFile)
	if err != nil {
		t.Fatalf("Failed to read message file: %v", err)
	}

	expected := "Subject: Test Message\r\n\r\nHello World!\r\nThis is a test.\r\n"
	if string(content) != expected {
		t.Errorf("Message content mismatch.\nExpected: %q\nGot: %q", expected, string(content))
	}

	// Verify size matches
	if totalSize != int64(len(content)) {
		t.Errorf("Size mismatch. Expected: %d, Got: %d", len(content), totalSize)
	}

	// Verify proper CRLF termination
	if !strings.HasSuffix(string(content), "\r\n") {
		t.Error("Message does not end with CRLF")
	}
}

func TestStreamEmailContent_EmptyData(t *testing.T) {
	cfg, tempDir := createSpoolTestConfig(t)
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	message := createTestSpoolMessage()

	// Empty data with just terminator (valid SMTP)
	smtpData := "\r\n.\r\n"
	reader := strings.NewReader(smtpData)

	totalSize, err := StreamEmailContent(ctx, cfg, message, reader)
	if err != nil {
		t.Fatalf("StreamEmailContent failed for empty data: %v", err)
	}

	// Should create file with just CRLF
	expectedFile := filepath.Join(tempDir, "incoming", message.Filename())
	content, err := os.ReadFile(expectedFile)
	if err != nil {
		t.Fatalf("Failed to read message file: %v", err)
	}

	if string(content) != "\r\n" {
		t.Errorf("Expected empty message with CRLF, got: %q", string(content))
	}

	if totalSize != 2 {
		t.Errorf("Expected totalSize 2 for empty message, got: %d", totalSize)
	}
}

func TestStreamEmailContent_MultilineMessage(t *testing.T) {
	cfg, tempDir := createSpoolTestConfig(t)
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	message := createTestSpoolMessage()

	// Multi-line message
	smtpData := "From: sender@example.com\r\n" +
		"To: recipient@localhost\r\n" +
		"Subject: Multi-line Test\r\n" +
		"\r\n" +
		"Line 1\r\n" +
		"Line 2\r\n" +
		"Final line\r\n" +
		".\r\n"

	reader := strings.NewReader(smtpData)

	totalSize, err := StreamEmailContent(ctx, cfg, message, reader)
	if err != nil {
		t.Fatalf("StreamEmailContent failed: %v", err)
	}

	// Read and verify content
	expectedFile := filepath.Join(tempDir, "incoming", message.Filename())
	content, err := os.ReadFile(expectedFile)
	if err != nil {
		t.Fatalf("Failed to read message file: %v", err)
	}

	// Expected content should exclude the SMTP terminator but include our CRLF
	expected := "From: sender@example.com\r\n" +
		"To: recipient@localhost\r\n" +
		"Subject: Multi-line Test\r\n" +
		"\r\n" +
		"Line 1\r\n" +
		"Line 2\r\n" +
		"Final line\r\n"

	if string(content) != expected {
		t.Errorf("Message content mismatch.\nExpected: %q\nGot: %q", expected, string(content))
	}

	if totalSize != int64(len(content)) {
		t.Errorf("Size mismatch. Expected: %d, Got: %d", len(content), totalSize)
	}
}

func TestStreamEmailContent_MessageSizeLimit(t *testing.T) {
	cfg, tempDir := createSpoolTestConfig(t)
	defer os.RemoveAll(tempDir)

	// Set a small message size limit
	cfg.Server.MaxMessageSize = 50

	ctx := context.Background()
	message := createTestSpoolMessage()

	// Create a message that exceeds the limit
	longContent := strings.Repeat("A", 100)
	smtpData := "Subject: Big\r\n\r\n" + longContent + "\r\n.\r\n"
	reader := strings.NewReader(smtpData)

	_, err := StreamEmailContent(ctx, cfg, message, reader)
	if err == nil {
		t.Fatal("Expected message size limit error, got nil")
	}

	if !strings.Contains(err.Error(), "message size exceeds limit") {
		t.Errorf("Expected size limit error, got: %v", err)
	}
}

func TestInitializeSpoolDirectories(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "golubsmtpd-spool-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	err = InitializeSpoolDirectories(tempDir)
	if err != nil {
		t.Fatalf("InitializeSpoolDirectories failed: %v", err)
	}

	// Verify all required directories were created
	requiredDirs := GetRequiredSpoolDirectories()
	for _, state := range requiredDirs {
		dir := filepath.Join(tempDir, string(state))
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("Required directory not created: %s", dir)
		}

		// Verify permissions (0700)
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("Failed to stat directory %s: %v", dir, err)
			continue
		}

		if info.Mode().Perm() != 0700 {
			t.Errorf("Directory %s has wrong permissions. Expected: 0700, Got: %o", dir, info.Mode().Perm())
		}
	}
}
