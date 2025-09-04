package delivery

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/types"
)

// testSetup represents common test fixtures and utilities
type testSetup struct {
	tempDir         string
	testMessagePath string
	testContent     string
	msg             *types.Message
}

// newTestSetup creates a new test setup with common fixtures
func newTestSetup(t *testing.T, messageID string) *testSetup {
	t.Helper()

	tempDir := t.TempDir()
	testContent := "Subject: Test Message\r\nFrom: test@example.com\r\n\r\nTest message content"
	testMessagePath := filepath.Join(tempDir, "test_message.eml")

	if err := os.WriteFile(testMessagePath, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to create test message: %v", err)
	}

	msg := &types.Message{
		ID:   messageID,
		From: "test@example.com",
	}

	return &testSetup{
		tempDir:         tempDir,
		testMessagePath: testMessagePath,
		testContent:     testContent,
		msg:             msg,
	}
}

// setupVirtualDelivery prepares virtual delivery testing environment
func (ts *testSetup) setupVirtualDelivery(t *testing.T) string {
	t.Helper()
	return filepath.Join(ts.tempDir, "virtual")
}

// verifyMaildirStructure checks that Maildir directories were created
func verifyMaildirStructure(t *testing.T, maildirBase string) {
	t.Helper()

	for _, dir := range []string{"new", "cur", "tmp"} {
		if _, err := os.Stat(filepath.Join(maildirBase, dir)); err != nil {
			t.Errorf("Maildir directory %s not created: %v", dir, err)
		}
	}
}

// verifyDeliveredMessage checks message was delivered with correct content and filename
func verifyDeliveredMessage(t *testing.T, newDir, expectedContent, expectedMessageID string) {
	t.Helper()

	files, err := os.ReadDir(newDir)
	if err != nil {
		t.Fatalf("Failed to read new/ directory: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("Expected 1 file in new/, got %d", len(files))
	}

	// Verify content
	content, err := os.ReadFile(filepath.Join(newDir, files[0].Name()))
	if err != nil {
		t.Fatalf("Failed to read delivered message: %v", err)
	}
	if string(content) != expectedContent {
		t.Errorf("Content mismatch:\nwant: %q\ngot:  %q", expectedContent, string(content))
	}

	// Verify filename format
	if err := validateMaildirFilename(files[0].Name(), expectedMessageID); err != nil {
		t.Errorf("Invalid filename: %v", err)
	}
}

// validateMaildirFilename validates format: timestamp.pid.messageID.golubsmtpd
func validateMaildirFilename(filename, expectedMessageID string) error {
	parts := strings.Split(filename, ".")
	if len(parts) != 4 {
		return fmt.Errorf("expected 4 parts, got %d in %q", len(parts), filename)
	}

	// Check timestamp format (20060102T150405Z)
	timestamp := parts[0]
	if _, err := time.Parse("20060102T150405Z", timestamp); err != nil {
		return fmt.Errorf("invalid timestamp %q: %v", timestamp, err)
	}

	// Check PID
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return fmt.Errorf("invalid PID %q: %v", parts[1], err)
	}

	// Check message ID
	if parts[2] != expectedMessageID {
		return fmt.Errorf("message ID mismatch: want %q, got %q", expectedMessageID, parts[2])
	}

	// Check identifier
	if parts[3] != "golubsmtpd" {
		return fmt.Errorf("expected identifier 'golubsmtpd', got %q", parts[3])
	}

	return nil
}
