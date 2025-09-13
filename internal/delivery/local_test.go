package delivery

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/types"
)

func TestDeliverToLocalUser(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Skip("Cannot get current user for local delivery test")
	}

	ts := newTestSetup(t, "test-local-delivery-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	recipient := currentUser.Username + "@localhost"

	// Use centralized path for local delivery testing
	testBasePath := filepath.Join(os.TempDir(), "golub-local-test")
	defer os.RemoveAll(testBasePath)

	testConfig := &config.LocalDeliveryConfig{
		BaseDirPath: testBasePath,
		MaxWorkers:  1,
	}

	// Count existing files before delivery
	maildirBase := filepath.Join(testBasePath, currentUser.Username, "Maildir")
	newDir := filepath.Join(maildirBase, "new")

	var beforeCount int
	if files, err := os.ReadDir(newDir); err == nil {
		beforeCount = len(files)
	}
	err = DeliverToLocalUser(context.Background(), ts.msg, ts.testMessagePath, recipient, testConfig)
	if err != nil {
		t.Fatalf("DeliverToLocalUser failed: %v", err)
	}

	// Verify Maildir structure was created
	verifyMaildirStructure(t, maildirBase)

	// Verify exactly one new file was added
	files, err := os.ReadDir(newDir)
	if err != nil {
		t.Fatalf("Failed to read new/ directory: %v", err)
	}

	afterCount := len(files)
	if afterCount != beforeCount+1 {
		t.Fatalf("Expected %d files after delivery, got %d", beforeCount+1, afterCount)
	}

	// Find and verify our delivered message by checking for our unique message ID
	var foundOurMessage bool
	for _, file := range files {
		if strings.Contains(file.Name(), ts.msg.ID) {
			foundOurMessage = true
			if err := validateMaildirFilename(file.Name(), ts.msg.ID); err != nil {
				t.Errorf("Invalid filename for our message: %v", err)
			}
			break
		}
	}

	if !foundOurMessage {
		t.Error("Could not find delivered message with expected message ID")
	}
}

func TestDeliverToLocalUser_NonExistentUser(t *testing.T) {
	// Create a test message file
	ts := newTestSetup(t, "test-nonexistent")

	msg := &types.Message{ID: "test", From: "test@example.com"}

	// Use a directory with restrictive permissions to trigger permission error
	restrictedDir := filepath.Join(os.TempDir(), "golub-restricted")
	os.MkdirAll(restrictedDir, 0o000) // No permissions
	defer os.RemoveAll(restrictedDir)

	testConfig := &config.LocalDeliveryConfig{
		BaseDirPath: restrictedDir,
		MaxWorkers:  1,
	}
	err := DeliverToLocalUser(context.Background(), msg, ts.testMessagePath, "nonexistent@localhost", testConfig)
	if err == nil {
		t.Fatal("Expected error for delivery to restricted directory")
	}
	// The error might be permission-related or Maildir creation-related
	if !strings.Contains(err.Error(), "permissions") && !strings.Contains(err.Error(), "failed to create") {
		t.Errorf("Expected permission or creation error, got: %v", err)
	}
}

func TestDeliverToLocalUser_CancelledContext(t *testing.T) {
	// Create a test message file
	ts := newTestSetup(t, "test-cancelled")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	currentUser, err := user.Current()
	if err != nil {
		t.Skip("Cannot get current user")
	}

	msg := &types.Message{ID: "test", From: "test@example.com"}
	testConfig := &config.LocalDeliveryConfig{
		BaseDirPath: filepath.Join(os.TempDir(), "golub-cancel-test"),
		MaxWorkers:  1,
	}
	err = DeliverToLocalUser(ctx, msg, ts.testMessagePath, currentUser.Username+"@localhost", testConfig)

	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}
}

func TestGenerateUniqueFilename(t *testing.T) {
	messageID := "test-msg-456"

	filename := generateUniqueFilename(messageID)

	// Test 1: Verify single filename is properly formatted
	if err := validateMaildirFilename(filename, messageID); err != nil {
		t.Errorf("Generated invalid filename: %v", err)
	}
}

func TestGenerateUniqueFilename_DifferentMessages(t *testing.T) {
	messageID1 := "msg-001"
	messageID2 := "msg-002"

	filename1 := generateUniqueFilename(messageID1)
	filename2 := generateUniqueFilename(messageID2)

	// Test 2: Different message IDs should generate different filenames
	if filename1 == filename2 {
		t.Errorf("Different message IDs should generate different filenames:\nmsg1: %s\nmsg2: %s", filename1, filename2)
	}

	// Both should be valid
	if err := validateMaildirFilename(filename1, messageID1); err != nil {
		t.Errorf("Invalid filename for msg1: %v", err)
	}
	if err := validateMaildirFilename(filename2, messageID2); err != nil {
		t.Errorf("Invalid filename for msg2: %v", err)
	}
}

func TestIsPermissionError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "EACCES permission error via PathError",
			err:      &os.PathError{Op: "mkdir", Path: "/tmp/test", Err: syscall.EACCES},
			expected: true,
		},
		{
			name:     "EPERM permission error via PathError",
			err:      &os.PathError{Op: "create", Path: "/tmp/test", Err: syscall.EPERM},
			expected: true,
		},
		{
			name:     "direct EACCES error",
			err:      syscall.EACCES,
			expected: true,
		},
		{
			name:     "direct EPERM error",
			err:      syscall.EPERM,
			expected: true,
		},
		{
			name:     "ENOENT error (not permission)",
			err:      &os.PathError{Op: "open", Path: "/tmp/test", Err: syscall.ENOENT},
			expected: false,
		},
		{
			name:     "other generic error",
			err:      os.ErrNotExist,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPermissionError(tt.err)
			if result != tt.expected {
				t.Errorf("isPermissionError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}
