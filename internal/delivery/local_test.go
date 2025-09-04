package delivery

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/types"
)

func TestDeliverToLocalUser(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Skip("Cannot get current user for local delivery test")
	}

	ts := newTestSetup(t, "test-local-delivery-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	recipient := currentUser.Username + "@localhost"

	// Count existing files before delivery
	maildirBase := filepath.Join("/home", currentUser.Username, "Maildir")
	newDir := filepath.Join(maildirBase, "new")

	var beforeCount int
	if files, err := os.ReadDir(newDir); err == nil {
		beforeCount = len(files)
	}

	err = DeliverToLocalUser(context.Background(), ts.msg, ts.testMessagePath, recipient)
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
	msg := &types.Message{ID: "test", From: "test@example.com"}

	err := DeliverToLocalUser(context.Background(), msg, "/tmp/test", "nonexistent@localhost")
	if err == nil {
		t.Fatal("Expected error for non-existent user")
	}
	if !strings.Contains(err.Error(), "local user lookup failed") {
		t.Errorf("Expected lookup error, got: %v", err)
	}
}

func TestDeliverToLocalUser_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	currentUser, err := user.Current()
	if err != nil {
		t.Skip("Cannot get current user")
	}

	msg := &types.Message{ID: "test", From: "test@example.com"}
	err = DeliverToLocalUser(ctx, msg, "/tmp/test", currentUser.Username+"@localhost")

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
