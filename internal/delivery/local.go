package delivery

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/types"
)

// GetLocalMaildirPath returns the Maildir path for a local system user
var GetLocalMaildirPath = func(email string) string {
	username := auth.ExtractUsername(email)
	return filepath.Join("/home", username, "Maildir", "new")
}

// DeliverToLocalUser handles delivery to a single local user
// Note: recipient is already validated by RCPT TO system user validation
func DeliverToLocalUser(ctx context.Context, msg *types.Message, messagePath, recipient string) error {
	// Extract username for path calculation
	username := auth.ExtractUsername(recipient)

	// Calculate Maildir base path for local user
	// Note: No user.Lookup() needed - already validated during RCPT TO
	maildirBase := filepath.Join("/home", username, "Maildir")

	// Perform the actual delivery
	if err := deliverToMaildir(ctx, msg, messagePath, maildirBase, recipient); err != nil {
		return err
	}

	slog.Info("Local delivery successful",
		"recipient", recipient,
		"username", username,
		"message_id", msg.ID)

	return nil
}

// createMaildirStructure creates the standard Maildir directory structure (new, cur, tmp)
func createMaildirStructure(maildirPath string) error {
	dirs := []string{
		filepath.Join(maildirPath, "new"),
		filepath.Join(maildirPath, "cur"),
		filepath.Join(maildirPath, "tmp"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// streamMessageToFile copies a message from source to destination with streaming
func streamMessageToFile(ctx context.Context, sourcePath, destPath string) error {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Open source file
	srcFile, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", sourcePath, err)
	}
	defer srcFile.Close()

	// Create destination file
	dstFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", destPath, err)
	}
	defer dstFile.Close()

	// Stream copy
	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("failed to copy message content: %w", err)
	}

	// Sync to ensure data is written to disk
	if err = dstFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync file to disk: %w", err)
	}

	return nil
}

// deliverToMaildir handles the common Maildir delivery logic
func deliverToMaildir(ctx context.Context, msg *types.Message, messagePath, maildirBase, recipient string) error {
	// Check for context cancellation
	if err := ctx.Err(); err != nil {
		return err
	}

	// Create Maildir directory structure if it doesn't exist
	if err := createMaildirStructure(maildirBase); err != nil {
		return fmt.Errorf("failed to create Maildir structure for %s: %w", recipient, err)
	}

	// Generate unique filename
	uniqueFilename := generateUniqueFilename(msg.ID)

	// Write to new/ directory
	maildirNew := filepath.Join(maildirBase, "new")
	finalFile := filepath.Join(maildirNew, uniqueFilename)

	// Stream message from spool to Maildir
	if err := streamMessageToFile(ctx, messagePath, finalFile); err != nil {
		return fmt.Errorf("failed to deliver message %s to %s: %w", msg.ID, recipient, err)
	}

	return nil
}

// generateUniqueFilename creates a unique filename for Maildir delivery
func generateUniqueFilename(messageID string) string {
	timestamp := time.Now().Format("20060102T150405Z")
	pid := os.Getpid()
	return fmt.Sprintf("%s.%d.%s.%s", timestamp, pid, messageID, "golubsmtpd")
}
