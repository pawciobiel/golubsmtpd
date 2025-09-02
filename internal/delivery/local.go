package delivery

import (
	"context"
	"log/slog"
	"os/user"
	"path/filepath"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
)

// GetLocalMaildirPath returns the Maildir path for a local system user
func GetLocalMaildirPath(email string) string {
	username := auth.ExtractUsername(email)
	return filepath.Join("/home", username, "Maildir", "new")
}

// DeliverToLocal handles delivery to local system users with semaphore-limited goroutines
// Recipients are delivered to ~/Maildir/new/ in their home directories
// Note: All recipients have already been validated by authentication system during RCPT TO
func DeliverToLocal(ctx context.Context, messagePath string, recipients map[string]struct{}, config config.LocalDeliveryConfig) DeliveryResult {
	maxWorkers := GetMaxWorkers(config.MaxWorkers, len(recipients))

	return DeliverWithWorkers(ctx, recipients, maxWorkers, RecipientLocal,
		func(ctx context.Context, recipient string) bool {
			return DeliverToLocalUser(ctx, messagePath, recipient)
		})
}

// DeliverToLocalUser handles delivery to a single local user
// Note: recipient is already validated by authentication system during RCPT TO
func DeliverToLocalUser(ctx context.Context, messagePath, recipient string) bool {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return false
	default:
	}

	// Get Maildir path for this local user
	maildirNew := GetLocalMaildirPath(recipient)

	// Extract username for logging and validation
	username := auth.ExtractUsername(recipient)

	// Verify user exists (should succeed since recipient was validated during RCPT TO)
	_, err := user.Lookup(username)
	if err != nil {
		slog.Error("Local user lookup failed for validated recipient", "recipient", recipient, "username", username, "error", err)
		return false
	}

	// For now, just log the delivery attempt (placeholder implementation)
	slog.Info("Local delivery",
		"recipient", recipient,
		"username", username,
		"maildir", maildirNew,
		"message_path", messagePath)

	// TODO: Implement actual Maildir delivery by streaming from messagePath
	// - Copy/stream file from messagePath to maildirNew/unique_filename
	// - Ensure atomic operation (temp file + rename)
	// - Handle disk space and permission errors

	// For now, mark as successful since this is a placeholder
	return true
}
