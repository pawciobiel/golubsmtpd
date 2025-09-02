package delivery

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
)

// GetVirtualMaildirPath returns the Maildir path for a virtual domain user
func GetVirtualMaildirPath(email string, virtualRoot string) string {
	username, domain := auth.ExtractUsernameAndDomain(email)
	return filepath.Join(virtualRoot, domain, username, "Maildir", "new")
}

// DeliverToVirtual handles delivery to virtual domain users with semaphore-limited goroutines
// Recipients are delivered to /var/mail/virtual/domain.com/username/Maildir/new/
// Note: All recipients have already been validated by authentication system during RCPT TO
func DeliverToVirtual(ctx context.Context, messagePath string, recipients map[string]struct{}, config config.LocalDeliveryConfig, virtualRoot string) DeliveryResult {
	maxWorkers := GetMaxWorkers(config.MaxWorkers, len(recipients))

	return DeliverWithWorkers(ctx, recipients, maxWorkers, RecipientVirtual,
		func(ctx context.Context, recipient string) bool {
			return DeliverToVirtualUser(ctx, messagePath, recipient, virtualRoot)
		})
}

// DeliverToVirtualUser handles delivery to a single virtual user
// Note: recipient is already validated by authentication system during RCPT TO
func DeliverToVirtualUser(ctx context.Context, messagePath, recipient, virtualRoot string) bool {
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return false
	default:
	}

	// Get Maildir path for this virtual user
	maildirNew := GetVirtualMaildirPath(recipient, virtualRoot)

	// Extract username and domain for logging
	username, domain := auth.ExtractUsernameAndDomain(recipient)

	// For now, just log the delivery attempt (placeholder implementation)
	slog.Info("Virtual delivery",
		"recipient", recipient,
		"username", username,
		"domain", domain,
		"maildir", maildirNew,
		"message_path", messagePath)

	// TODO: Implement actual virtual Maildir delivery by streaming from messagePath
	// - Create directory structure if it doesn't exist (virtualRoot/domain.com/username/Maildir/{new,cur,tmp})
	// - Copy/stream file from messagePath to maildirNew/unique_filename
	// - Ensure atomic operation (temp file + rename)
	// - Handle disk space and permission errors
	// - Set appropriate ownership and permissions

	// For now, mark as successful since this is a placeholder
	return true
}
