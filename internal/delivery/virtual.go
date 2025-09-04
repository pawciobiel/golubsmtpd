package delivery

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/types"
)

// GetVirtualMaildirPath returns the Maildir path for a virtual domain user
func GetVirtualMaildirPath(email string, virtualRoot string) string {
	username, domain := auth.ExtractUsernameAndDomain(email)
	return filepath.Join(virtualRoot, domain, username, "Maildir", "new")
}


// DeliverToVirtualUser handles delivery to a single virtual user
// Note: recipient is already validated by authentication system during RCPT TO
func DeliverToVirtualUser(ctx context.Context, msg *types.Message, messagePath, recipient, virtualRoot string) error {
	// Extract username and domain for path calculation
	username, domain := auth.ExtractUsernameAndDomain(recipient)

	// Calculate Maildir base path for virtual user
	maildirBase := filepath.Join(virtualRoot, domain, username, "Maildir")

	// Perform the actual delivery
	if err := deliverToMaildir(ctx, msg, messagePath, maildirBase, recipient); err != nil {
		return err
	}

	slog.Info("Virtual delivery successful",
		"recipient", recipient,
		"username", username,
		"domain", domain,
		"message_id", msg.ID)

	return nil
}
