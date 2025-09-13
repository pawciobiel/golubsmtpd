package smtp

import (
	"fmt"
	"log/slog"
	"os/user"
	"strconv"
	"strings"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
)

// SocketSenderValidator validates senders for Unix socket connections
type SocketSenderValidator struct {
	credentials *SocketCredentials
	username    string
	config      *config.Config
	logger      *slog.Logger
}

// NewSocketSenderValidator creates a new socket sender validator
func NewSocketSenderValidator(creds *SocketCredentials, cfg *config.Config, logger *slog.Logger) *SocketSenderValidator {
	username, err := getUsernameFromUID(creds.UID)
	if err != nil {
		logger.Error("Failed to get username from UID", "uid", creds.UID, "error", err)
		username = fmt.Sprintf("uid-%d", creds.UID)
	}

	return &SocketSenderValidator{
		credentials: creds,
		username:    username,
		config:      cfg,
		logger:      logger,
	}
}

func (v *SocketSenderValidator) ValidateSender(sender string) error {
	// Empty sender (bounce messages) - only allow for trusted users
	if sender == "" {
		if v.isTrustedUser() {
			return nil
		}
		return fmt.Errorf("null sender not allowed for user %s", v.username)
	}

	// Trusted users can send as anyone (like Postfix)
	if v.isTrustedUser() {
		return nil
	}

	// Regular users can only send as themselves for local domains
	allowedSenders := v.getAllowedSenders()
	for _, allowed := range allowedSenders {
		if strings.EqualFold(sender, allowed) {
			return nil
		}
	}

	return fmt.Errorf("user %s not allowed to send as %s", v.username, sender)
}

func (v *SocketSenderValidator) IsAuthenticated() bool {
	return true // Socket connections are always "authenticated" via kernel
}

func (v *SocketSenderValidator) GetUsername() string {
	return v.username
}

func (v *SocketSenderValidator) isTrustedUser() bool {
	for _, trustedUser := range v.config.Server.TrustedUsers {
		if trustedUser == v.username {
			return true
		}
	}
	return false
}

func (v *SocketSenderValidator) getAllowedSenders() []string {
	// Allow user@localdomain for each local domain (like Postfix)
	allowed := make([]string, 0, len(v.config.Server.LocalDomains))
	for _, domain := range v.config.Server.LocalDomains {
		allowed = append(allowed, v.username+"@"+domain)
	}
	return allowed
}

// SubmissionSenderValidator validates senders for submission ports (587, 465)
type SubmissionSenderValidator struct {
	authenticator auth.Authenticator
	config        *config.Config
	authenticated bool
	username      string
}

// NewSubmissionSenderValidator creates a new submission sender validator
func NewSubmissionSenderValidator(authenticator auth.Authenticator, cfg *config.Config) *SubmissionSenderValidator {
	return &SubmissionSenderValidator{
		authenticator: authenticator,
		config:        cfg,
		authenticated: false,
	}
}

func (v *SubmissionSenderValidator) ValidateSender(sender string) error {
	// Submission ports require authentication
	if !v.authenticated {
		return fmt.Errorf("authentication required for sender validation")
	}

	// Empty sender not allowed on submission ports
	if sender == "" {
		return fmt.Errorf("null sender not allowed on submission port")
	}

	// For now, authenticated users can send as anyone
	// TODO: Add proper sender restrictions based on user permissions
	return nil
}

func (v *SubmissionSenderValidator) IsAuthenticated() bool {
	return v.authenticated
}

func (v *SubmissionSenderValidator) GetUsername() string {
	return v.username
}

// SetAuthenticated marks the user as authenticated
func (v *SubmissionSenderValidator) SetAuthenticated(username string) {
	v.authenticated = true
	v.username = username
}

// RelayValidator validates senders for relay port (25)
type RelayValidator struct {
	config *config.Config
	logger *slog.Logger
}

// NewRelayValidator creates a new relay validator
func NewRelayValidator(cfg *config.Config, logger *slog.Logger) *RelayValidator {
	return &RelayValidator{
		config: cfg,
		logger: logger,
	}
}

func (v *RelayValidator) ValidateSender(sender string) error {
	// On port 25, we're more permissive as this is for MTA-to-MTA communication
	// TODO: Add proper relay rules, SPF checking, etc.

	// Allow empty sender for bounce messages
	if sender == "" {
		return nil
	}

	// For now, allow any sender - proper relay rules will be added later
	return nil
}

func (v *RelayValidator) IsAuthenticated() bool {
	return false // Port 25 typically doesn't require authentication
}

func (v *RelayValidator) GetUsername() string {
	return "" // No user for unauthenticated connections
}

// getUsernameFromUID converts UID to username
func getUsernameFromUID(uid int) (string, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", err
	}
	return u.Username, nil
}
