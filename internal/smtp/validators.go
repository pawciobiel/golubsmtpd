package smtp

import (
	"fmt"
	"log/slog"
	"os/user"
	"strconv"
	"strings"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/delivery"
)

// ValidationError is returned by ValidateSender when a policy rejects the sender.
// Reason is a human-readable string safe to include in log output.
type ValidationError struct {
	Reason string
}

func (e *ValidationError) Error() string { return e.Reason }

// SocketValidator validates senders for Unix socket connections
type SocketValidator struct {
	credentials *SocketCredentials
	username    string
	config      *config.Config
	logger      *slog.Logger
}

// NewSocketValidator creates a new socket validator
func NewSocketValidator(creds *SocketCredentials, cfg *config.Config, logger *slog.Logger) *SocketValidator {
	username, err := getUsernameFromUID(creds.UID)
	if err != nil {
		logger.Error("Failed to get username from UID", "uid", creds.UID, "error", err)
		username = fmt.Sprintf("uid-%d", creds.UID)
	}

	return &SocketValidator{
		credentials: creds,
		username:    username,
		config:      cfg,
		logger:      logger,
	}
}

func (v *SocketValidator) ValidateSender(sender string, _ ValidationContext) error {
	if sender == "" {
		if v.isTrustedUser() {
			return nil
		}
		return &ValidationError{Reason: fmt.Sprintf("null sender not allowed for user %s", v.username)}
	}

	if v.isTrustedUser() {
		return nil
	}

	allowedSenders := v.getAllowedSenders()
	for _, allowed := range allowedSenders {
		if strings.EqualFold(sender, allowed) {
			return nil
		}
	}

	return &ValidationError{Reason: fmt.Sprintf("user %s not allowed to send as %s", v.username, sender)}
}

func (v *SocketValidator) ValidateRecipient(_ string, _ ValidationContext) error {
	return nil
}

func (v *SocketValidator) IsAuthenticated() bool {
	return true
}

func (v *SocketValidator) GetUsername() string {
	return v.username
}

func (v *SocketValidator) isTrustedUser() bool {
	for _, trustedUser := range v.config.Server.TrustedUsers {
		if trustedUser == v.username {
			return true
		}
	}
	return false
}

func (v *SocketValidator) getAllowedSenders() []string {
	allowed := make([]string, 0, len(v.config.Server.LocalDomains))
	for _, domain := range v.config.Server.LocalDomains {
		allowed = append(allowed, v.username+"@"+domain)
	}
	return allowed
}

// SubmissionValidator validates senders for submission ports (587, 465).
// Auth state is read from ValidationContext — no local state duplication.
type SubmissionValidator struct {
	authenticator auth.Authenticator
	config        *config.Config
}

// NewSubmissionValidator creates a new submission validator
func NewSubmissionValidator(authenticator auth.Authenticator, cfg *config.Config) *SubmissionValidator {
	return &SubmissionValidator{
		authenticator: authenticator,
		config:        cfg,
	}
}

func (v *SubmissionValidator) ValidateSender(sender string, ctx ValidationContext) error {
	if !ctx.Authenticated {
		return &ValidationError{Reason: "authentication required before MAIL FROM"}
	}

	if sender == "" {
		return &ValidationError{Reason: "null sender not allowed on submission port"}
	}

	allowed := v.authenticator.GetAllowedSenders(ctx.Username)
	for _, a := range allowed {
		if strings.EqualFold(a, sender) {
			return nil
		}
	}

	return &ValidationError{Reason: fmt.Sprintf("user %s not allowed to send as %s", ctx.Username, sender)}
}

func (v *SubmissionValidator) ValidateRecipient(_ string, ctx ValidationContext) error {
	if ctx.RecipientType == delivery.RecipientExternal {
		return &ValidationError{Reason: fmt.Sprintf("user %s may not send to external recipients", ctx.Username)}
	}
	return nil
}

func (v *SubmissionValidator) IsAuthenticated() bool {
	return false
}

func (v *SubmissionValidator) GetUsername() string {
	return ""
}

// RelayValidator accepts all senders; recipient policy is enforced in handleRcpt.
type RelayValidator struct {
	config *config.Config
}

func NewRelayValidator(cfg *config.Config) *RelayValidator {
	return &RelayValidator{config: cfg}
}

func (v *RelayValidator) ValidateSender(sender string, _ ValidationContext) error {
	// Accept null sender (RFC 5321 §4.5.5 — bounce/DSN messages use <>).
	// Accept any non-empty sender: cannot validate or restrict the envelope sender
	// for inbound MTA connections. TODO: optionally verify via SPF (phase 2).
	return nil
}

func (v *RelayValidator) ValidateRecipient(_ string, ctx ValidationContext) error {
	if !v.config.Relay.Enabled {
		return &ValidationError{Reason: "relay disabled in config"}
	}
	if ctx.Authenticated {
		return &ValidationError{Reason: "authenticated session may not use relay queue"}
	}
	return nil
}

func (v *RelayValidator) IsAuthenticated() bool {
	return false
}

func (v *RelayValidator) GetUsername() string {
	return ""
}

// getUsernameFromUID converts UID to username
func getUsernameFromUID(uid int) (string, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

