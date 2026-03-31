package smtp

import (
	"context"
	"crypto/tls"
	"net"
	"log/slog"
	"net/textproto"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/logging"
	"github.com/pawciobiel/golubsmtpd/internal/queue"
)

// ConnectionType represents the type of connection
type ConnectionType string

const (
	ConnectionTypeTCP    ConnectionType = "tcp"
	ConnectionTypeSocket ConnectionType = "socket"
)

// ListenerMode mirrors config.ListenerMode in the smtp package
type ListenerMode = config.ListenerMode

// ConnectionContext contains information about the connection
type ConnectionContext struct {
	Type        ConnectionType
	Port        int
	Mode        ListenerMode  // plain, starttls, tls
	TLS         bool          // true once TLS is active (implicit on 465, after STARTTLS on 587)
	ClientIP    string
	Credentials *SocketCredentials
	TLSConfig   *tls.Config   // non-nil when STARTTLS upgrade is possible
}

// SocketCredentials represents Unix socket peer credentials
type SocketCredentials struct {
	UID int // User ID
	GID int // Group ID
	PID int // Process ID
}

// SMTPHandler interface for handling SMTP sessions
type SMTPHandler interface {
	Handle(ctx context.Context) error
}

// Strategy interfaces for different session behaviors
type HeaderGenerator interface {
	GenerateHeaders(msg *queue.Message, connCtx ConnectionContext) string
}

type SenderValidator interface {
	ValidateSender(sender string) error
	IsAuthenticated() bool
	GetUsername() string
}

type DataHandler interface {
	HandleData(ctx context.Context, args []string, sess *Session) error
	HandleAuth(ctx context.Context, args []string, sess *Session) error
	HandleMail(ctx context.Context, args []string, sess *Session) error
}

// NewSMTPHandler creates appropriate SMTP handler based on connection context
func NewSMTPHandler(
	connCtx ConnectionContext,
	cfg *config.Config,
	rawConn net.Conn,
	textprotoConn *textproto.Conn,
	deps *Dependencies,
) SMTPHandler {
	logger := logging.GetLogger()

	validator := createSenderValidator(connCtx, cfg, deps.Authenticator, logger)

	logger.Debug("Creating SMTP handler", "connection_type", connCtx.Type)

	switch connCtx.Type {
	case ConnectionTypeSocket:
		logger.Debug("Creating socket session")
		return NewSocketSession(connCtx.Credentials, cfg, textprotoConn, validator, deps)
	case ConnectionTypeTCP:
		logger.Debug("Creating TCP session")
		return NewTCPSession(connCtx, cfg, rawConn, textprotoConn, validator, deps)
	default:
		logger.Error("Unknown connection type", "type", connCtx.Type)
		return NewTCPSession(connCtx, cfg, rawConn, textprotoConn, validator, deps)
	}
}

// createSenderValidator creates appropriate validator based on connection context
func createSenderValidator(
	connCtx ConnectionContext,
	cfg *config.Config,
	authenticator auth.Authenticator,
	logger *slog.Logger,
) SenderValidator {
	switch connCtx.Type {
	case ConnectionTypeSocket:
		return NewSocketSenderValidator(connCtx.Credentials, cfg, logger)
	case ConnectionTypeTCP:
		// Validator is selected by IANA-assigned port semantics:
		//   25  = MTA-to-MTA relay (permissive sender, RCPT TO enforces relay policy)
		//   587 = authenticated submission (STARTTLS + AUTH required)
		//   465 = authenticated submission (implicit TLS + AUTH required)
		//
		// TODO: replace port-based inference with an explicit ListenerRole field
		// (relay vs submission) in ListenerConfig so non-standard ports work correctly.
		// Requires config changes and validation updates.
		switch connCtx.Port {
		case 587, 465:
			return NewSubmissionSenderValidator(authenticator, cfg)
		default:
			return NewRelayValidator(cfg, logger)
		}
	default:
		logger.Error("Unknown connection type for validator", "type", connCtx.Type)
		return NewRelayValidator(cfg, logger)
	}
}
