package smtp

import (
	"context"
	"log/slog"
	"net/textproto"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/queue"
)

// ConnectionType represents the type of connection
type ConnectionType string

const (
	ConnectionTypeTCP    ConnectionType = "tcp"
	ConnectionTypeSocket ConnectionType = "socket"
)

// ConnectionContext contains information about the connection
type ConnectionContext struct {
	Type        ConnectionType
	Port        int
	TLS         bool
	ClientIP    string
	Credentials *SocketCredentials
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
	logger *slog.Logger,
	textproto *textproto.Conn,
	authenticator auth.Authenticator,
	queue *queue.Queue,
) SMTPHandler {
	// Create appropriate validator based on connection type
	validator := createSenderValidator(connCtx, cfg, authenticator, logger)

	logger.Debug("Creating SMTP handler", "connection_type", connCtx.Type)

	switch connCtx.Type {
	case ConnectionTypeSocket:
		logger.Debug("Creating socket session")
		return NewSocketSession(connCtx.Credentials, cfg, logger, textproto, validator, authenticator, queue)
	case ConnectionTypeTCP:
		logger.Debug("Creating TCP session")
		return NewTCPSession(connCtx, cfg, logger, textproto, validator, authenticator, queue)
	default:
		logger.Error("Unknown connection type", "type", connCtx.Type)
		return NewTCPSession(connCtx, cfg, logger, textproto, validator, authenticator, queue)
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
		// Different validation based on port
		switch connCtx.Port {
		case 587: // Submission port - requires authentication
			return NewSubmissionSenderValidator(authenticator, cfg)
		case 25: // MTA port - relay rules apply
			return NewRelayValidator(cfg, logger)
		case 465: // SMTPS port - requires authentication
			return NewSubmissionSenderValidator(authenticator, cfg)
		default:
			logger.Warn("Unknown TCP port, using relay validator", "port", connCtx.Port)
			return NewRelayValidator(cfg, logger)
		}
	default:
		logger.Error("Unknown connection type for validator", "type", connCtx.Type)
		return NewRelayValidator(cfg, logger)
	}
}
