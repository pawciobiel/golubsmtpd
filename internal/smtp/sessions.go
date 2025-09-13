package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"net/textproto"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/queue"
)

// tcpSessionHandler handles the standard TCP SMTP session flow
func tcpSessionHandler(ctx context.Context, sess *Session) error {
	defer sess.textproto.Close()

	sess.logger.Info("Starting SMTP session", "client_ip", sess.clientIP)

	// Send greeting
	if err := sess.sendGreeting(); err != nil {
		return fmt.Errorf("failed to send greeting: %w", err)
	}

	// Process commands
	for sess.state != StateClosed {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := sess.textproto.ReadLine()
		if err != nil {
			sess.logger.Debug("Error reading command", "error", err)
			return err
		}

		sess.logger.Debug("Received command", "command", line, "client_ip", sess.clientIP)

		if err := sess.processCommand(ctx, line); err != nil {
			sess.logger.Error("Error processing command", "error", err, "command", line)
			return err
		}
	}

	return nil
}

// NewTCPSession creates a new TCP session with appropriate strategies
func NewTCPSession(
	connCtx ConnectionContext,
	cfg *config.Config,
	logger *slog.Logger,
	textproto *textproto.Conn,
	validator SenderValidator,
	authenticator auth.Authenticator,
	queue *queue.Queue,
) SMTPHandler {
	// Create TCP-specific strategies
	headerGenerator := &TCPHeaderGenerator{}
	dataHandler := &TCPDataHandler{}

	// Create session with strategies and handler
	return NewSession(cfg, logger, textproto, connCtx.ClientIP, authenticator, queue,
		headerGenerator, validator, dataHandler, tcpSessionHandler, connCtx)
}

// socketSessionHandler handles Unix domain socket SMTP session flow
func socketSessionHandler(ctx context.Context, sess *Session) error {
	defer sess.textproto.Close()

	sess.logger.Debug("Starting socket SMTP session", "username", sess.username)

	// Socket sessions skip greeting and go straight to SMTP commands
	sess.state = StateGreeted

	// Process commands using embedded session logic
	for sess.state != StateClosed {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := sess.textproto.ReadLine()
		if err != nil {
			sess.logger.Debug("Error reading command", "error", err)
			return err
		}

		sess.logger.Debug("Socket SMTP command", "command", line, "username", sess.username)

		// Use embedded session's processCommand
		if err := sess.processCommand(ctx, line); err != nil {
			sess.logger.Error("Error processing socket command", "error", err, "command", line)
			return err
		}
	}

	return nil
}

// NewSocketSession creates a new socket session with appropriate strategies
func NewSocketSession(
	credentials *SocketCredentials,
	cfg *config.Config,
	logger *slog.Logger,
	textproto *textproto.Conn,
	validator SenderValidator,
	authenticator auth.Authenticator,
	queue *queue.Queue,
) SMTPHandler {
	// Get username from UID
	username, err := getUsernameFromUID(credentials.UID)
	if err != nil {
		logger.Error("Failed to get username from UID", "uid", credentials.UID, "error", err)
		username = fmt.Sprintf("uid-%d", credentials.UID)
	}

	// Create socket-specific strategies
	headerGenerator := &SocketHeaderGenerator{}
	dataHandler := &SocketDataHandler{}

	// Create connection context for socket
	connCtx := ConnectionContext{
		Type:        ConnectionTypeSocket,
		ClientIP:    "socket",
		Credentials: credentials,
	}

	// Create session with strategies and handler
	session := NewSession(cfg, logger, textproto, "socket", authenticator, queue,
		headerGenerator, validator, dataHandler, socketSessionHandler, connCtx)

	// Mark as already authenticated since socket connections are kernel-verified
	session.authenticated = true
	session.username = username

	return session
}
