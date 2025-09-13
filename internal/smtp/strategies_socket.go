package smtp

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/queue"
)

// SocketHeaderGenerator adds all missing headers for socket connections
type SocketHeaderGenerator struct{}

func (g *SocketHeaderGenerator) GenerateHeaders(msg *queue.Message, connCtx ConnectionContext) string {
	var headers strings.Builder

	// Add Received header for socket connections
	timestamp := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 UTC")
	headers.WriteString(fmt.Sprintf("Received: from localhost (unix socket) by localhost; %s\r\n",
		timestamp))

	// Add missing basic headers for socket-delivered messages
	headers.WriteString(fmt.Sprintf("From: %s\r\n", msg.From))

	// Add To header(s) - combine all recipients
	var recipients []string
	for recipient := range msg.LocalRecipients {
		recipients = append(recipients, recipient)
	}
	for recipient := range msg.VirtualRecipients {
		recipients = append(recipients, recipient)
	}
	for recipient := range msg.RelayRecipients {
		recipients = append(recipients, recipient)
	}
	for recipient := range msg.ExternalRecipients {
		recipients = append(recipients, recipient)
	}

	if len(recipients) > 0 {
		headers.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(recipients, ", ")))
	}

	// Add Date header (using UTC)
	headers.WriteString(fmt.Sprintf("Date: %s\r\n", msg.Created.UTC().Format("Mon, 02 Jan 2006 15:04:05 UTC")))

	// Add our internal message ID for tracing
	headers.WriteString(fmt.Sprintf("GolubSMTPd-Message-ID: %s\r\n", msg.ID))

	// Add empty line to separate headers from body
	headers.WriteString("\r\n")

	return headers.String()
}

// SocketDataHandler handles DATA command for Unix socket connections
type SocketDataHandler struct{}

func (h *SocketDataHandler) HandleData(ctx context.Context, args []string, sess *Session) error {
	// Check session state - must have at least one recipient
	if sess.state != StateRcptTo {
		return sess.writeResponse(Response(StatusBadSequence, "RCPT TO required before DATA"))
	}

	if sess.currentMessage.TotalRecipients() == 0 {
		return sess.writeResponse(Response(StatusBadSequence, "No recipients specified"))
	}

	// Start data collection
	sess.state = StateData
	if err := sess.writeResponse(Response(StatusStartMailInput, "Start mail input; end with <CRLF>.<CRLF>")); err != nil {
		return err
	}

	// Generate headers using the strategy (includes all missing headers)
	headers := sess.headerGenerator.GenerateHeaders(sess.currentMessage, sess.connCtx)

	// Create a reader that combines headers and message data
	var messageReader io.Reader
	if headers != "" {
		headerReader := strings.NewReader(headers)
		messageReader = io.MultiReader(headerReader, sess.textproto.R)
	} else {
		messageReader = sess.textproto.R
	}

	// Stream message data directly to storage
	totalSize, err := queue.StreamEmailContent(ctx, sess.config, sess.currentMessage, messageReader)
	if err != nil {
		sess.logger.Error("Error storing message data", "error", err, "client_ip", sess.clientIP)
		return sess.writeResponse(Response(StatusLocalError, "Error storing message"))
	}

	// Update message size after successful storage
	sess.currentMessage.TotalSize = totalSize

	sess.logger.Info("Socket message received and stored",
		"sender", sess.currentMessage.From,
		"total_recipients", sess.currentMessage.TotalRecipients(),
		"size", totalSize,
		"message_id", sess.currentMessage.ID,
		"username", sess.senderValidator.GetUsername())

	// Publish message to queue for processing
	if err := sess.queue.PublishMessage(ctx, sess.currentMessage); err != nil {
		sess.logger.Error("Error publishing message to queue", "error", err, "message_id", sess.currentMessage.ID)
		// Don't fail the SMTP transaction - message is already stored
	}

	// Reset session for next mail transaction
	sess.resetSession()

	return sess.writeResponse(Response(StatusOK, "Message accepted for delivery"))
}

// HandleAuth for socket connections - authentication not needed
func (h *SocketDataHandler) HandleAuth(ctx context.Context, args []string, sess *Session) error {
	return sess.writeResponse(Response(StatusBadSequence, "Authentication not required for local connections"))
}

// HandleMail for socket connections - use socket-specific sender validation
func (h *SocketDataHandler) HandleMail(ctx context.Context, args []string, sess *Session) error {
	if sess.state != StateGreeted {
		return sess.writeResponse(Response(StatusBadSequence, "Bad sequence of commands"))
	}

	if len(args) == 0 {
		return sess.writeResponse(Response(StatusSyntaxError, "MAIL command requires FROM parameter"))
	}

	// Parse MAIL FROM using existing EmailValidator (RFC compliant)
	emailValidator := NewEmailValidator(sess.config)
	emailAddr, err := emailValidator.ParseMailFromCommand(args)
	if err != nil {
		return sess.writeResponse(Response(StatusSyntaxError, err.Error()))
	}

	sender := emailAddr.Full

	// Use socket validator for sender validation
	if err := sess.senderValidator.ValidateSender(sender); err != nil {
		sess.logger.Warn("Socket sender validation failed",
			"sender", sender,
			"username", sess.senderValidator.GetUsername(),
			"error", err)
		return sess.writeResponse(Response(StatusMailboxUnavailable, "Sender address not allowed"))
	}

	// Create new message using proper Message struct
	sess.currentMessage = &queue.Message{
		From:               sender,
		ClientIP:           "socket",
		LocalRecipients:    make(map[string]struct{}),
		VirtualRecipients:  make(map[string]struct{}),
		RelayRecipients:    make(map[string]struct{}),
		ExternalRecipients: make(map[string]struct{}),
		Created:            time.Now(),
	}
	// Generate ID for the message
	sess.currentMessage.ID = queue.GenerateID()

	sess.state = StateMailFrom
	return sess.writeResponse(Response(StatusOK, "OK"))
}
