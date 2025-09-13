package smtp

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/queue"
)

// TCPHeaderGenerator adds Received header and GolubSMTPd-Message-ID for TCP connections
type TCPHeaderGenerator struct{}

func (g *TCPHeaderGenerator) GenerateHeaders(msg *queue.Message, connCtx ConnectionContext) string {
	var headers strings.Builder

	// Add Received header for message tracing
	clientInfo := connCtx.ClientIP
	// TODO: Add client hostname from HELO/EHLO if available

	timestamp := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 UTC")
	headers.WriteString(fmt.Sprintf("Received: from %s by localhost; %s\r\n",
		clientInfo, timestamp))

	// Add our internal message ID for tracing
	headers.WriteString(fmt.Sprintf("GolubSMTPd-Message-ID: %s\r\n", msg.ID))

	return headers.String()
}

// TCPDataHandler handles DATA command for TCP connections
type TCPDataHandler struct{}

func (h *TCPDataHandler) HandleData(ctx context.Context, args []string, sess *Session) error {
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

	// Generate headers using the strategy
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

	sess.logger.Info("TCP message received and stored",
		"sender", sess.currentMessage.From,
		"total_recipients", sess.currentMessage.TotalRecipients(),
		"size", totalSize,
		"message_id", sess.currentMessage.ID,
		"client_ip", sess.clientIP)

	// Publish message to queue for processing
	if err := sess.queue.PublishMessage(ctx, sess.currentMessage); err != nil {
		sess.logger.Error("Error publishing message to queue", "error", err, "message_id", sess.currentMessage.ID)
		// Don't fail the SMTP transaction - message is already stored
	}

	// Reset session for next mail transaction
	sess.resetSession()

	return sess.writeResponse(Response(StatusOK, "Message accepted for delivery"))
}

// HandleAuth for TCP connections - use default session logic
func (h *TCPDataHandler) HandleAuth(ctx context.Context, args []string, sess *Session) error {
	// Delegate to default session AUTH handling
	return sess.handleAuth(ctx, args)
}

// HandleMail for TCP connections - use default session logic
func (h *TCPDataHandler) HandleMail(ctx context.Context, args []string, sess *Session) error {
	// Delegate to default session MAIL handling
	return sess.handleMail(ctx, args)
}
