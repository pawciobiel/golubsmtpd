package smtp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/textproto"
	"strings"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/delivery"
	"github.com/pawciobiel/golubsmtpd/internal/queue"
)

// SessionState represents the current state of an SMTP session
type SessionState int

const (
	StateConnected SessionState = iota
	StateGreeted
	StateAuthenticated
	StateMailFrom
	StateRcptTo
	StateData
	StateClosed
)

// SessionHandlerFunc defines the function signature for session flow handlers
type SessionHandlerFunc func(ctx context.Context, sess *Session) error

// Session represents an SMTP session with a client
type Session struct {
	config         *config.Config
	logger         *slog.Logger
	textproto      *textproto.Conn
	clientIP       string
	hostname       string
	authenticator  auth.Authenticator
	emailValidator *EmailValidator
	rcptValidator  *RcptValidator
	queue          *queue.Queue

	// Strategy interfaces for different behaviors
	headerGenerator HeaderGenerator
	senderValidator SenderValidator
	dataHandler     DataHandler
	sessionHandler  SessionHandlerFunc
	connCtx         ConnectionContext

	// Session state
	state               SessionState
	clientHelloHostname string
	authenticated       bool
	username            string

	// Message being built during session
	currentMessage *queue.Message

	// Security checks
	reverseDNS   string
	dnsblResults []string
}

// NewSession creates a new SMTP session with strategies
func NewSession(
	cfg *config.Config,
	logger *slog.Logger,
	textprotoConn *textproto.Conn,
	clientIP string,
	authenticator auth.Authenticator,
	q *queue.Queue,
	headerGenerator HeaderGenerator,
	senderValidator SenderValidator,
	dataHandler DataHandler,
	sessionHandler SessionHandlerFunc,
	connCtx ConnectionContext,
) *Session {
	return &Session{
		config:          cfg,
		logger:          logger,
		textproto:       textprotoConn,
		clientIP:        clientIP,
		hostname:        cfg.Server.Hostname,
		authenticator:   authenticator,
		emailValidator:  NewEmailValidator(cfg),
		rcptValidator:   NewRcptValidator(cfg, authenticator, logger),
		queue:           q,
		headerGenerator: headerGenerator,
		senderValidator: senderValidator,
		dataHandler:     dataHandler,
		sessionHandler:  sessionHandler,
		connCtx:         connCtx,
		state:           StateConnected,
	}
}

// containsDomain checks if a domain exists in a slice (case-insensitive)
func containsDomain(domains []string, domain string) bool {
	for _, d := range domains {
		if strings.EqualFold(d, domain) {
			return true
		}
	}
	return false
}

// classifyDomain determines the domain type for recipient classification
func (sess *Session) classifyDomain(domain string) delivery.RecipientType {
	if containsDomain(sess.config.Server.LocalDomains, domain) {
		return delivery.RecipientLocal
	}
	if containsDomain(sess.config.Server.VirtualDomains, domain) {
		return delivery.RecipientVirtual
	}
	if containsDomain(sess.config.Server.RelayDomains, domain) {
		return delivery.RecipientRelay
	}
	return delivery.RecipientExternal
}

// Handle processes the SMTP session
func (sess *Session) Handle(ctx context.Context) error {
	// Delegate to session-specific handler function
	return sess.sessionHandler(ctx, sess)
}

func (sess *Session) sendGreeting() error {
	sess.state = StateGreeted
	greeting := ResponseWithHostname(StatusReady, sess.hostname, "ESMTP Service ready")
	return sess.writeResponse(greeting)
}

func (sess *Session) processCommand(ctx context.Context, line string) error {
	// Parse command and arguments
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return sess.writeResponse(Response(StatusSyntaxError, ""))
	}

	command := strings.ToUpper(parts[0])
	args := parts[1:]

	// I don't think it make sense to check this on DATA command... perhaps do it in other commands but not here... ->refactor...
	//// Check for end of message
	//if line == "." {
	//	break
	//}
	//// Handle SMTP dot-stuffing (lines starting with .. become .)
	//if strings.HasPrefix(line, "..") {
	//	line = line[1:]
	//}

	switch command {
	case "HELO":
		return sess.handleHelo(ctx, args)
	case "EHLO":
		return sess.handleEhlo(ctx, args)
	case "AUTH":
		return sess.dataHandler.HandleAuth(ctx, args, sess)
	case "MAIL":
		return sess.dataHandler.HandleMail(ctx, args, sess)
	case "RCPT":
		return sess.handleRcpt(ctx, args)
	case "DATA":
		return sess.dataHandler.HandleData(ctx, args, sess)
	case "RSET":
		return sess.handleRset(ctx, args)
	case "NOOP":
		return sess.handleNoop(ctx, args)
	case "QUIT":
		return sess.handleQuit(ctx, args)
	default:
		return sess.writeResponse(Response(StatusCommandNotImpl, "Command not implemented"))
	}
}

func (sess *Session) handleHelo(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return sess.writeResponse(Response(StatusParamError, "HELO requires domain"))
	}

	hostname := args[0]
	if err := ValidateHelloHostname(hostname); err != nil {
		return sess.writeResponse(Response(StatusParamError, "Invalid hostname"))
	}

	sess.clientHelloHostname = hostname
	sess.state = StateGreeted
	response := fmt.Sprintf("250 %s Hello %s [%s]", sess.hostname, sess.clientHelloHostname, sess.clientIP)
	return sess.writeResponse(response)
}

func (sess *Session) handleEhlo(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return sess.writeResponse(Response(StatusParamError, "EHLO requires domain"))
	}

	hostname := args[0]
	if err := ValidateHelloHostname(hostname); err != nil {
		return sess.writeResponse(Response(StatusParamError, "Invalid hostname"))
	}

	sess.clientHelloHostname = hostname
	sess.state = StateGreeted

	// Send multi-line response
	responses := []string{
		fmt.Sprintf("250-%s Hello %s [%s]", sess.hostname, sess.clientHelloHostname, sess.clientIP),
		"250-AUTH PLAIN LOGIN",
		"250 HELP",
	}

	for i, resp := range responses {
		if i == len(responses)-1 {
			// Last line uses space instead of dash
			resp = strings.Replace(resp, "250-", "250 ", 1)
		}
		if err := sess.writeResponse(resp); err != nil {
			return err
		}
	}

	return nil
}

func (sess *Session) handleAuth(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return sess.writeResponse(Response(StatusParamError, "AUTH requires mechanism"))
	}

	if sess.state != StateGreeted {
		return sess.writeResponse(Response(StatusBadSequence, "EHLO/HELO required before AUTH"))
	}

	if sess.authenticated {
		return sess.writeResponse(Response(StatusBadSequence, "Already authenticated"))
	}

	mechanism := strings.ToUpper(args[0])

	switch mechanism {
	case "PLAIN":
		return sess.handleAuthPlain(ctx, args[1:])
	case "LOGIN":
		return sess.handleAuthLogin(ctx, args[1:])
	default:
		return sess.writeResponse(Response(StatusParamError, "Authentication mechanism not supported"))
	}
}

func (sess *Session) handleAuthPlain(ctx context.Context, args []string) error {
	var credentials string

	if len(args) > 0 {
		credentials = args[0]
	} else {
		if err := sess.writeResponse("334 "); err != nil {
			return err
		}

		line, err := sess.textproto.ReadLine()
		if err != nil {
			return fmt.Errorf("failed to read AUTH PLAIN credentials: %w", err)
		}
		credentials = line
	}

	if credentials == "*" {
		return sess.writeResponse(Response(StatusAuthRequired, "Authentication cancelled"))
	}

	username, password, err := auth.DecodePlain(credentials)
	if err != nil {
		sess.logger.Debug("AUTH PLAIN decode failed", "error", err, "client_ip", sess.clientIP)
		return sess.writeResponse(Response(StatusAuthRequired, "Authentication failed"))
	}

	return sess.authenticateUser(ctx, username, password)
}

func (sess *Session) handleAuthLogin(ctx context.Context, args []string) error {
	if err := sess.writeResponse("334 " + auth.EncodeBase64("Username:")); err != nil {
		return err
	}

	userLine, err := sess.textproto.ReadLine()
	if err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	if userLine == "*" {
		return sess.writeResponse(Response(StatusAuthRequired, "Authentication cancelled"))
	}

	username, err := auth.DecodeBase64(userLine)
	if err != nil {
		sess.logger.Debug("AUTH LOGIN username decode failed", "error", err, "client_ip", sess.clientIP)
		return sess.writeResponse(Response(StatusAuthRequired, "Authentication failed"))
	}

	if err := sess.writeResponse("334 " + auth.EncodeBase64("Password:")); err != nil {
		return err
	}

	passLine, err := sess.textproto.ReadLine()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	if passLine == "*" {
		return sess.writeResponse(Response(StatusAuthRequired, "Authentication cancelled"))
	}

	password, err := auth.DecodeBase64(passLine)
	if err != nil {
		sess.logger.Debug("AUTH LOGIN password decode failed", "error", err, "client_ip", sess.clientIP)
		return sess.writeResponse(Response(StatusAuthRequired, "Authentication failed"))
	}

	return sess.authenticateUser(ctx, username, password)
}

func (sess *Session) authenticateUser(ctx context.Context, username, password string) error {
	authCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	result := sess.authenticator.Authenticate(authCtx, username, password)

	if result.Success {
		sess.authenticated = true
		sess.username = result.Username
		sess.state = StateAuthenticated
		sess.logger.Info("Authentication successful", "username", username, "client_ip", sess.clientIP)
		return sess.writeResponse(Response(StatusAuthSuccess, "Authentication successful"))
	}

	sess.logger.Warn("Authentication failed", "username", username, "client_ip", sess.clientIP, "error", result.Error)
	return sess.writeResponse(Response(StatusAuthRequired, "Authentication failed"))
}

func (sess *Session) handleMail(ctx context.Context, args []string) error {
	// Check session state
	if sess.state != StateGreeted && sess.state != StateAuthenticated {
		return sess.writeResponse(Response(StatusBadSequence, "EHLO/HELO required before MAIL"))
	}

	// Initialize new message for this mail transaction
	sess.currentMessage = &queue.Message{
		ID:                  queue.GenerateID(),
		ClientIP:            sess.clientIP,
		ClientHelloHostname: sess.clientHelloHostname,
		LocalRecipients:     make(map[string]struct{}),
		VirtualRecipients:   make(map[string]struct{}),
		RelayRecipients:     make(map[string]struct{}),
		ExternalRecipients:  make(map[string]struct{}),
		Created:             time.Now().UTC(),
	}

	// Parse and validate the MAIL FROM command
	emailAddr, err := sess.emailValidator.ParseMailFromCommand(args)
	if err != nil {
		sess.logger.Debug("MAIL FROM validation failed", "error", err, "client_ip", sess.clientIP)
		return sess.writeResponse(Response(StatusParamError, err.Error()))
	}

	// Store the sender address in message
	sess.currentMessage.From = emailAddr.Full
	sess.state = StateMailFrom

	sess.logger.Info("MAIL FROM accepted", "sender", sess.currentMessage.From, "client_ip", sess.clientIP)
	return sess.writeResponse(Response(StatusOK, "Sender accepted"))
}

func (sess *Session) handleRcpt(ctx context.Context, args []string) error {
	// Check session state - MAIL FROM must be done first
	if sess.state != StateMailFrom && sess.state != StateRcptTo {
		return sess.writeResponse(Response(StatusBadSequence, "MAIL FROM required before RCPT TO"))
	}

	// Check recipient limit
	maxRecipients := sess.config.Server.MaxRecipients
	if maxRecipients > 0 && sess.currentMessage.TotalRecipients() >= maxRecipients {
		return sess.writeResponse(Response(StatusExceededStorage, "Too many recipients"))
	}

	// Parse and validate the RCPT TO command
	emailAddr, err := sess.emailValidator.ParseRcptToCommand(args)
	if err != nil {
		sess.logger.Debug("RCPT TO validation failed", "error", err, "client_ip", sess.clientIP)
		return sess.writeResponse(Response(StatusParamError, err.Error()))
	}

	// Classify domain type
	domainType := sess.classifyDomain(emailAddr.Domain)

	// Handle based on domain type
	switch domainType {
	case delivery.RecipientLocal, delivery.RecipientVirtual:
		// Validate recipient using unified validator
		if !sess.rcptValidator.IsRecipientValid(ctx, emailAddr.Full, domainType) {
			sess.logger.Debug("Recipient validation failed", "recipient", emailAddr.Full, "domain_type", domainType, "client_ip", sess.clientIP)
			return sess.writeResponse(Response(StatusMailboxUnavailable, "User unknown"))
		}

		// Check for duplicates and add to appropriate map
		if domainType == delivery.RecipientLocal {
			if _, exists := sess.currentMessage.LocalRecipients[emailAddr.Full]; exists {
				sess.logger.Debug("Duplicate recipient ignored", "recipient", emailAddr.Full, "domain_type", domainType, "client_ip", sess.clientIP)
				return sess.writeResponse(Response(StatusOK, "Recipient accepted"))
			}
			sess.currentMessage.LocalRecipients[emailAddr.Full] = struct{}{}
		} else {
			if _, exists := sess.currentMessage.VirtualRecipients[emailAddr.Full]; exists {
				sess.logger.Debug("Duplicate recipient ignored", "recipient", emailAddr.Full, "domain_type", domainType, "client_ip", sess.clientIP)
				return sess.writeResponse(Response(StatusOK, "Recipient accepted"))
			}
			sess.currentMessage.VirtualRecipients[emailAddr.Full] = struct{}{}
		}

	case delivery.RecipientRelay:
		// Check for duplicates in relay map
		if _, exists := sess.currentMessage.RelayRecipients[emailAddr.Full]; exists {
			sess.logger.Debug("Duplicate relay recipient ignored", "recipient", emailAddr.Full, "client_ip", sess.clientIP)
			return sess.writeResponse(Response(StatusOK, "Recipient accepted"))
		}
		sess.currentMessage.RelayRecipients[emailAddr.Full] = struct{}{}

	case delivery.RecipientExternal:
		sess.logger.Debug("External domain not permitted", "recipient", emailAddr.Full, "domain", emailAddr.Domain, "client_ip", sess.clientIP)
		return sess.writeResponse(Response(StatusTransactionFailed, "Relay not permitted"))
	}

	sess.state = StateRcptTo

	sess.logger.Info("RCPT TO accepted", "recipient", emailAddr.Full, "domain_type", domainType, "total_recipients", sess.currentMessage.TotalRecipients(), "client_ip", sess.clientIP)
	return sess.writeResponse(Response(StatusOK, "Recipient accepted"))
}

func (sess *Session) handleData(ctx context.Context, args []string) error {
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

	// Generate headers for the message (overridden by session types)
	headers := sess.generateHeaders()

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

	sess.logger.Info("Message received and stored",
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

func (sess *Session) handleRset(ctx context.Context, args []string) error {
	sess.resetSession()
	return sess.writeResponse(Response(StatusOK, "Reset state"))
}

func (sess *Session) handleNoop(ctx context.Context, args []string) error {
	return sess.writeResponse(Response(StatusOK, ""))
}

func (sess *Session) handleQuit(ctx context.Context, args []string) error {
	sess.state = StateClosed
	return sess.writeResponse(Response(StatusClosing, ""))
}

func (sess *Session) resetSession() {
	// Keep authentication state but reset mail transaction
	if sess.authenticated {
		sess.state = StateAuthenticated
	} else {
		sess.state = StateGreeted
	}

	// Clear current message
	sess.currentMessage = nil
}

func (sess *Session) writeResponse(response string) error {
	sess.logger.Debug("Sending response", "response", response, "client_ip", sess.clientIP)
	return sess.textproto.PrintfLine("%s", response)
}

// generateHeaders creates headers to be prepended to the message
// Default implementation returns empty string (no headers added)
// Session types override this to add appropriate headers
func (sess *Session) generateHeaders() string {
	sess.logger.Debug("Session.generateHeaders (default) called", "client_ip", sess.clientIP)
	return ""
}
