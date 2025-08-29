package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
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

// Session represents an SMTP session with a client
type Session struct {
	config         *config.Config
	logger         *slog.Logger
	conn           net.Conn
	textproto      *textproto.Conn
	clientIP       string
	hostname       string
	authenticator  auth.Authenticator
	emailValidator *EmailValidator

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

// NewSession creates a new SMTP session
func NewSession(cfg *config.Config, logger *slog.Logger, conn net.Conn, clientIP string, authenticator auth.Authenticator) *Session {
	return &Session{
		config:         cfg,
		logger:         logger,
		conn:           conn,
		textproto:      textproto.NewConn(conn),
		clientIP:       clientIP,
		hostname:       cfg.Server.Hostname,
		authenticator:  authenticator,
		emailValidator: NewEmailValidator(cfg),
		state:          StateConnected,
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
func (s *Session) classifyDomain(domain string) queue.RecipientType {
	if containsDomain(s.config.Server.LocalDomains, domain) {
		return queue.RecipientLocal
	}
	if containsDomain(s.config.Server.VirtualDomains, domain) {
		return queue.RecipientVirtual
	}
	if containsDomain(s.config.Server.RelayDomains, domain) {
		return queue.RecipientRelay
	}
	return queue.RecipientExternal
}

// validateUserWithChain tries authentication plugins in chain order
func (s *Session) validateUserWithChain(ctx context.Context, email string) bool {
	return s.authenticator.ValidateUser(ctx, email)
}

// Handle processes the SMTP session
func (s *Session) Handle(ctx context.Context) error {
	defer s.textproto.Close()

	s.logger.Info("Starting SMTP session", "client_ip", s.clientIP)

	// Send greeting
	if err := s.sendGreeting(); err != nil {
		return fmt.Errorf("failed to send greeting: %w", err)
	}

	// Process commands
	for s.state != StateClosed {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Update timeouts for each command
		if s.config.Server.ReadTimeout > 0 {
			s.conn.SetReadDeadline(time.Now().Add(s.config.Server.ReadTimeout))
		}
		if s.config.Server.WriteTimeout > 0 {
			s.conn.SetWriteDeadline(time.Now().Add(s.config.Server.WriteTimeout))
		}

		line, err := s.textproto.ReadLine()
		if err != nil {
			s.logger.Debug("Error reading command", "error", err)
			return err
		}

		s.logger.Debug("Received command", "command", line, "client_ip", s.clientIP)

		if err := s.processCommand(ctx, line); err != nil {
			s.logger.Error("Error processing command", "error", err, "command", line)
			return err
		}
	}

	return nil
}

func (s *Session) sendGreeting() error {
	s.state = StateGreeted
	greeting := ResponseWithHostname(StatusReady, s.hostname, "ESMTP Service ready")
	return s.writeResponse(greeting)
}

func (s *Session) processCommand(ctx context.Context, line string) error {
	// Parse command and arguments
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return s.writeResponse(Response(StatusSyntaxError, ""))
	}

	command := strings.ToUpper(parts[0])
	args := parts[1:]

	switch command {
	case "HELO":
		return s.handleHelo(ctx, args)
	case "EHLO":
		return s.handleEhlo(ctx, args)
	case "AUTH":
		return s.handleAuth(ctx, args)
	case "MAIL":
		return s.handleMail(ctx, args)
	case "RCPT":
		return s.handleRcpt(ctx, args)
	case "DATA":
		return s.handleData(ctx, args)
	case "RSET":
		return s.handleRset(ctx, args)
	case "NOOP":
		return s.handleNoop(ctx, args)
	case "QUIT":
		return s.handleQuit(ctx, args)
	default:
		return s.writeResponse(Response(StatusCommandNotImpl, "Command not implemented"))
	}
}

func (s *Session) handleHelo(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return s.writeResponse(Response(StatusParamError, "HELO requires domain"))
	}

	hostname := args[0]
	if err := ValidateHelloHostname(hostname); err != nil {
		return s.writeResponse(Response(StatusParamError, "Invalid hostname"))
	}

	s.clientHelloHostname = hostname
	s.state = StateGreeted
	response := fmt.Sprintf("250 %s Hello %s [%s]", s.hostname, s.clientHelloHostname, s.clientIP)
	return s.writeResponse(response)
}

func (s *Session) handleEhlo(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return s.writeResponse(Response(StatusParamError, "EHLO requires domain"))
	}

	hostname := args[0]
	if err := ValidateHelloHostname(hostname); err != nil {
		return s.writeResponse(Response(StatusParamError, "Invalid hostname"))
	}

	s.clientHelloHostname = hostname
	s.state = StateGreeted

	// Send multi-line response
	responses := []string{
		fmt.Sprintf("250-%s Hello %s [%s]", s.hostname, s.clientHelloHostname, s.clientIP),
		"250-AUTH PLAIN LOGIN",
		"250 HELP",
	}

	for i, resp := range responses {
		if i == len(responses)-1 {
			// Last line uses space instead of dash
			resp = strings.Replace(resp, "250-", "250 ", 1)
		}
		if err := s.writeResponse(resp); err != nil {
			return err
		}
	}

	return nil
}

func (s *Session) handleAuth(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return s.writeResponse(Response(StatusParamError, "AUTH requires mechanism"))
	}

	if s.state != StateGreeted {
		return s.writeResponse(Response(StatusBadSequence, "EHLO/HELO required before AUTH"))
	}

	if s.authenticated {
		return s.writeResponse(Response(StatusBadSequence, "Already authenticated"))
	}

	mechanism := strings.ToUpper(args[0])

	switch mechanism {
	case "PLAIN":
		return s.handleAuthPlain(ctx, args[1:])
	case "LOGIN":
		return s.handleAuthLogin(ctx, args[1:])
	default:
		return s.writeResponse(Response(StatusParamError, "Authentication mechanism not supported"))
	}
}

func (s *Session) handleAuthPlain(ctx context.Context, args []string) error {
	var credentials string

	if len(args) > 0 {
		credentials = args[0]
	} else {
		if err := s.writeResponse("334 "); err != nil {
			return err
		}

		line, err := s.textproto.ReadLine()
		if err != nil {
			return fmt.Errorf("failed to read AUTH PLAIN credentials: %w", err)
		}
		credentials = line
	}

	if credentials == "*" {
		return s.writeResponse(Response(StatusAuthRequired, "Authentication cancelled"))
	}

	username, password, err := auth.DecodePlain(credentials)
	if err != nil {
		s.logger.Debug("AUTH PLAIN decode failed", "error", err, "client_ip", s.clientIP)
		return s.writeResponse(Response(StatusAuthRequired, "Authentication failed"))
	}

	return s.authenticateUser(ctx, username, password)
}

func (s *Session) handleAuthLogin(ctx context.Context, args []string) error {
	if err := s.writeResponse("334 " + auth.EncodeBase64("Username:")); err != nil {
		return err
	}

	userLine, err := s.textproto.ReadLine()
	if err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	if userLine == "*" {
		return s.writeResponse(Response(StatusAuthRequired, "Authentication cancelled"))
	}

	username, err := auth.DecodeBase64(userLine)
	if err != nil {
		s.logger.Debug("AUTH LOGIN username decode failed", "error", err, "client_ip", s.clientIP)
		return s.writeResponse(Response(StatusAuthRequired, "Authentication failed"))
	}

	if err := s.writeResponse("334 " + auth.EncodeBase64("Password:")); err != nil {
		return err
	}

	passLine, err := s.textproto.ReadLine()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	if passLine == "*" {
		return s.writeResponse(Response(StatusAuthRequired, "Authentication cancelled"))
	}

	password, err := auth.DecodeBase64(passLine)
	if err != nil {
		s.logger.Debug("AUTH LOGIN password decode failed", "error", err, "client_ip", s.clientIP)
		return s.writeResponse(Response(StatusAuthRequired, "Authentication failed"))
	}

	return s.authenticateUser(ctx, username, password)
}

func (s *Session) authenticateUser(ctx context.Context, username, password string) error {
	authCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	result := s.authenticator.Authenticate(authCtx, username, password)

	if result.Success {
		s.authenticated = true
		s.username = result.Username
		s.state = StateAuthenticated
		s.logger.Info("Authentication successful", "username", username, "client_ip", s.clientIP)
		return s.writeResponse(Response(StatusAuthSuccess, "Authentication successful"))
	}

	s.logger.Warn("Authentication failed", "username", username, "client_ip", s.clientIP, "error", result.Error)
	return s.writeResponse(Response(StatusAuthRequired, "Authentication failed"))
}

func (s *Session) handleMail(ctx context.Context, args []string) error {
	// Check session state
	if s.state != StateGreeted && s.state != StateAuthenticated {
		return s.writeResponse(Response(StatusBadSequence, "EHLO/HELO required before MAIL"))
	}

	// Initialize new message for this mail transaction
	s.currentMessage = &queue.Message{
		ClientIP:            s.clientIP,
		ClientHelloHostname: s.clientHelloHostname,
		LocalRecipients:     make(map[string]struct{}),
		VirtualRecipients:   make(map[string]struct{}),
		RelayRecipients:     make(map[string]struct{}),
		ExternalRecipients:  make(map[string]struct{}),
		Created:            time.Now().UTC(),
	}

	// Parse and validate the MAIL FROM command
	emailAddr, err := s.emailValidator.ParseMailFromCommand(args)
	if err != nil {
		s.logger.Debug("MAIL FROM validation failed", "error", err, "client_ip", s.clientIP)
		return s.writeResponse(Response(StatusParamError, err.Error()))
	}

	// Store the sender address in message
	s.currentMessage.From = emailAddr.Full
	s.state = StateMailFrom

	s.logger.Info("MAIL FROM accepted", "sender", s.currentMessage.From, "client_ip", s.clientIP)
	return s.writeResponse(Response(StatusOK, "Sender accepted"))
}

func (s *Session) handleRcpt(ctx context.Context, args []string) error {
	// Check session state - MAIL FROM must be done first
	if s.state != StateMailFrom && s.state != StateRcptTo {
		return s.writeResponse(Response(StatusBadSequence, "MAIL FROM required before RCPT TO"))
	}

	// Check recipient limit
	maxRecipients := s.config.Server.MaxRecipients
	if maxRecipients > 0 && s.currentMessage.TotalRecipients() >= maxRecipients {
		return s.writeResponse(Response(StatusExceededStorage, "Too many recipients"))
	}

	// Parse and validate the RCPT TO command
	emailAddr, err := s.emailValidator.ParseRcptToCommand(args)
	if err != nil {
		s.logger.Debug("RCPT TO validation failed", "error", err, "client_ip", s.clientIP)
		return s.writeResponse(Response(StatusParamError, err.Error()))
	}

	// Classify domain type
	domainType := s.classifyDomain(emailAddr.Domain)
	
	// Handle based on domain type
	switch domainType {
	case queue.RecipientLocal, queue.RecipientVirtual:
		// Validate user exists using plugin chain
		if !s.validateUserWithChain(ctx, emailAddr.Full) {
			s.logger.Debug("User validation failed", "recipient", emailAddr.Full, "domain_type", domainType, "client_ip", s.clientIP)
			return s.writeResponse(Response(StatusMailboxUnavailable, "User unknown"))
		}
		
		// Check for duplicates and add to appropriate map
		if domainType == queue.RecipientLocal {
			if _, exists := s.currentMessage.LocalRecipients[emailAddr.Full]; exists {
				s.logger.Debug("Duplicate recipient ignored", "recipient", emailAddr.Full, "domain_type", domainType, "client_ip", s.clientIP)
				return s.writeResponse(Response(StatusOK, "Recipient accepted"))
			}
			s.currentMessage.LocalRecipients[emailAddr.Full] = struct{}{}
		} else {
			if _, exists := s.currentMessage.VirtualRecipients[emailAddr.Full]; exists {
				s.logger.Debug("Duplicate recipient ignored", "recipient", emailAddr.Full, "domain_type", domainType, "client_ip", s.clientIP)
				return s.writeResponse(Response(StatusOK, "Recipient accepted"))
			}
			s.currentMessage.VirtualRecipients[emailAddr.Full] = struct{}{}
		}
		
	case queue.RecipientRelay:
		// Check for duplicates in relay map
		if _, exists := s.currentMessage.RelayRecipients[emailAddr.Full]; exists {
			s.logger.Debug("Duplicate relay recipient ignored", "recipient", emailAddr.Full, "client_ip", s.clientIP)
			return s.writeResponse(Response(StatusOK, "Recipient accepted"))
		}
		s.currentMessage.RelayRecipients[emailAddr.Full] = struct{}{}
		
	case queue.RecipientExternal:
		s.logger.Debug("External domain not permitted", "recipient", emailAddr.Full, "domain", emailAddr.Domain, "client_ip", s.clientIP)
		return s.writeResponse(Response(StatusTransactionFailed, "Relay not permitted"))
	}

	s.state = StateRcptTo

	s.logger.Info("RCPT TO accepted", "recipient", emailAddr.Full, "domain_type", domainType, "total_recipients", s.currentMessage.TotalRecipients(), "client_ip", s.clientIP)
	return s.writeResponse(Response(StatusOK, "Recipient accepted"))
}

func (s *Session) handleData(ctx context.Context, args []string) error {
	// Check session state - must have at least one recipient
	if s.state != StateRcptTo {
		return s.writeResponse(Response(StatusBadSequence, "RCPT TO required before DATA"))
	}

	if s.currentMessage.TotalRecipients() == 0 {
		return s.writeResponse(Response(StatusBadSequence, "No recipients specified"))
	}

	// Start data collection
	s.state = StateData
	if err := s.writeResponse(Response(StatusStartMailInput, "Start mail input; end with <CRLF>.<CRLF>")); err != nil {
		return err
	}

	// Read message data
	messageData, err := s.readMessageData()
	if err != nil {
		s.logger.Error("Error reading message data", "error", err, "client_ip", s.clientIP)
		return s.writeResponse(Response(StatusLocalError, "Error reading message"))
	}

	// TODO: Store message using Maildir storage system
	s.logger.Info("Message received",
		"sender", s.currentMessage.From,
		"total_recipients", s.currentMessage.TotalRecipients(),
		"size", len(messageData),
		"client_ip", s.clientIP)

	// Reset session for next mail transaction
	s.resetSession()

	return s.writeResponse(Response(StatusOK, "Message accepted for delivery"))
}

func (s *Session) handleRset(ctx context.Context, args []string) error {
	s.resetSession()
	return s.writeResponse(Response(StatusOK, "Reset state"))
}

func (s *Session) handleNoop(ctx context.Context, args []string) error {
	return s.writeResponse(Response(StatusOK, ""))
}

func (s *Session) handleQuit(ctx context.Context, args []string) error {
	s.state = StateClosed
	return s.writeResponse(Response(StatusClosing, ""))
}

func (s *Session) resetSession() {
	// Keep authentication state but reset mail transaction
	if s.authenticated {
		s.state = StateAuthenticated
	} else {
		s.state = StateGreeted
	}
	
	// Clear current message
	s.currentMessage = nil
}

func (s *Session) readMessageData() ([]byte, error) {
	var messageData []byte
	maxMessageSize := s.config.Server.MaxMessageSize

	for {
		line, err := s.textproto.ReadLine()
		if err != nil {
			return nil, fmt.Errorf("failed to read message line: %w", err)
		}

		// Check for end of message
		if line == "." {
			break
		}

		// Handle SMTP dot-stuffing (lines starting with .. become .)
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}

		// Add line to message data with CRLF
		lineBytes := []byte(line + "\r\n")

		// Check message size limit
		if maxMessageSize > 0 && len(messageData)+len(lineBytes) > maxMessageSize {
			return nil, fmt.Errorf("message size exceeds limit")
		}

		messageData = append(messageData, lineBytes...)
	}

	return messageData, nil
}

func (s *Session) writeResponse(response string) error {
	s.logger.Debug("Sending response", "response", response, "client_ip", s.clientIP)
	return s.textproto.PrintfLine("%s", response)
}
