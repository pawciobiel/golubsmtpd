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
	state         SessionState
	helo          string
	authenticated bool
	username      string
	mailFrom      string
	rcptTo        []string

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
		rcptTo:         make([]string, 0),
	}
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

		if err := s.processCommand(line); err != nil {
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

func (s *Session) processCommand(line string) error {
	// Parse command and arguments
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return s.writeResponse(Response(StatusSyntaxError, ""))
	}

	command := strings.ToUpper(parts[0])
	args := parts[1:]

	switch command {
	case "HELO":
		return s.handleHelo(args)
	case "EHLO":
		return s.handleEhlo(args)
	case "AUTH":
		return s.handleAuth(args)
	case "MAIL":
		return s.handleMail(args)
	case "RCPT":
		return s.handleRcpt(args)
	case "DATA":
		return s.handleData(args)
	case "RSET":
		return s.handleRset(args)
	case "NOOP":
		return s.handleNoop(args)
	case "QUIT":
		return s.handleQuit(args)
	default:
		return s.writeResponse(Response(StatusCommandNotImpl, "Command not implemented"))
	}
}

func (s *Session) handleHelo(args []string) error {
	if len(args) == 0 {
		return s.writeResponse(Response(StatusParamError, "HELO requires domain"))
	}

	s.helo = args[0]
	s.state = StateGreeted
	response := fmt.Sprintf("250 %s Hello %s [%s]", s.hostname, s.helo, s.clientIP)
	return s.writeResponse(response)
}

func (s *Session) handleEhlo(args []string) error {
	if len(args) == 0 {
		return s.writeResponse(Response(StatusParamError, "EHLO requires domain"))
	}

	s.helo = args[0]
	s.state = StateGreeted

	// Send multi-line response
	responses := []string{
		fmt.Sprintf("250-%s Hello %s [%s]", s.hostname, s.helo, s.clientIP),
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

func (s *Session) handleAuth(args []string) error {
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
		return s.handleAuthPlain(args[1:])
	case "LOGIN":
		return s.handleAuthLogin(args[1:])
	default:
		return s.writeResponse(Response(StatusParamError, "Authentication mechanism not supported"))
	}
}

func (s *Session) handleAuthPlain(args []string) error {
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

	return s.authenticateUser(username, password)
}

func (s *Session) handleAuthLogin(args []string) error {
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

	return s.authenticateUser(username, password)
}

func (s *Session) authenticateUser(username, password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := s.authenticator.Authenticate(ctx, username, password)

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

func (s *Session) handleMail(args []string) error {
	// Check session state
	if s.state != StateGreeted && s.state != StateAuthenticated {
		return s.writeResponse(Response(StatusBadSequence, "EHLO/HELO required before MAIL"))
	}

	// Reset session state for new mail transaction
	s.mailFrom = ""
	s.rcptTo = s.rcptTo[:0] // Clear recipients

	// Parse and validate the MAIL FROM command
	emailAddr, err := s.emailValidator.ParseMailFromCommand(args)
	if err != nil {
		s.logger.Debug("MAIL FROM validation failed", "error", err, "client_ip", s.clientIP)
		return s.writeResponse(Response(StatusParamError, err.Error()))
	}

	// Store the sender address
	s.mailFrom = emailAddr.Full
	s.state = StateMailFrom

	s.logger.Info("MAIL FROM accepted", "sender", s.mailFrom, "client_ip", s.clientIP)
	return s.writeResponse(Response(StatusOK, "Sender accepted"))
}

func (s *Session) handleRcpt(args []string) error {
	// Check session state - MAIL FROM must be done first
	if s.state != StateMailFrom && s.state != StateRcptTo {
		return s.writeResponse(Response(StatusBadSequence, "MAIL FROM required before RCPT TO"))
	}

	// Check recipient limit
	maxRecipients := s.config.Server.MaxRecipients
	if maxRecipients > 0 && len(s.rcptTo) >= maxRecipients {
		return s.writeResponse(Response(StatusExceededStorage, "Too many recipients"))
	}

	// Parse and validate the RCPT TO command
	emailAddr, err := s.emailValidator.ParseRcptToCommand(args)
	if err != nil {
		s.logger.Debug("RCPT TO validation failed", "error", err, "client_ip", s.clientIP)
		return s.writeResponse(Response(StatusParamError, err.Error()))
	}

	// Check for duplicate recipients
	for _, existing := range s.rcptTo {
		if existing == emailAddr.Full {
			s.logger.Debug("Duplicate recipient ignored", "recipient", emailAddr.Full, "client_ip", s.clientIP)
			return s.writeResponse(Response(StatusOK, "Recipient accepted"))
		}
	}

	// Add recipient to list
	s.rcptTo = append(s.rcptTo, emailAddr.Full)
	s.state = StateRcptTo

	s.logger.Info("RCPT TO accepted", "recipient", emailAddr.Full, "total_recipients", len(s.rcptTo), "client_ip", s.clientIP)
	return s.writeResponse(Response(StatusOK, "Recipient accepted"))
}

func (s *Session) handleData(args []string) error {
	// Check session state - must have at least one recipient
	if s.state != StateRcptTo {
		return s.writeResponse(Response(StatusBadSequence, "RCPT TO required before DATA"))
	}

	if len(s.rcptTo) == 0 {
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
		"sender", s.mailFrom,
		"recipients", len(s.rcptTo),
		"size", len(messageData),
		"client_ip", s.clientIP)

	// Reset session for next mail transaction
	s.resetSession()

	return s.writeResponse(Response(StatusOK, "Message accepted for delivery"))
}

func (s *Session) handleRset(args []string) error {
	s.resetSession()
	return s.writeResponse(Response(StatusOK, "Reset state"))
}

func (s *Session) handleNoop(args []string) error {
	return s.writeResponse(Response(StatusOK, ""))
}

func (s *Session) handleQuit(args []string) error {
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
	s.mailFrom = ""
	s.rcptTo = s.rcptTo[:0] // Clear slice but keep capacity
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
