package smtp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"time"

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
	config     *config.Config
	logger     *slog.Logger
	conn       net.Conn
	textproto  *textproto.Conn
	clientIP   string
	hostname   string
	
	// Session state
	state        SessionState
	helo         string
	authenticated bool
	username     string
	mailFrom     string
	rcptTo       []string
	
	// Security checks
	reverseDNS   string
	dnsblResults []string
}

// NewSession creates a new SMTP session
func NewSession(cfg *config.Config, logger *slog.Logger, conn net.Conn, clientIP string) *Session {
	return &Session{
		config:   cfg,
		logger:   logger,
		conn:     conn,
		textproto: textproto.NewConn(conn),
		clientIP: clientIP,
		hostname: cfg.Server.Hostname,
		state:    StateConnected,
		rcptTo:   make([]string, 0),
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
	// TODO: Implement authentication
	return s.writeResponse(Response(StatusCommandNotImpl, "AUTH not implemented yet"))
}

func (s *Session) handleMail(args []string) error {
	// TODO: Implement MAIL FROM
	return s.writeResponse(Response(StatusCommandNotImpl, "MAIL not implemented yet"))
}

func (s *Session) handleRcpt(args []string) error {
	// TODO: Implement RCPT TO
	return s.writeResponse(Response(StatusCommandNotImpl, "RCPT not implemented yet"))
}

func (s *Session) handleData(args []string) error {
	// TODO: Implement DATA
	return s.writeResponse(Response(StatusCommandNotImpl, "DATA not implemented yet"))
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
	s.state = StateGreeted
	s.authenticated = false
	s.username = ""
	s.mailFrom = ""
	s.rcptTo = s.rcptTo[:0] // Clear slice but keep capacity
}

func (s *Session) writeResponse(response string) error {
	s.logger.Debug("Sending response", "response", response, "client_ip", s.clientIP)
	return s.textproto.PrintfLine("%s", response)
}