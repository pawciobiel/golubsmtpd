package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/security"
	"github.com/pawciobiel/golubsmtpd/internal/smtp"
)

const (
	UnknownClientIP = "unknown"
)

type Server struct {
	config   *config.Config
	logger   *slog.Logger
	listener net.Listener
	wg       sync.WaitGroup
	shutdown chan struct{}

	// Security checkers
	rdnsChecker  *security.RDNSChecker
	dnsblChecker *security.DNSBLChecker

	// Authentication
	authenticator auth.Authenticator

	// Lock-free connection tracking
	totalConnections int64    // atomic counter
	ipConnections    sync.Map // map[string]*int64 - IP -> connection count
}

func New(cfg *config.Config, logger *slog.Logger, authenticator auth.Authenticator) *Server {
	return &Server{
		config:        cfg,
		logger:        logger,
		shutdown:      make(chan struct{}),
		rdnsChecker:   security.NewRDNSChecker(&cfg.Security.ReverseDNS, logger),
		dnsblChecker:  security.NewDNSBLChecker(&cfg.Security.DNSBL, logger),
		authenticator: authenticator,
	}
}

func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.config.Server.Bind, s.config.Server.Port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.listener = listener
	s.logger.Info("SMTP server started", "address", addr)

	// Start accepting connections
	s.wg.Add(1)
	go s.acceptLoop(ctx)

	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Shutting down SMTP server")
	close(s.shutdown)

	if s.listener != nil {
		s.listener.Close()
	}

	// Wait for all goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("SMTP server stopped gracefully")
		return nil
	case <-ctx.Done():
		s.logger.Warn("SMTP server shutdown timeout")
		return ctx.Err()
	}
}

func (s *Server) acceptLoop(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-s.shutdown:
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return
			default:
				s.logger.Error("Failed to accept connection", "error", err)
				continue
			}
		}

		clientIP := getClientIP(conn)

		// Check limits BEFORE spawning goroutine
		if !s.canAcceptConnection(clientIP) {
			conn.Close()
			continue
		}

		// Track connection
		s.trackConnection(clientIP)

		s.wg.Add(1)
		go s.handleConnection(ctx, conn, clientIP)
	}
}

func (s *Server) canAcceptConnection(clientIP string) bool {
	// Reject connections with invalid IP addresses
	if clientIP == UnknownClientIP {
		s.logger.Warn("Connection rejected: unable to determine client IP")
		return false
	}

	// Check total connection limit (atomic read)
	totalConns := atomic.LoadInt64(&s.totalConnections)
	if totalConns >= int64(s.config.Server.MaxConnections) {
		s.logger.Warn("Connection rejected: max connections reached",
			"current", totalConns, "max", s.config.Server.MaxConnections)
		return false
	}

	// Check per-IP connection limit (sync.Map)
	ipConns := s.getIPConnectionCount(clientIP)
	if ipConns >= s.config.Server.MaxConnectionsPerIP {
		s.logger.Warn("Connection rejected: max connections per IP reached",
			"ip", clientIP, "current", ipConns, "max", s.config.Server.MaxConnectionsPerIP)
		return false
	}

	return true
}

func (s *Server) trackConnection(clientIP string) {
	atomic.AddInt64(&s.totalConnections, 1)
	s.incrementIPConnection(clientIP)
}

func (s *Server) untrackConnection(clientIP string) {
	atomic.AddInt64(&s.totalConnections, -1)
	s.decrementIPConnection(clientIP)
}

func (s *Server) getIPConnectionCount(ip string) int {
	if val, ok := s.ipConnections.Load(ip); ok {
		return int(atomic.LoadInt64(val.(*int64)))
	}
	return 0
}

func (s *Server) incrementIPConnection(ip string) {
	// Load or create counter for this IP
	val, _ := s.ipConnections.LoadOrStore(ip, new(int64))
	atomic.AddInt64(val.(*int64), 1)
}

func (s *Server) decrementIPConnection(ip string) {
	if val, ok := s.ipConnections.Load(ip); ok {
		newCount := atomic.AddInt64(val.(*int64), -1)
		// Clean up if count reaches zero
		if newCount <= 0 {
			s.ipConnections.Delete(ip)
		}
	}
}

func (s *Server) performSecurityChecks(ctx context.Context, clientIP string) bool {
	rdnsResult := s.rdnsChecker.Lookup(ctx, clientIP)
	if !rdnsResult.Valid {
		s.logger.Warn("rDNS check failed",
			"client_ip", clientIP,
			"hostname", rdnsResult.Hostname,
			"error", rdnsResult.Error)
		return false
	}

	dnsblResults := s.dnsblChecker.CheckIP(ctx, clientIP)
	for _, result := range dnsblResults {
		if result.Listed && s.dnsblChecker.ShouldReject() {
			s.logger.Warn("IP listed in DNSBL, rejecting connection",
				"client_ip", clientIP,
				"provider", result.Provider,
				"response_codes", result.ResponseCodes)
			return false
		}
	}

	return true
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn, clientIP string) {
	defer s.wg.Done()
	defer s.untrackConnection(clientIP)
	defer conn.Close()

	s.logger.Info("New connection accepted", "client_ip", clientIP)

	if !s.performSecurityChecks(ctx, clientIP) {
		s.logger.Warn("Connection rejected due to security checks", "client_ip", clientIP)
		return
	}

	session := smtp.NewSession(s.config, s.logger, conn, clientIP, s.authenticator)
	if err := session.Handle(ctx); err != nil {
		s.logger.Debug("SMTP session ended", "client_ip", clientIP, "error", err)
	} else {
		s.logger.Debug("SMTP session completed successfully", "client_ip", clientIP)
	}
}

func getClientIP(conn net.Conn) string {
	if addr := conn.RemoteAddr(); addr != nil {
		if tcpAddr, ok := addr.(*net.TCPAddr); ok {
			return tcpAddr.IP.String()
		}
	}
	return UnknownClientIP
}
