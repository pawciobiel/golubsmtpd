package server

import (
	"context"
	"fmt"
	"net"
	"net/textproto"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/aliases"
	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/logging"
	"github.com/pawciobiel/golubsmtpd/internal/queue"
	"github.com/pawciobiel/golubsmtpd/internal/security"
	"github.com/pawciobiel/golubsmtpd/internal/smtp"
)

var log = logging.GetLogger

const (
	UnknownClientIP = "unknown"
)

type Server struct {
	config       *config.Config
	listener     net.Listener
	socketListen net.Listener
	wg           sync.WaitGroup
	shutdown     chan struct{}

	// Security checkers
	rdnsChecker  *security.RDNSChecker
	dnsblChecker *security.DNSBLChecker

	// Authentication
	authenticator auth.Authenticator

	localAliasesMaps *aliases.LocalAliasesMaps

	// Message queue
	queue *queue.Queue

	// SMTP dependencies
	smtpDeps *smtp.Dependencies

	// Lock-free connection tracking
	totalConnections int64    // atomic counter
	ipConnections    sync.Map // map[string]*int64 - IP -> connection count
}

func New(cfg *config.Config, authenticator auth.Authenticator, localAliasesMaps *aliases.LocalAliasesMaps) *Server {
	smtpDeps := &smtp.Dependencies{
		Authenticator:    authenticator,
		LocalAliasesMaps: localAliasesMaps,
	}

	return &Server{
		config:           cfg,
		shutdown:         make(chan struct{}),
		rdnsChecker:      security.NewRDNSChecker(&cfg.Security.ReverseDNS),
		dnsblChecker:     security.NewDNSBLChecker(&cfg.Security.DNSBL),
		authenticator:    authenticator,
		localAliasesMaps: localAliasesMaps,
		smtpDeps:         smtpDeps,
	}
}

func (srv *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", srv.config.Server.Bind, srv.config.Server.Port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	srv.listener = listener

	// Initialize and start message queue
	srv.queue = queue.NewQueue(ctx, srv.config)
	srv.queue.StartConsumer(ctx)

	// Update SMTP dependencies with queue
	srv.smtpDeps.Queue = srv.queue

	log().Info("SMTP server started", "address", addr)

	// Start Unix domain socket listener
	if err := srv.startSocketListener(ctx); err != nil {
		srv.listener.Close()
		return fmt.Errorf("failed to start Unix domain socket listener: %w", err)
	}

	// Start accepting connections
	srv.wg.Add(1)
	go srv.acceptLoop(ctx)

	return nil
}

func (srv *Server) Stop(ctx context.Context) error {
	log().Info("Shutting down SMTP server")
	close(srv.shutdown)

	if srv.listener != nil {
		srv.listener.Close()
	}

	if srv.socketListen != nil {
		srv.socketListen.Close()
	}

	// Stop message queue first
	if srv.queue != nil {
		if err := srv.queue.Stop(ctx); err != nil {
			log().Error("Error stopping message queue", "error", err)
		}
	}

	// Wait for all goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		srv.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log().Info("SMTP server stopped gracefully")
		return nil
	case <-ctx.Done():
		log().Warn("SMTP server shutdown timeout")
		return ctx.Err()
	}
}

func (srv *Server) acceptLoop(ctx context.Context) {
	defer srv.wg.Done()

	for {
		select {
		case <-srv.shutdown:
			return
		default:
		}

		conn, err := srv.listener.Accept()
		if err != nil {
			select {
			case <-srv.shutdown:
				return
			default:
				log().Error("Failed to accept connection", "error", err)
				continue
			}
		}

		clientIP := getClientIP(conn)

		// Check limits BEFORE spawning goroutine
		if !srv.canAcceptConnection(clientIP) {
			conn.Close()
			continue
		}

		// Track connection
		srv.trackConnection(clientIP)

		srv.wg.Add(1)
		go srv.handleConnection(ctx, conn, clientIP)
	}
}

func (srv *Server) canAcceptConnection(clientIP string) bool {
	// Reject connections with invalid IP addresses
	if clientIP == UnknownClientIP {
		log().Warn("Connection rejected: unable to determine client IP")
		return false
	}

	// Check total connection limit (atomic read)
	totalConns := atomic.LoadInt64(&srv.totalConnections)
	if totalConns >= int64(srv.config.Server.MaxConnections) {
		log().Warn("Connection rejected: max connections reached",
			"current", totalConns, "max", srv.config.Server.MaxConnections)
		return false
	}

	// Check per-IP connection limit (sync.Map)
	ipConns := srv.getIPConnectionCount(clientIP)
	if ipConns >= srv.config.Server.MaxConnectionsPerIP {
		log().Warn("Connection rejected: max connections per IP reached",
			"ip", clientIP, "current", ipConns, "max", srv.config.Server.MaxConnectionsPerIP)
		return false
	}

	return true
}

func (srv *Server) trackConnection(clientIP string) {
	atomic.AddInt64(&srv.totalConnections, 1)
	srv.incrementIPConnection(clientIP)
}

func (srv *Server) untrackConnection(clientIP string) {
	atomic.AddInt64(&srv.totalConnections, -1)
	srv.decrementIPConnection(clientIP)
}

func (srv *Server) getIPConnectionCount(ip string) int {
	if val, ok := srv.ipConnections.Load(ip); ok {
		return int(atomic.LoadInt64(val.(*int64)))
	}
	return 0
}

func (srv *Server) incrementIPConnection(ip string) {
	// Load or create counter for this IP
	val, _ := srv.ipConnections.LoadOrStore(ip, new(int64))
	atomic.AddInt64(val.(*int64), 1)
}

func (srv *Server) decrementIPConnection(ip string) {
	if val, ok := srv.ipConnections.Load(ip); ok {
		newCount := atomic.AddInt64(val.(*int64), -1)
		// Clean up if count reaches zero
		if newCount <= 0 {
			srv.ipConnections.Delete(ip)
		}
	}
}

func (srv *Server) performSecurityChecks(ctx context.Context, clientIP string) bool {
	rdnsResult := srv.rdnsChecker.Lookup(ctx, clientIP)
	if !rdnsResult.Valid {
		log().Warn("rDNS check failed",
			"client_ip", clientIP,
			"hostname", rdnsResult.Hostname,
			"error", rdnsResult.Error)
		return false
	}

	dnsblResults := srv.dnsblChecker.CheckIP(ctx, clientIP)
	for _, result := range dnsblResults {
		if result.Listed && srv.dnsblChecker.ShouldReject() {
			log().Warn("IP listed in DNSBL, rejecting connection",
				"client_ip", clientIP,
				"provider", result.Provider,
				"response_codes", result.ResponseCodes)
			return false
		}
	}

	return true
}

func (srv *Server) handleConnection(ctx context.Context, conn net.Conn, clientIP string) {
	defer srv.wg.Done()
	defer srv.untrackConnection(clientIP)
	defer conn.Close()

	log().Info("New connection accepted", "client_ip", clientIP)

	if !srv.performSecurityChecks(ctx, clientIP) {
		log().Warn("Connection rejected due to security checks", "client_ip", clientIP)
		return
	}

	// Set connection timeouts
	if srv.config.Server.ReadTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(srv.config.Server.ReadTimeout))
	}
	if srv.config.Server.WriteTimeout > 0 {
		conn.SetWriteDeadline(time.Now().Add(srv.config.Server.WriteTimeout))
	}

	// Create connection context for TCP
	connCtx := smtp.ConnectionContext{
		Type:     smtp.ConnectionTypeTCP,
		Port:     srv.config.Server.Port,
		TLS:      false, // TODO: detect TLS state
		ClientIP: clientIP,
	}

	// Create SMTP handler using factory
	textprotoConn := textproto.NewConn(conn)
	handler := smtp.NewSMTPHandler(connCtx, srv.config, textprotoConn, srv.smtpDeps)

	if err := handler.Handle(ctx); err != nil {
		log().Debug("SMTP session ended", "client_ip", clientIP, "error", err)
	} else {
		log().Debug("SMTP session completed successfully", "client_ip", clientIP)
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
