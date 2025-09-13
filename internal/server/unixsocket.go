package server

import (
	"context"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/pawciobiel/golubsmtpd/internal/smtp"
)

// startSocketListener creates and starts the Unix domain socket listener
func (srv *Server) startSocketListener(ctx context.Context) error {
	socketPath := srv.config.Server.SocketPath
	if socketPath == "" {
		srv.logger.Info("Unix domain socket disabled (no socket_path configured)")
		return nil
	}

	// Create directory if it doesn't exist
	socketDir := filepath.Dir(socketPath)
	if err := os.MkdirAll(socketDir, 0o755); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Remove existing socket file if it exists
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing socket file: %w", err)
	}

	// Create Unix domain socket
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to create Unix domain socket at %s: %w", socketPath, err)
	}

	srv.socketListen = listener

	// Set socket permissions (666) - allow all users like Postfix
	if err := os.Chmod(socketPath, 0o666); err != nil {
		listener.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	// Keep current ownership (don't force mail group)
	srv.logger.Debug("Socket permissions set to 666 (all users can access)")

	srv.logger.Info("Unix domain socket listener started", "socket_path", socketPath)

	// Start accepting socket connections
	srv.wg.Add(1)
	go srv.socketAcceptLoop(ctx)

	return nil
}

// socketAcceptLoop accepts connections on the Unix domain socket
func (srv *Server) socketAcceptLoop(ctx context.Context) {
	defer srv.wg.Done()
	defer func() {
		if srv.socketListen != nil {
			srv.socketListen.Close()
			// Clean up socket file
			if socketPath := srv.config.Server.SocketPath; socketPath != "" {
				os.Remove(socketPath)
			}
		}
	}()

	for {
		select {
		case <-srv.shutdown:
			return
		default:
		}

		conn, err := srv.socketListen.Accept()
		if err != nil {
			select {
			case <-srv.shutdown:
				return
			default:
				srv.logger.Error("Failed to accept socket connection", "error", err)
				continue
			}
		}

		srv.wg.Add(1)
		go srv.handleSocketConnection(ctx, conn)
	}
}

// handleSocketConnection handles a single Unix domain socket connection
func (srv *Server) handleSocketConnection(ctx context.Context, conn net.Conn) {
	defer srv.wg.Done()
	defer conn.Close()

	srv.logger.Debug("New socket connection accepted")

	// Get peer credentials (UID, GID, PID) from Unix socket
	credentials, err := srv.getSocketCredentials(conn)
	if err != nil {
		srv.logger.Error("Failed to get socket credentials", "error", err)
		return
	}

	srv.logger.Debug("Socket connection credentials",
		"uid", credentials.UID,
		"gid", credentials.GID,
		"pid", credentials.PID)

	// Validate the connecting process
	if !srv.isSocketConnectionValid(credentials) {
		srv.logger.Warn("Socket connection validation failed")
		return
	}

	// Create connection context for socket - convert credentials
	smtpCreds := &smtp.SocketCredentials{
		UID: credentials.UID,
		GID: credentials.GID,
		PID: credentials.PID,
	}

	connCtx := smtp.ConnectionContext{
		Type:        smtp.ConnectionTypeSocket,
		Credentials: smtpCreds,
	}

	// Create SMTP handler using factory
	textprotoConn := textproto.NewConn(conn)
	handler := smtp.NewSMTPHandler(connCtx, srv.config, srv.logger, textprotoConn, srv.authenticator, srv.queue)

	if err := handler.Handle(ctx); err != nil {
		srv.logger.Debug("Socket SMTP session ended", "error", err)
	} else {
		srv.logger.Debug("Socket SMTP session completed successfully")
	}
}

// SocketCredentials represents Unix socket peer credentials
type SocketCredentials struct {
	UID int // User ID
	GID int // Group ID
	PID int // Process ID
}

// getSocketCredentials retrieves peer credentials from Unix socket
func (srv *Server) getSocketCredentials(conn net.Conn) (*SocketCredentials, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("connection is not a Unix socket")
	}

	// Get raw connection file descriptor
	file, err := unixConn.File()
	if err != nil {
		return nil, fmt.Errorf("failed to get connection file: %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	// Get peer credentials using SO_PEERCRED
	ucred, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return nil, fmt.Errorf("failed to get peer credentials: %w", err)
	}

	return &SocketCredentials{
		UID: int(ucred.Uid),
		GID: int(ucred.Gid),
		PID: int(ucred.Pid),
	}, nil
}

// isSocketConnectionValid validates the connecting process and user
func (srv *Server) isSocketConnectionValid(creds *SocketCredentials) bool {
	// Check if user is in trusted users list
	username, err := srv.getUsernameFromUID(creds.UID)
	if err != nil {
		srv.logger.Error("Failed to get username for UID", "uid", creds.UID, "error", err)
		return false
	}

	// For now, allow all users - sender validation will happen in SMTP session
	// This allows regular users to connect, but they'll be restricted in MAIL FROM
	srv.logger.Debug("Socket connection from user", "username", username, "uid", creds.UID)

	return true
}

// getUsernameFromUID converts UID to username
func (srv *Server) getUsernameFromUID(uid int) (string, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// isTrustedUser checks if a user is in the trusted users list
func (srv *Server) isTrustedUser(username string) bool {
	for _, trustedUser := range srv.config.Server.TrustedUsers {
		if trustedUser == username {
			return true
		}
	}
	return false
}
