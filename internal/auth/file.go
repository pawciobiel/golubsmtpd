package auth

import (
	"bufio"
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
)

// FileAuthenticator implements file-based authentication with streaming reads
type FileAuthenticator struct {
	filePath     string
	logger       *slog.Logger
	authCount    int64 // authentication attempts (atomic)
	successCount int64 // successful authentications (atomic)
}

// NewFileAuthenticator creates a new file-based authenticator
func NewFileAuthenticator(ctx context.Context, filePath string, logger *slog.Logger) (*FileAuthenticator, error) {
	auth := &FileAuthenticator{
		filePath: filePath,
		logger:   logger,
	}

	// Check context before file operations
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Verify file exists and is readable
	if _, err := os.Stat(filePath); err != nil {
		return nil, fmt.Errorf("auth file not accessible: %w", err)
	}

	return auth, nil
}

// Authenticate verifies username and password by streaming through the file
func (f *FileAuthenticator) Authenticate(ctx context.Context, username, password string) *AuthResult {
	atomic.AddInt64(&f.authCount, 1)

	if username == "" || password == "" {
		return &AuthResult{
			Success: false,
			Error:   fmt.Errorf("username and password required"),
		}
	}

	file, err := os.Open(f.filePath)
	if err != nil {
		f.logger.Error("Failed to open auth file", "error", err)
		return &AuthResult{
			Success: false,
			Error:   fmt.Errorf("authentication unavailable"),
		}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++

		// Check for context cancellation
		select {
		case <-ctx.Done():
			return &AuthResult{
				Success: false,
				Error:   ctx.Err(),
			}
		default:
		}

		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse username:password format
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		fileUsername := strings.TrimSpace(parts[0])
		filePassword := strings.TrimSpace(parts[1])

		// Check if this is the user we're looking for
		if fileUsername == username {
			// Constant-time password comparison to prevent timing attacks
			if subtle.ConstantTimeCompare([]byte(password), []byte(filePassword)) == 1 {
				atomic.AddInt64(&f.successCount, 1)
				f.logger.Info("Authentication successful", "username", username)
				return &AuthResult{
					Success:  true,
					Username: username,
				}
			} else {
				f.logger.Debug("Authentication failed: invalid password", "username", username)
				return &AuthResult{Success: false}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		f.logger.Error("Error reading auth file", "error", err)
		return &AuthResult{
			Success: false,
			Error:   fmt.Errorf("authentication error"),
		}
	}

	f.logger.Debug("Authentication failed: user not found", "username", username)
	return &AuthResult{Success: false}
}

// Name returns the plugin name
func (f *FileAuthenticator) Name() string {
	return "file"
}

// Close cleans up resources
func (f *FileAuthenticator) Close() error {
	return nil
}

// GetStats returns authentication statistics
func (f *FileAuthenticator) GetStats() (attempts, successes int64) {
	return atomic.LoadInt64(&f.authCount), atomic.LoadInt64(&f.successCount)
}

// NewFileAuthenticatorFromConfig creates a file authenticator from configuration
func NewFileAuthenticatorFromConfig(ctx context.Context, config map[string]interface{}, logger *slog.Logger) (Authenticator, error) {
	pathInterface, exists := config["users_file"]
	if !exists {
		return nil, fmt.Errorf("file plugin requires 'users_file' parameter")
	}

	path, ok := pathInterface.(string)
	if !ok {
		return nil, fmt.Errorf("file plugin 'users_file' must be a string")
	}

	return NewFileAuthenticator(ctx, path, logger)
}
