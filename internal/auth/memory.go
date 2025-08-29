package auth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/pawciobiel/golubsmtpd/internal/config"
)

// MemoryAuthenticator implements in-memory authentication
type MemoryAuthenticator struct {
	logger       *slog.Logger
	users        map[string]string // username -> password
	authCount    int64             // authentication attempts (atomic)
	successCount int64             // successful authentications (atomic)
}

// NewMemoryAuthenticator creates a new in-memory authenticator
func NewMemoryAuthenticator(ctx context.Context, users []config.UserConfig, logger *slog.Logger) (*MemoryAuthenticator, error) {
	// Check context before processing
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if len(users) == 0 {
		return nil, fmt.Errorf("no users configured for memory authenticator")
	}

	userMap := make(map[string]string)
	for _, user := range users {
		if user.Username == "" {
			return nil, fmt.Errorf("username cannot be empty")
		}
		userMap[user.Username] = user.Password
	}

	auth := &MemoryAuthenticator{
		logger: logger,
		users:  userMap,
	}

	logger.Info("Memory authenticator initialized", "user_count", len(users))
	return auth, nil
}

// Authenticate verifies username and password against in-memory users
func (m *MemoryAuthenticator) Authenticate(ctx context.Context, username, password string) *AuthResult {
	atomic.AddInt64(&m.authCount, 1)

	if username == "" || password == "" {
		return &AuthResult{
			Success: false,
			Error:   fmt.Errorf("username and password required"),
		}
	}

	storedPassword, exists := m.users[username]
	if !exists {
		m.logger.Debug("Authentication failed: user not found",
			"username", username)
		return &AuthResult{Success: false}
	}

	// Constant-time password comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(password), []byte(storedPassword)) == 1 {
		atomic.AddInt64(&m.successCount, 1)
		m.logger.Info("Authentication successful", "username", username)
		return &AuthResult{
			Success:  true,
			Username: username,
		}
	}

	m.logger.Debug("Authentication failed: invalid password", "username", username)
	return &AuthResult{Success: false}
}

// ValidateUser checks if a user/email exists for RCPT TO validation
func (m *MemoryAuthenticator) ValidateUser(ctx context.Context, email string) bool {
	if email == "" {
		return false
	}

	// Direct lookup using full email as username
	_, exists := m.users[email]
	if exists {
		m.logger.Debug("User validation successful", "email", email, "plugin", "memory")
	} else {
		m.logger.Debug("User validation failed: user not found", "email", email, "plugin", "memory")
	}
	
	return exists
}

// Name returns the plugin name
func (m *MemoryAuthenticator) Name() string {
	return "memory"
}

// Close cleans up resources
func (m *MemoryAuthenticator) Close() error {
	return nil
}

// GetStats returns authentication statistics
func (m *MemoryAuthenticator) GetStats() (attempts, successes int64) {
	return atomic.LoadInt64(&m.authCount), atomic.LoadInt64(&m.successCount)
}

// GetUserCount returns the number of configured users
func (m *MemoryAuthenticator) GetUserCount() int {
	return len(m.users)
}

// NewMemoryAuthenticatorFromConfig creates a memory authenticator from configuration
func NewMemoryAuthenticatorFromConfig(ctx context.Context, config map[string]interface{}, logger *slog.Logger) (Authenticator, error) {
	// Check context before processing
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	usersInterface, exists := config["users"]
	if !exists {
		return nil, fmt.Errorf("memory plugin requires 'users' parameter")
	}

	usersSlice, ok := usersInterface.([]interface{})
	if !ok {
		return nil, fmt.Errorf("memory plugin 'users' must be a list")
	}

	if len(usersSlice) == 0 {
		return nil, fmt.Errorf("no users configured for memory authenticator")
	}

	userMap := make(map[string]string)
	for i, userInterface := range usersSlice {
		userConfig, ok := userInterface.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("memory plugin user %d must be an object", i)
		}

		usernameInterface, exists := userConfig["username"]
		if !exists {
			return nil, fmt.Errorf("memory plugin user %d missing 'username'", i)
		}

		username, ok := usernameInterface.(string)
		if !ok {
			return nil, fmt.Errorf("memory plugin user %d 'username' must be a string", i)
		}

		if username == "" {
			return nil, fmt.Errorf("memory plugin user %d username cannot be empty", i)
		}

		passwordInterface, exists := userConfig["password"]
		if !exists {
			return nil, fmt.Errorf("memory plugin user %d missing 'password'", i)
		}

		password, ok := passwordInterface.(string)
		if !ok {
			return nil, fmt.Errorf("memory plugin user %d 'password' must be a string", i)
		}

		userMap[username] = password
	}

	auth := &MemoryAuthenticator{
		logger: logger,
		users:  userMap,
	}

	logger.Info("Memory authenticator initialized", "user_count", len(userMap))
	return auth, nil
}
