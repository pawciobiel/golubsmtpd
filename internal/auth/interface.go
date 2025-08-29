package auth

import "context"

// AuthResult represents the result of an authentication attempt
type AuthResult struct {
	Success  bool
	Username string
	Error    error
}

// Authenticator defines the interface for authentication plugins
type Authenticator interface {
	// Authenticate verifies username and password for SMTP AUTH
	Authenticate(ctx context.Context, username, password string) *AuthResult

	// ValidateUser checks if a user/email exists for RCPT TO validation
	ValidateUser(ctx context.Context, email string) bool

	// Name returns the plugin name
	Name() string

	// Close cleans up resources
	Close() error
}

// Registry manages authentication plugins using generics for type safety
type Registry[T Authenticator] struct {
	plugins map[string]T
}

// NewRegistry creates a new plugin registry
func NewRegistry[T Authenticator]() *Registry[T] {
	return &Registry[T]{
		plugins: make(map[string]T),
	}
}

// Register adds a plugin to the registry
func (r *Registry[T]) Register(name string, plugin T) {
	r.plugins[name] = plugin
}

// Get retrieves a plugin by name
func (r *Registry[T]) Get(name string) (T, bool) {
	plugin, exists := r.plugins[name]
	return plugin, exists
}

// List returns all registered plugin names
func (r *Registry[T]) List() []string {
	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	return names
}
