package auth

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pawciobiel/golubsmtpd/internal/config"
)

func TestMemoryAuthenticator_Aliases(t *testing.T) {
	cfg := map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{
				"username": "alice@example.com",
				"password": "pass123",
				"aliases": []interface{}{
					"alice@company.com",
					"a.smith@example.com",
				},
			},
			map[string]interface{}{
				"username": "bob@example.com",
				"password": "pass456",
			},
		},
	}

	auth, err := NewMemoryAuthenticatorFromConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Failed to create memory authenticator: %v", err)
	}
	defer auth.Close()

	memAuth := auth.(*MemoryAuthenticator)

	tests := []struct {
		name             string
		email            string
		expectedUsername string
		expectedFound    bool
	}{
		{
			name:             "primary username",
			email:            "alice@example.com",
			expectedUsername: "alice@example.com",
			expectedFound:    true,
		},
		{
			name:             "first alias",
			email:            "alice@company.com",
			expectedUsername: "alice@example.com",
			expectedFound:    true,
		},
		{
			name:             "second alias",
			email:            "a.smith@example.com",
			expectedUsername: "alice@example.com",
			expectedFound:    true,
		},
		{
			name:             "user without aliases",
			email:            "bob@example.com",
			expectedUsername: "bob@example.com",
			expectedFound:    true,
		},
		{
			name:             "non-existent email",
			email:            "nonexistent@example.com",
			expectedUsername: "",
			expectedFound:    false,
		},
		{
			name:             "empty string",
			email:            "",
			expectedUsername: "",
			expectedFound:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, found := memAuth.GetUsernameForEmail(tt.email)
			if found != tt.expectedFound {
				t.Errorf("Expected found=%v, got %v", tt.expectedFound, found)
			}
			if diff := cmp.Diff(tt.expectedUsername, username); diff != "" {
				t.Errorf("Username mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMemoryAuthenticator_DuplicateAlias(t *testing.T) {
	cfg := map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{
				"username": "alice@example.com",
				"password": "pass123",
				"aliases": []interface{}{
					"shared@example.com",
				},
			},
			map[string]interface{}{
				"username": "bob@example.com",
				"password": "pass456",
				"aliases": []interface{}{
					"shared@example.com",
				},
			},
		},
	}

	_, err := NewMemoryAuthenticatorFromConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("Expected error for duplicate alias")
	}

	expected := "memory plugin alias 'shared@example.com' already assigned to user 'alice@example.com', cannot assign to 'bob@example.com'"
	if diff := cmp.Diff(expected, err.Error()); diff != "" {
		t.Errorf("Error message mismatch (-want +got):\n%s", diff)
	}
}

func TestMemoryAuthenticator_AliasConflictsWithUsername(t *testing.T) {
	cfg := map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{
				"username": "alice@example.com",
				"password": "pass123",
			},
			map[string]interface{}{
				"username": "bob@example.com",
				"password": "pass456",
				"aliases": []interface{}{
					"alice@example.com",
				},
			},
		},
	}

	_, err := NewMemoryAuthenticatorFromConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("Expected error for alias conflicting with username")
	}

	expected := "memory plugin alias 'alice@example.com' conflicts with existing username"
	if diff := cmp.Diff(expected, err.Error()); diff != "" {
		t.Errorf("Error message mismatch (-want +got):\n%s", diff)
	}
}

func TestMemoryAuthenticator_EmptyAlias(t *testing.T) {
	cfg := map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{
				"username": "alice@example.com",
				"password": "pass123",
				"aliases": []interface{}{
					"",
				},
			},
		},
	}

	_, err := NewMemoryAuthenticatorFromConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("Expected error for empty alias")
	}

	expected := "memory plugin user 0 alias 0 cannot be empty"
	if diff := cmp.Diff(expected, err.Error()); diff != "" {
		t.Errorf("Error message mismatch (-want +got):\n%s", diff)
	}
}

func TestMemoryAuthenticator_InvalidAliasType(t *testing.T) {
	cfg := map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{
				"username": "alice@example.com",
				"password": "pass123",
				"aliases": []interface{}{
					123,
				},
			},
		},
	}

	_, err := NewMemoryAuthenticatorFromConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("Expected error for invalid alias type")
	}

	expected := "memory plugin user 0 alias 0 must be a string"
	if diff := cmp.Diff(expected, err.Error()); diff != "" {
		t.Errorf("Error message mismatch (-want +got):\n%s", diff)
	}
}

func TestMemoryAuthenticator_InvalidAliasesType(t *testing.T) {
	cfg := map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{
				"username": "alice@example.com",
				"password": "pass123",
				"aliases": "not a list",
			},
		},
	}

	_, err := NewMemoryAuthenticatorFromConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("Expected error for invalid aliases type")
	}

	expected := "memory plugin user 0 'aliases' must be a list"
	if diff := cmp.Diff(expected, err.Error()); diff != "" {
		t.Errorf("Error message mismatch (-want +got):\n%s", diff)
	}
}

func TestMemoryAuthenticator_NoAliases(t *testing.T) {
	cfg := map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{
				"username": "alice@example.com",
				"password": "pass123",
			},
		},
	}

	auth, err := NewMemoryAuthenticatorFromConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Failed to create memory authenticator: %v", err)
	}
	defer auth.Close()

	memAuth := auth.(*MemoryAuthenticator)

	if len(memAuth.emailToUsername) != 0 {
		t.Errorf("Expected empty emailToUsername map, got %d entries", len(memAuth.emailToUsername))
	}

	username, found := memAuth.GetUsernameForEmail("alice@example.com")
	if !found {
		t.Error("Expected to find alice@example.com")
	}
	expected := "alice@example.com"
	if diff := cmp.Diff(expected, username); diff != "" {
		t.Errorf("Username mismatch (-want +got):\n%s", diff)
	}
}

func TestMemoryAuthenticator_Authentication_WithAliases(t *testing.T) {
	cfg := map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{
				"username": "alice@example.com",
				"password": "pass123",
				"aliases": []interface{}{
					"alice@company.com",
				},
			},
		},
	}

	auth, err := NewMemoryAuthenticatorFromConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Failed to create memory authenticator: %v", err)
	}
	defer auth.Close()

	result := auth.Authenticate(context.Background(), "alice@example.com", "pass123")
	if !result.Success {
		t.Error("Expected authentication with primary username to succeed")
	}

	result = auth.Authenticate(context.Background(), "alice@company.com", "pass123")
	if result.Success {
		t.Error("Expected authentication with alias to fail (aliases are for MAIL FROM, not authentication)")
	}
}

func TestMemoryAuthenticator_ValidateUser_WithAliases(t *testing.T) {
	cfg := map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{
				"username": "alice@example.com",
				"password": "pass123",
				"aliases": []interface{}{
					"alice@company.com",
				},
			},
		},
	}

	auth, err := NewMemoryAuthenticatorFromConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Failed to create memory authenticator: %v", err)
	}
	defer auth.Close()

	if !auth.ValidateUser(context.Background(), "alice@example.com") {
		t.Error("Expected ValidateUser with primary username to succeed")
	}

	if auth.ValidateUser(context.Background(), "alice@company.com") {
		t.Error("Expected ValidateUser with alias to fail (aliases are for MAIL FROM, not RCPT TO)")
	}
}

func TestMemoryAuthenticator_NewMemoryAuthenticator_WithAliases(t *testing.T) {
	users := []config.UserConfig{
		{
			Username: "alice@example.com",
			Password: "pass123",
			Aliases:  []string{"alice@company.com", "a.smith@example.com"},
		},
		{
			Username: "bob@example.com",
			Password: "pass456",
			Aliases:  nil,
		},
	}

	auth, err := NewMemoryAuthenticator(context.Background(), users)
	if err != nil {
		t.Fatalf("Failed to create memory authenticator: %v", err)
	}
	defer auth.Close()

	username, found := auth.GetUsernameForEmail("alice@company.com")
	if !found {
		t.Error("Expected to find alias alice@company.com")
	}
	expected := "alice@example.com"
	if diff := cmp.Diff(expected, username); diff != "" {
		t.Errorf("Username mismatch (-want +got):\n%s", diff)
	}

	username, found = auth.GetUsernameForEmail("bob@example.com")
	if !found {
		t.Error("Expected to find bob@example.com")
	}
	expected = "bob@example.com"
	if diff := cmp.Diff(expected, username); diff != "" {
		t.Errorf("Username mismatch (-want +got):\n%s", diff)
	}
}
