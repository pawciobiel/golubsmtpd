package auth

import "strings"

// ExtractUsername extracts the local part from an email address
// Example: user@domain.com -> user
func ExtractUsername(email string) string {
	// Simple extraction: user@domain -> user
	for i, char := range email {
		if char == '@' {
			return email[:i]
		}
	}
	return "" // Invalid email format
}

// ExtractUsernameAndDomain extracts both parts from an email address
// Example: user@domain.com -> user, domain.com
func ExtractUsernameAndDomain(email string) (username, domain string) {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", "" // Invalid email format
}
