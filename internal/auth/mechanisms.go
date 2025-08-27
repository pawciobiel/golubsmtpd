package auth

import (
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	// MaxAuthDataSize limits the raw base64 input size to prevent DoS (1KB)
	MaxAuthDataSize = 1024
	// MaxDecodedSize limits the decoded data size (768 bytes)
	MaxDecodedSize = 768
)

// ValidateAuthInput performs common validation on authentication input
func ValidateAuthInput(input string) error {
	if len(input) > MaxAuthDataSize {
		return fmt.Errorf("authentication data too large: %d bytes (max %d)",
			len(input), MaxAuthDataSize)
	}
	return nil
}

// ValidateDecodedData checks the size of decoded authentication data
func ValidateDecodedData(data []byte) error {
	if len(data) > MaxDecodedSize {
		return fmt.Errorf("decoded authentication data too large: %d bytes (max %d)",
			len(data), MaxDecodedSize)
	}
	return nil
}

// DecodePlain decodes PLAIN SASL mechanism data
// Format: [authzid] NUL authcid NUL passwd
func DecodePlain(encoded string) (username, password string, err error) {
	if err := ValidateAuthInput(encoded); err != nil {
		return "", "", err
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", fmt.Errorf("invalid base64 encoding: %w", err)
	}

	if err := ValidateDecodedData(decoded); err != nil {
		return "", "", err
	}

	parts := strings.Split(string(decoded), "\x00")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid PLAIN format: expected 3 parts, got %d", len(parts))
	}

	// parts[0] is authorization identity (usually empty)
	// parts[1] is authentication identity (username)
	// parts[2] is password
	username = parts[1]
	password = parts[2]

	if username == "" {
		return "", "", fmt.Errorf("username cannot be empty")
	}

	return username, password, nil
}

// EncodeBase64 encodes a string in base64 for AUTH responses
func EncodeBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// DecodeBase64 decodes a base64 string for AUTH commands with size limits
func DecodeBase64(s string) (string, error) {
	if err := ValidateAuthInput(s); err != nil {
		return "", err
	}

	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("invalid base64 encoding: %w", err)
	}

	if err := ValidateDecodedData(decoded); err != nil {
		return "", err
	}

	return string(decoded), nil
}
