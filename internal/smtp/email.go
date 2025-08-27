package smtp

import (
	"context"
	"fmt"
	"net"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/config"
)

const (
	// MaxEmailLength limits email address length in characters to prevent DoS (RFC 5321)
	MaxEmailLength = 254
	// MaxLocalLength limits local part length in characters (RFC 5321)
	MaxLocalLength = 64
	// MaxDomainLength limits domain part length in characters (RFC 5321)
	MaxDomainLength = 253
	// DNSTimeout is the timeout for DNS lookups
	DNSTimeout = 5 * time.Second
)

// Email validation types
const (
	ValidationBasic    = "basic"
	ValidationExtended = "extended"
	ValidationDNS_MX   = "dns_mx"
	ValidationDNS_A    = "dns_a"
)

// FQDN regex - validates domain format including ccTLDs like .co.uk
var fqdnRegex = regexp.MustCompile(`^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,}|[a-zA-Z0-9-]{2,}\.[a-zA-Z]{2,}))$`)

// EmailAddress represents a parsed email address
type EmailAddress struct {
	Local  string // local part (before @)
	Domain string // domain part (after @)
	Full   string // complete address
}

// EmailValidator handles email address validation with configurable validation pipeline
type EmailValidator struct {
	config *config.Config
}

// NewEmailValidator creates a new email validator with configuration
func NewEmailValidator(cfg *config.Config) *EmailValidator {
	return &EmailValidator{config: cfg}
}

// hasValidationType checks if a validation type is enabled in the configuration
func (v *EmailValidator) hasValidationType(validationType string) bool {
	for _, vType := range v.config.Server.EmailValidation {
		if vType == validationType {
			return true
		}
	}
	return false
}

// ParseEmailAddress parses and validates an email address using the configured validation pipeline
func (v *EmailValidator) ParseEmailAddress(email string) (*EmailAddress, error) {
	if len(email) == 0 {
		return nil, fmt.Errorf("email address cannot be empty")
	}

	if len(email) > MaxEmailLength {
		return nil, fmt.Errorf("email address too long: %d characters (max %d)", len(email), MaxEmailLength)
	}

	// Remove surrounding angle brackets if present
	email = strings.Trim(email, "<>")
	email = strings.TrimSpace(email)

	// Basic validation using Go's standard library (RFC 5322 compliant)
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email format: %w", err)
	}

	// Split on @ symbol for additional validation
	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid email format: must contain exactly one @")
	}

	local := parts[0]
	domain := parts[1]

	// Validate lengths per RFC 5321
	if len(local) > MaxLocalLength {
		return nil, fmt.Errorf("local part too long: %d characters (max %d)", len(local), MaxLocalLength)
	}

	if len(domain) > MaxDomainLength {
		return nil, fmt.Errorf("domain part too long: %d characters (max %d)", len(domain), MaxDomainLength)
	}

	// Run configured validation pipeline (each type only once)
	if v.hasValidationType(ValidationExtended) {
		if err := v.extendedValidation(addr.Address, domain); err != nil {
			return nil, fmt.Errorf("extended validation failed: %w", err)
		}
	}

	if v.hasValidationType(ValidationDNS_MX) {
		if err := v.validateMXRecord(domain); err != nil {
			return nil, fmt.Errorf("MX record validation failed: %w", err)
		}
	}

	if v.hasValidationType(ValidationDNS_A) {
		if err := v.validateARecord(domain); err != nil {
			return nil, fmt.Errorf("A record validation failed: %w", err)
		}
	}

	return &EmailAddress{
		Local:  local,
		Domain: domain,
		Full:   addr.Address,
	}, nil
}

// extendedValidation performs additional email format validation
func (v *EmailValidator) extendedValidation(email, domain string) error {
	// Check for consecutive dots
	if strings.Contains(email, "..") {
		return fmt.Errorf("consecutive dots not allowed")
	}

	// Check email doesn't start or end with dot
	if strings.HasPrefix(email, ".") || strings.HasSuffix(email, ".") {
		return fmt.Errorf("email cannot start or end with dot")
	}

	// Check domain has at least one dot (TLD)
	if !strings.Contains(domain, ".") {
		return fmt.Errorf("domain must contain at least one dot")
	}

	// Validate FQDN format (including ccTLDs like .co.uk)
	if !fqdnRegex.MatchString(domain) {
		return fmt.Errorf("invalid domain format: %s", domain)
	}

	// Check for valid characters in local part
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		localPart := parts[0]
		if strings.HasPrefix(localPart, ".") || strings.HasSuffix(localPart, ".") {
			return fmt.Errorf("local part cannot start or end with dot")
		}
	}

	// TODO: Add github.com/go-playground/validator integration here if available
	// This could be done conditionally with build tags or runtime detection

	return nil
}

// validateMXRecord checks if the domain has valid MX records
func (v *EmailValidator) validateMXRecord(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), DNSTimeout)
	defer cancel()

	// Create a custom resolver with timeout
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: DNSTimeout,
			}
			return d.DialContext(ctx, network, address)
		},
	}

	mxRecords, err := resolver.LookupMX(ctx, domain)
	if err != nil {
		return fmt.Errorf("MX lookup failed for domain %s: %w", domain, err)
	}

	if len(mxRecords) == 0 {
		return fmt.Errorf("no MX records found for domain %s", domain)
	}

	return nil
}

// validateARecord checks if the domain has valid A/AAAA records
func (v *EmailValidator) validateARecord(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), DNSTimeout)
	defer cancel()

	// Create a custom resolver with timeout
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: DNSTimeout,
			}
			return d.DialContext(ctx, network, address)
		},
	}

	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return fmt.Errorf("A/AAAA lookup failed for domain %s: %w", domain, err)
	}

	if len(ips) == 0 {
		return fmt.Errorf("no A/AAAA records found for domain %s", domain)
	}

	return nil
}

// ParseMailFromCommand parses a MAIL FROM command and extracts the email address
func (v *EmailValidator) ParseMailFromCommand(args []string) (*EmailAddress, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("MAIL FROM requires an email address")
	}

	// Join all args in case there are spaces
	fullArg := strings.Join(args, " ")

	// Remove "FROM:" prefix if present
	if strings.HasPrefix(strings.ToUpper(fullArg), "FROM:") {
		fullArg = fullArg[5:]
	}

	fullArg = strings.TrimSpace(fullArg)

	if fullArg == "" {
		return nil, fmt.Errorf("MAIL FROM requires an email address")
	}

	return v.ParseEmailAddress(fullArg)
}

// ParseRcptToCommand parses a RCPT TO command and extracts the email address
func (v *EmailValidator) ParseRcptToCommand(args []string) (*EmailAddress, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("RCPT TO requires an email address")
	}

	// Join all args in case there are spaces
	fullArg := strings.Join(args, " ")

	// Remove "TO:" prefix if present
	if strings.HasPrefix(strings.ToUpper(fullArg), "TO:") {
		fullArg = fullArg[3:]
	}

	fullArg = strings.TrimSpace(fullArg)

	if fullArg == "" {
		return nil, fmt.Errorf("RCPT TO requires an email address")
	}

	return v.ParseEmailAddress(fullArg)
}
