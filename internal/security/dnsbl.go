package security

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/logging"
)

var log = logging.GetLogger

// DNSBLChecker performs DNSBL (DNS Blacklist) checks
type DNSBLChecker struct {
	config *config.DNSBLConfig

	// Lock-free counters
	checkCount   int64
	hitCount     int64
	providerHits map[string]*int64 // provider -> hit count
}

// DNSBLResult contains the result of a DNSBL check
type DNSBLResult struct {
	IP            string
	Domain        string
	Listed        bool
	Provider      string
	ResponseCodes []string
	Action        string // "reject" or "log"
	Error         error
}

// NewDNSBLChecker creates a new DNSBL checker
func NewDNSBLChecker(cfg *config.DNSBLConfig) *DNSBLChecker {
	checker := &DNSBLChecker{
		config:       cfg,
		providerHits: make(map[string]*int64),
	}

	// Initialize per-provider counters
	for _, provider := range cfg.Providers {
		checker.providerHits[provider] = new(int64)
	}

	return checker
}

// CheckIP performs DNSBL checks on an IP address
func (d *DNSBLChecker) CheckIP(ctx context.Context, ip string) []*DNSBLResult {
	if !d.config.Enabled || !d.config.CheckIP {
		return nil
	}

	atomic.AddInt64(&d.checkCount, 1)

	// Parse IP to ensure it's valid
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return []*DNSBLResult{{
			IP:     ip,
			Listed: false,
			Error:  fmt.Errorf("invalid IP address: %s", ip),
		}}
	}

	// TODO: add IPv6 DNSBL support
	if parsedIP.To4() == nil {
		log().Debug("Skipping DNSBL check for non-IPv4 address", "ip", ip)
		return nil
	}

	var results []*DNSBLResult

	// Check each DNSBL provider
	for _, provider := range d.config.Providers {
		result := d.checkIPAgainstProvider(ctx, ip, provider)
		if result != nil {
			results = append(results, result)
		}
	}

	return results
}

// CheckDomain performs DNSBL checks on a domain
func (d *DNSBLChecker) CheckDomain(ctx context.Context, domain string) []*DNSBLResult {
	if !d.config.Enabled || !d.config.CheckSenderDomain {
		return nil
	}

	atomic.AddInt64(&d.checkCount, 1)

	var results []*DNSBLResult

	// Check each DNSBL provider that supports domain checking
	for _, provider := range d.config.Providers {
		result := d.checkDomainAgainstProvider(ctx, domain, provider)
		if result != nil {
			results = append(results, result)
		}
	}

	return results
}

func (d *DNSBLChecker) checkIPAgainstProvider(ctx context.Context, ip string, provider string) *DNSBLResult {
	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Reverse the IP for DNSBL lookup (e.g., 1.2.3.4 -> 4.3.2.1)
	reversedIP := reverseIPv4(ip)
	if reversedIP == "" {
		return &DNSBLResult{
			IP:       ip,
			Provider: provider,
			Listed:   false,
			Error:    fmt.Errorf("failed to reverse IP: %s", ip),
		}
	}

	// Build DNSBL query (e.g., 4.3.2.1.zen.spamhaus.org)
	query := fmt.Sprintf("%s.%s", reversedIP, provider)

	// Perform DNS lookup
	addrs, err := net.DefaultResolver.LookupHost(ctx, query)
	if err != nil {
		// DNS lookup failure usually means the IP is not listed
		if isNotFoundError(err) {
			return &DNSBLResult{
				IP:       ip,
				Provider: provider,
				Listed:   false,
				Action:   d.config.Action,
			}
		}

		return &DNSBLResult{
			IP:       ip,
			Provider: provider,
			Listed:   false,
			Error:    fmt.Errorf("DNSBL lookup failed for %s: %w", query, err),
			Action:   d.config.Action,
		}
	}

	// IP is listed if we got any response
	if len(addrs) > 0 {
		atomic.AddInt64(&d.hitCount, 1)
		if counter, exists := d.providerHits[provider]; exists {
			atomic.AddInt64(counter, 1)
		}

		result := &DNSBLResult{
			IP:            ip,
			Provider:      provider,
			Listed:        true,
			ResponseCodes: addrs,
			Action:        d.config.Action,
		}

		log().Warn("IP found in DNSBL",
			"ip", ip,
			"provider", provider,
			"response_codes", addrs,
			"action", d.config.Action)

		return result
	}

	return &DNSBLResult{
		IP:       ip,
		Provider: provider,
		Listed:   false,
		Action:   d.config.Action,
	}
}

func (d *DNSBLChecker) checkDomainAgainstProvider(ctx context.Context, domain string, provider string) *DNSBLResult {
	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Build domain DNSBL query (e.g., example.com.dbl.spamhaus.org)
	query := fmt.Sprintf("%s.%s", domain, provider)

	// Perform DNS lookup
	addrs, err := net.DefaultResolver.LookupHost(ctx, query)
	if err != nil {
		// DNS lookup failure usually means the domain is not listed
		if isNotFoundError(err) {
			return &DNSBLResult{
				Domain:   domain,
				Provider: provider,
				Listed:   false,
				Action:   d.config.Action,
			}
		}

		return &DNSBLResult{
			Domain:   domain,
			Provider: provider,
			Listed:   false,
			Error:    fmt.Errorf("domain DNSBL lookup failed for %s: %w", query, err),
			Action:   d.config.Action,
		}
	}

	// Domain is listed if we got any response
	if len(addrs) > 0 {
		atomic.AddInt64(&d.hitCount, 1)
		if counter, exists := d.providerHits[provider]; exists {
			atomic.AddInt64(counter, 1)
		}

		result := &DNSBLResult{
			Domain:        domain,
			Provider:      provider,
			Listed:        true,
			ResponseCodes: addrs,
			Action:        d.config.Action,
		}

		log().Warn("Domain found in DNSBL",
			"domain", domain,
			"provider", provider,
			"response_codes", addrs,
			"action", d.config.Action)

		return result
	}

	return &DNSBLResult{
		Domain:   domain,
		Provider: provider,
		Listed:   false,
		Action:   d.config.Action,
	}
}

// reverseIPv4 reverses an IPv4 address for DNSBL lookup
// e.g., "192.168.1.1" -> "1.1.168.192"
func reverseIPv4(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}

	// Validate each part is a valid octet
	for _, part := range parts {
		if octet, err := strconv.Atoi(part); err != nil || octet < 0 || octet > 255 {
			return ""
		}
	}

	// Reverse the order
	return fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
}

// isNotFoundError checks if the error indicates DNS name not found
func isNotFoundError(err error) bool {
	if dnsErr, ok := err.(*net.DNSError); ok {
		return dnsErr.IsNotFound
	}
	return false
}

// GetStats returns DNSBL check statistics
func (d *DNSBLChecker) GetStats() (checks, hits int64, providerStats map[string]int64) {
	providerStats = make(map[string]int64)
	for provider, counter := range d.providerHits {
		providerStats[provider] = atomic.LoadInt64(counter)
	}
	return atomic.LoadInt64(&d.checkCount), atomic.LoadInt64(&d.hitCount), providerStats
}

// IsEnabled returns whether DNSBL checking is enabled
func (d *DNSBLChecker) IsEnabled() bool {
	return d.config.Enabled
}

// ShouldReject returns true if DNSBL hits should result in connection rejection
func (d *DNSBLChecker) ShouldReject() bool {
	return d.config.Action == "reject"
}
