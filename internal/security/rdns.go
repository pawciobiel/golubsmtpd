package security

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/config"
)

// RDNSChecker performs reverse DNS lookups with caching
type RDNSChecker struct {
	config *config.ReverseDNSConfig

	// Lock-free counters
	lookupCount int64
	failCount   int64
}

// RDNSResult contains the result of a reverse DNS lookup
type RDNSResult struct {
	IP       string
	Hostname string
	Valid    bool
	Error    error
}

// NewRDNSChecker creates a new reverse DNS checker
func NewRDNSChecker(cfg *config.ReverseDNSConfig) *RDNSChecker {
	return &RDNSChecker{
		config: cfg,
	}
}

// LookupWithTimeout performs a reverse DNS lookup with timeout
func (r *RDNSChecker) LookupWithTimeout(ctx context.Context, ip string, timeout time.Duration) *RDNSResult {
	if !r.config.Enabled {
		return &RDNSResult{
			IP:    ip,
			Valid: true, // Pass through if disabled
		}
	}

	atomic.AddInt64(&r.lookupCount, 1)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result := &RDNSResult{IP: ip}

	// Perform reverse DNS lookup
	hostnames, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		atomic.AddInt64(&r.failCount, 1)
		result.Error = err
		result.Valid = !r.config.RejectOnFail

		log().Debug("Reverse DNS lookup failed",
			"ip", ip,
			"error", err,
			"reject_on_fail", r.config.RejectOnFail)

		return result
	}

	if len(hostnames) == 0 {
		atomic.AddInt64(&r.failCount, 1)
		result.Valid = !r.config.RejectOnFail

		log().Debug("No reverse DNS hostname found",
			"ip", ip,
			"reject_on_fail", r.config.RejectOnFail)

		return result
	}

	// Use the first hostname returned
	hostname := hostnames[0]
	result.Hostname = hostname
	result.Valid = true

	log().Debug("Reverse DNS lookup successful",
		"ip", ip,
		"hostname", hostname)

	return result
}

// Lookup performs a reverse DNS lookup with default 5 second timeout
func (r *RDNSChecker) Lookup(ctx context.Context, ip string) *RDNSResult {
	return r.LookupWithTimeout(ctx, ip, 5*time.Second)
}

// GetStats returns lookup statistics
func (r *RDNSChecker) GetStats() (lookups, failures int64) {
	return atomic.LoadInt64(&r.lookupCount), atomic.LoadInt64(&r.failCount)
}

// IsEnabled returns whether reverse DNS checking is enabled
func (r *RDNSChecker) IsEnabled() bool {
	return r.config.Enabled
}
