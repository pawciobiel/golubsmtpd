package smtp

import (
	"context"
	"os/user"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/aliases"
	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/delivery"
	"github.com/pawciobiel/golubsmtpd/internal/logging"
)

// RcptValidator handles RCPT TO recipient validation
type RcptValidator struct {
	config           *config.Config
	authenticator    auth.Authenticator
	systemCache      *LRUCache // Cache for system user lookups
	virtualCache     *LRUCache // Cache for virtual user lookups
	localAliasesMaps *aliases.LocalAliasesMaps
}

// NewRcptValidator creates a new RCPT TO validator
func NewRcptValidator(cfg *config.Config, authenticator auth.Authenticator, localAliasesMaps *aliases.LocalAliasesMaps) *RcptValidator {
	return &RcptValidator{
		config:           cfg,
		authenticator:    authenticator,
		systemCache:      NewLRUCache(cfg.Cache.SystemUsers.Capacity, cfg.Cache.SystemUsers.TTL),
		virtualCache:     NewLRUCache(cfg.Cache.VirtualUsers.Capacity, cfg.Cache.VirtualUsers.TTL),
		localAliasesMaps: localAliasesMaps,
	}
}

// IsRecipientValid validates recipient based on domain classification
func (r *RcptValidator) IsRecipientValid(ctx context.Context, recipient string, domainType delivery.RecipientType) bool {
	switch domainType {
	case delivery.RecipientLocal:
		return r.IsSystemUserEmailValid(ctx, recipient)
	case delivery.RecipientVirtual:
		return r.IsVirtualUserEmailValid(ctx, recipient)
	case delivery.RecipientRelay:
		return true // Accept relay recipients
	case delivery.RecipientExternal:
		return false // External recipients not accepted
	default:
		logging.GetLogger().Warn("Unknown recipient type", "recipient", recipient, "type", domainType)
		return false
	}
}

// IsSystemUserEmailValid checks if email corresponds to a valid system user
func (r *RcptValidator) IsSystemUserEmailValid(ctx context.Context, email string) bool {
	username := auth.ExtractUsername(email)

	// Check cache first
	if exists, found := r.systemCache.Get(username); found {
		logging.GetLogger().Debug("System user cache hit", "username", username, "exists", exists)
		return exists
	}

	// System lookup with timeout
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	resultChan := make(chan bool, 1)
	go func() {
		_, err := user.Lookup(username)
		resultChan <- err == nil
	}()

	select {
	case exists := <-resultChan:
		r.systemCache.Put(username, exists)
		logging.GetLogger().Debug("System user lookup", "username", username, "exists", exists)
		return exists
	case <-lookupCtx.Done():
		logging.GetLogger().Warn("System user lookup timeout", "username", username)
		return false
	}
}

// IsVirtualUserEmailValid checks if email is valid using auth plugins
func (r *RcptValidator) IsVirtualUserEmailValid(ctx context.Context, email string) bool {
	if cachedResult, found := r.virtualCache.Get(email); found {
		logging.GetLogger().Debug("Virtual user cache hit", "email", email, "exists", cachedResult)
		return cachedResult
	}

	exists := r.authenticator.ValidateUser(ctx, email)
	r.virtualCache.Put(email, exists)

	logging.GetLogger().Debug("Virtual user lookup", "email", email, "exists", exists)
	return exists
}

// ResolveLocalAlias resolves local aliases to actual recipients
func (r *RcptValidator) ResolveLocalAlias(alias string) []string {
	if r.localAliasesMaps == nil {
		return nil
	}
	return r.localAliasesMaps.ResolveAlias(alias)
}

// Close cleans up resources
func (r *RcptValidator) Close() error {
	r.systemCache.Close()
	r.virtualCache.Close()
	return nil
}
