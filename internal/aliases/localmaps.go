package aliases

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/user"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/logging"
)

var log = logging.GetLogger

// LocalAliasesMaps manages local domain aliases mapping from configured file
type LocalAliasesMaps struct {
	config  *config.Config
	aliases map[string][]string // alias -> pre-validated recipients
	mu      sync.RWMutex
}

// NewLocalAliasesMaps creates a new local aliases maps manager
func NewLocalAliasesMaps(cfg *config.Config) *LocalAliasesMaps {
	return &LocalAliasesMaps{
		config:  cfg,
		aliases: make(map[string][]string),
	}
}

// LoadAliasesMaps loads and validates aliases from the configured file at startup
func (lam *LocalAliasesMaps) LoadAliasesMaps(ctx context.Context) error {
	lam.mu.Lock()
	defer lam.mu.Unlock()

	filePath := lam.config.Server.LocalAliasesFilePath

	// Empty file path means no aliases configured
	if filePath == "" {
		lam.aliases = make(map[string][]string)
		log().Info("No local aliases file configured")
		return nil
	}

	// Check if file exists
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return fmt.Errorf("aliases file not found: %s", filePath)
	}
	if err != nil {
		return fmt.Errorf("failed to stat aliases file %s: %w", filePath, err)
	}

	// Add 3-second timeout for parsing
	parseCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Parse the file with timeout
	rawAliases, err := lam.parseAliasesFile(parseCtx, filePath)
	if err != nil {
		if parseCtx.Err() == context.DeadlineExceeded {
			panic(fmt.Sprintf("CRITICAL: Failed to parse aliases file %s within 3 seconds - file too large or I/O issues", filePath))
		}
		return fmt.Errorf("failed to parse aliases file: %w", err)
	}

	// Validate all aliases and their destinations
	validatedAliases := make(map[string][]string)
	for alias, destinations := range rawAliases {
		validDestinations := make([]string, 0, len(destinations))

		for _, dest := range destinations {
			username := auth.ExtractUsername(dest)

			// Validate destination user exists
			if _, err := user.Lookup(username); err == nil {
				validDestinations = append(validDestinations, dest)
			} else {
				// Log invalid destination but continue processing other destinations
				log().Warn("Invalid alias destination - user not found",
					"alias", alias,
					"destination", dest,
					"username", username)
			}
		}

		// Only include alias if it has at least one valid destination
		if len(validDestinations) > 0 {
			sort.Strings(validDestinations) // Consistent ordering
			validatedAliases[alias] = validDestinations
		} else {
			log().Warn("Alias has no valid destinations, skipping",
				"alias", alias,
				"file", filePath)
		}
	}

	// Warn about large files
	if len(rawAliases) > 1000 {
		log().Warn("Large aliases file detected",
			"file", filePath,
			"alias_count", len(rawAliases),
			"threshold", 1000)
	}

	lam.aliases = validatedAliases
	log().Info("Local aliases maps loaded successfully",
		"file", filePath,
		"total_aliases", len(rawAliases),
		"valid_aliases", len(validatedAliases))

	return nil
}

// parseAliasesFile parses /etc/aliases format file with timeout protection
func (lam *LocalAliasesMaps) parseAliasesFile(ctx context.Context, filePath string) (map[string][]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open aliases file: %w", err)
	}
	defer file.Close()

	aliases := make(map[string][]string)
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++

		// Check context cancellation/timeout every 10 lines for responsiveness
		if lineNum%10 == 0 {
			select {
			case <-ctx.Done():
				if ctx.Err() == context.DeadlineExceeded {
					return nil, fmt.Errorf("parsing timeout exceeded after %d lines", lineNum)
				}
				return nil, ctx.Err()
			default:
			}
		}

		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse alias line: alias: user1,user2,user3
		colonIndex := strings.Index(line, ":")
		if colonIndex == -1 {
			log().Debug("Invalid alias line format, skipping",
				"file", filePath,
				"line", lineNum,
				"content", line)
			continue
		}

		alias := strings.TrimSpace(line[:colonIndex])
		if alias == "" {
			log().Debug("Empty alias name, skipping",
				"file", filePath,
				"line", lineNum)
			continue
		}

		// Parse recipients (comma or space separated)
		recipientsPart := strings.TrimSpace(line[colonIndex+1:])
		if recipientsPart == "" {
			log().Debug("Empty alias recipients, skipping",
				"file", filePath,
				"line", lineNum,
				"alias", alias)
			continue
		}

		// Split by comma first, then by spaces
		var recipients []string
		for _, part := range strings.Split(recipientsPart, ",") {
			for _, recipient := range strings.Fields(strings.TrimSpace(part)) {
				recipient = strings.TrimSpace(recipient)
				if recipient != "" {
					// Ensure recipient is properly formatted as email
					if !strings.Contains(recipient, "@") {
						recipient = recipient + "@localhost"
					}
					recipients = append(recipients, recipient)
				}
			}
		}

		if len(recipients) > 0 {
			aliases[alias] = recipients
			log().Debug("Parsed alias",
				"alias", alias,
				"recipients", recipients)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading aliases file at line %d: %w", lineNum, err)
	}

	return aliases, nil
}

// ResolveAlias resolves an alias to its pre-validated recipients (fast lookup)
func (lam *LocalAliasesMaps) ResolveAlias(alias string) []string {
	lam.mu.RLock()
	defer lam.mu.RUnlock()

	recipients, exists := lam.aliases[alias]
	if !exists {
		return nil
	}

	// Return a copy to prevent external modification
	result := make([]string, len(recipients))
	copy(result, recipients)
	return result
}

// RefreshAliasesMaps reloads aliases from file (future functionality)
func (lam *LocalAliasesMaps) RefreshAliasesMaps(ctx context.Context) error {
	return lam.LoadAliasesMaps(ctx)
}