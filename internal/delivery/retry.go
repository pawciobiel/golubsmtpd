package delivery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const retryDirName = "retry"

// RetryState tracks retry metadata for a single outbound message.
type RetryState struct {
	MessageID  string            `json:"message_id"`
	From       string            `json:"from"`
	Created    time.Time         `json:"created"`
	NextRetry  time.Time         `json:"next_retry"`
	Attempts   int               `json:"attempts"`
	Recipients map[string]string `json:"recipients"` // addr -> "pending"|"ok"|"tempfail"|"permfail"|"expired"
}

// RetryStatePath returns the path to the retry metadata file for a message.
func RetryStatePath(spoolDir, messageID string) string {
	return filepath.Join(spoolDir, retryDirName, messageID+".json")
}

// LoadRetryState reads retry state from disk. Returns nil, nil if not found.
func LoadRetryState(spoolDir, messageID string) (*RetryState, error) {
	data, err := os.ReadFile(RetryStatePath(spoolDir, messageID))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read retry state for %s: %w", messageID, err)
	}
	var state RetryState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse retry state for %s: %w", messageID, err)
	}
	return &state, nil
}

// SaveRetryState writes retry state atomically to disk.
func SaveRetryState(spoolDir string, state *RetryState) error {
	dir := filepath.Join(spoolDir, retryDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create retry dir: %w", err)
	}
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal retry state: %w", err)
	}
	path := RetryStatePath(spoolDir, state.MessageID)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("failed to write retry state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("failed to commit retry state: %w", err)
	}
	return nil
}

// DeleteRetryState removes the retry metadata file for a message.
func DeleteRetryState(spoolDir, messageID string) error {
	err := os.Remove(RetryStatePath(spoolDir, messageID))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete retry state for %s: %w", messageID, err)
	}
	return nil
}

// NewRetryState creates initial retry state for a message.
func NewRetryState(messageID, from string, retryInterval time.Duration, recipients []string) *RetryState {
	now := time.Now().UTC()
	recips := make(map[string]string, len(recipients))
	for _, r := range recipients {
		recips[r] = "pending"
	}
	return &RetryState{
		MessageID:  messageID,
		From:       from,
		Created:    now,
		NextRetry:  now.Add(retryInterval),
		Attempts:   0,
		Recipients: recips,
	}
}

// RecordAttempt updates state from a DeliveryResult and returns whether any recipients
// still need retrying. Marks expired recipients when max age is exceeded.
func (s *RetryState) RecordAttempt(result DeliveryResult, retryInterval, maxAge time.Duration) (shouldRetry bool) {
	s.Attempts++

	for _, addr := range result.Successful {
		s.Recipients[addr] = "ok"
	}
	for _, addr := range result.TempFailed {
		s.Recipients[addr] = "tempfail"
	}
	for _, addr := range result.PermFailed {
		s.Recipients[addr] = "permfail"
	}

	if time.Since(s.Created) >= maxAge {
		for addr, status := range s.Recipients {
			if status == "pending" || status == "tempfail" {
				s.Recipients[addr] = "expired"
			}
		}
		return false
	}

	for _, status := range s.Recipients {
		if status == "pending" || status == "tempfail" {
			s.NextRetry = time.Now().UTC().Add(retryInterval)
			return true
		}
	}
	return false
}

// PendingRecipients returns addresses that still need delivery attempts.
func (s *RetryState) PendingRecipients() map[string]struct{} {
	pending := make(map[string]struct{})
	for addr, status := range s.Recipients {
		if status == "pending" || status == "tempfail" {
			pending[addr] = struct{}{}
		}
	}
	return pending
}

// BounceRecipients returns addresses that need a DSN (permfail or retry-expired).
func (s *RetryState) BounceRecipients() []string {
	var addrs []string
	for addr, status := range s.Recipients {
		if status == "permfail" || status == "expired" {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}
