package types

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Message represents a message to be processed via channel
type Message struct {
	ID                  string
	From                string
	ClientIP            string
	ClientHelloHostname string
	LocalRecipients     map[string]struct{}
	VirtualRecipients   map[string]struct{}
	RelayRecipients     map[string]struct{}
	ExternalRecipients  map[string]struct{}
	TotalSize           int64
	Created             time.Time
}

// TotalRecipients returns the total number of recipients across all types
func (m *Message) TotalRecipients() int {
	return len(m.LocalRecipients) + len(m.VirtualRecipients) + len(m.RelayRecipients) + len(m.ExternalRecipients)
}

// Filename generates the standardized filename for this message
func (m *Message) Filename() string {
	timestamp := m.Created.Format("20060102T150405Z")
	return fmt.Sprintf("%s.%s.eml", timestamp, m.ID)
}

// GenerateID creates a new unique message ID without hyphens
func GenerateID() string {
	return strings.ReplaceAll(uuid.New().String(), "-", "")
}
