package queue

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// MessageState represents the lifecycle state of a message in the spool system
type MessageState string

const (
	MessageStateIncoming   MessageState = "incoming"   // New messages from SMTP sessions
	MessageStateProcessing MessageState = "processing" // Messages being processed for delivery
	MessageStateFailed     MessageState = "failed"     // Failed delivery attempts
	MessageStateDelivered  MessageState = "delivered"  // Successfully delivered (archive)
)

// String returns the string representation of MessageState
func (ms MessageState) String() string {
	return string(ms)
}

// GetRequiredSpoolDirectories returns all required spool directory names
func GetRequiredSpoolDirectories() []MessageState {
	return []MessageState{
		MessageStateIncoming,
		MessageStateProcessing,
		MessageStateFailed,
		MessageStateDelivered,
	}
}

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
