package queue

import (
	"time"
)

// RecipientType represents the type of recipient domain
type RecipientType string

const (
	RecipientLocal    RecipientType = "local"
	RecipientVirtual  RecipientType = "virtual"
	RecipientRelay    RecipientType = "relay"
	RecipientExternal RecipientType = "external"
)

// String returns the string representation of RecipientType
func (rt RecipientType) String() string {
	return string(rt)
}

// Message represents a message to be processed via channel
type Message struct {
	ID                   string
	From                 string
	ClientIP             string
	ClientHelloHostname  string
	LocalRecipients      map[string]struct{}
	VirtualRecipients    map[string]struct{}
	RelayRecipients      map[string]struct{}
	ExternalRecipients   map[string]struct{}
	MessageTotalSize     int64
	Created              time.Time
}

// TotalRecipients returns the total number of recipients across all types
func (m *Message) TotalRecipients() int {
	return len(m.LocalRecipients) + len(m.VirtualRecipients) + len(m.RelayRecipients) + len(m.ExternalRecipients)
}