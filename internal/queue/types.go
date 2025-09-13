package queue

import (
	"github.com/pawciobiel/golubsmtpd/internal/types"
)

// Re-export types for compatibility
type (
	Message      = types.Message
	MessageState = types.MessageState
)

const (
	MessageStateIncoming   = types.MessageStateIncoming
	MessageStateProcessing = types.MessageStateProcessing
	MessageStateFailed     = types.MessageStateFailed
	MessageStateDelivered  = types.MessageStateDelivered
)

// Re-export functions
var (
	GenerateID                  = types.GenerateID
	GetRequiredSpoolDirectories = types.GetRequiredSpoolDirectories
)
