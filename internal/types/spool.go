package types

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
