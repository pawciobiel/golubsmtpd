package delivery

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

// DeliveryResult represents the outcome of a delivery attempt for a specific recipient type
type DeliveryResult struct {
	Type       RecipientType
	Successful []string
	Failed     []string
}

// DeliveryOutcome represents the result of a single delivery attempt
type DeliveryOutcome struct {
	Recipient string
	Success   bool
}
