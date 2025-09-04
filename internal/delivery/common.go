package delivery

import (
	"context"
)

// DeliverFunc represents a function that delivers a message to a single recipient
type DeliverFunc func(ctx context.Context, recipient string) error

// DeliverWithWorkers orchestrates concurrent delivery using semaphore-limited goroutines
// This eliminates boilerplate code common to all delivery types
func DeliverWithWorkers(
	ctx context.Context,
	recipients map[string]struct{},
	maxWorkers int,
	recipientType RecipientType,
	deliverFunc DeliverFunc,
) DeliveryResult {
	result := DeliveryResult{
		Type:       recipientType,
		Successful: make([]string, 0, len(recipients)),
		Failed:     make([]string, 0),
	}

	if len(recipients) == 0 {
		return result
	}

	// Limit workers to actual number of recipients - no point having 10 workers for 1 recipient
	if maxWorkers > len(recipients) {
		maxWorkers = len(recipients)
	}

	// Create semaphore and result collection
	sem := make(chan struct{}, maxWorkers)
	resultChan := make(chan DeliveryOutcome, len(recipients))

	// Launch one goroutine per recipient, limited by semaphore
	for recipient := range recipients {
		sem <- struct{}{} // Acquire semaphore BEFORE spawning goroutine
		go func(recipient string) {
			defer func() { <-sem }() // Release semaphore

			err := deliverFunc(ctx, recipient)
			resultChan <- DeliveryOutcome{Recipient: recipient, Success: err == nil}
		}(recipient)
	}

	// Collect exactly the number of results we expect
	for i := 0; i < len(recipients); i++ {
		outcome := <-resultChan
		if outcome.Success {
			result.Successful = append(result.Successful, outcome.Recipient)
		} else {
			result.Failed = append(result.Failed, outcome.Recipient)
		}
	}

	return result
}

// GetMaxWorkers calculates the effective max workers with sensible defaults
func GetMaxWorkers(configuredMax int, recipientCount int) int {
	maxWorkers := configuredMax
	if maxWorkers <= 0 {
		maxWorkers = 10 // Default
	}

	// Limit workers to actual number of recipients
	if maxWorkers > recipientCount {
		maxWorkers = recipientCount
	}

	return maxWorkers
}
