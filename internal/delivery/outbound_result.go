package delivery

import (
	"log/slog"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/types"
)

// OutboundResultHandler processes a DeliveryResult for outbound recipients:
// persists retry state for tempfails and returns DSN messages to inject for
// permfails and retry-exhausted recipients. The caller is responsible for
// publishing returned bounce messages to the queue.
func HandleOutboundResult(
	result DeliveryResult,
	msg *types.Message,
	spoolDir string,
	localHostname string,
	retryInterval time.Duration,
	retryMaxAge time.Duration,
) []*types.Message {
	var bounces []*types.Message

	// Immediate bounces for permanently failed recipients
	if len(result.PermFailed) > 0 {
		slog.Warn("Outbound permanent failure — generating DSN",
			"message_id", msg.ID, "recipients", result.PermFailed)
		bounces = append(bounces, GenerateDSN(msg, result.PermFailed, "recipient rejected by remote server", localHostname))
	}

	if len(result.TempFailed) == 0 {
		return bounces
	}

	// Load or create retry state for tempfailed recipients
	state, err := LoadRetryState(spoolDir, msg.ID)
	if err != nil {
		slog.Error("Failed to load retry state — dropping tempfailed recipients",
			"message_id", msg.ID, "error", err)
		return bounces
	}
	if state == nil {
		state = NewRetryState(msg.ID, msg.From, retryInterval, result.TempFailed)
	}

	shouldRetry := state.RecordAttempt(result, retryInterval, retryMaxAge)

	// Bounce any recipients that have now expired
	if expired := state.BounceRecipients(); len(expired) > 0 {
		slog.Warn("Outbound retry exhausted — generating DSN",
			"message_id", msg.ID, "recipients", expired)
		bounces = append(bounces, GenerateDSN(msg, expired, "maximum retry time exceeded", localHostname))
		if err := DeleteRetryState(spoolDir, msg.ID); err != nil {
			slog.Error("Failed to delete exhausted retry state", "message_id", msg.ID, "error", err)
		}
		return bounces
	}

	if shouldRetry {
		if err := SaveRetryState(spoolDir, state); err != nil {
			slog.Error("Failed to save retry state", "message_id", msg.ID, "error", err)
		} else {
			slog.Info("Outbound message scheduled for retry",
				"message_id", msg.ID, "next_retry", state.NextRetry, "attempts", state.Attempts)
		}
	}

	return bounces
}
