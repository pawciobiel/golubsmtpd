package queue

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/delivery"
	"github.com/pawciobiel/golubsmtpd/internal/logging"
)

var log = logging.GetLogger

var (
	ErrQueueFull   = errors.New("queue full")
	ErrQueueClosed = errors.New("queue closed")
)

type Queue struct {
	messageQueue chan *Message
	config       *config.Config
	sem          chan struct{} // Limits concurrent processors
	processorWg  sync.WaitGroup
	consumerDone chan struct{} // Signals when consumer loop exits

	// Publisher coordination
	publisherCtx    context.Context
	publisherCancel context.CancelFunc // Function stored as struct field
	publisherWg     sync.WaitGroup     // Track active publishers
}

func NewQueue(ctx context.Context, config *config.Config) *Queue {
	publisherCtx, cancel := context.WithCancel(ctx) // cancel is a function

	return &Queue{
		messageQueue:    make(chan *Message, config.Queue.BufferSize),
		config:          config,
		sem:             make(chan struct{}, config.Queue.MaxConsumers),
		processorWg:     sync.WaitGroup{},
		consumerDone:    make(chan struct{}),
		publisherCtx:    publisherCtx,
		publisherCancel: cancel, // Store the cancel function
	}
}

// StartConsumer starts the consumer loop in a goroutine (non-blocking)
func (q *Queue) StartConsumer(ctx context.Context) {
	log().Debug("Starting message queue consumers")
	go func() {
		defer close(q.consumerDone) // Signal when consumer loop exits
		log().Debug("Consumer loop started")
		for {
			select {
			case msg, ok := <-q.messageQueue:
				if !ok {
					// Channel closed, exit consumer loop
				log().Debug("Channel closed, exit consumer loop")
					return
				}

				log().Debug("Message received, acquiring semaphore", "message_id", msg.ID)
				// Try to acquire semaphore - this will block if at capacity
				q.sem <- struct{}{} // Acquire semaphore BEFORE spawning goroutine
				q.processorWg.Go(func() {
					defer func() { <-q.sem }() // Release semaphore
					q.processMessage(ctx, msg)
				})

			case <-ctx.Done():
				// Context cancelled, exit consumer loop
				log().Debug("Context cancelled, exit consumer loop")
				return
			}
		}
	}()
}

// PublishMessage tracks publishers and uses publisher context
func (q *Queue) PublishMessage(ctx context.Context, msg *Message) error {
	q.publisherWg.Add(1)
	defer q.publisherWg.Done()

	// Check if publishers are being shut down
	select {
	case <-q.publisherCtx.Done():
		log().Debug("Publisher context cancelled, rejecting message", "message_id", msg.ID)
		return ErrQueueClosed
	default:
	}

	// Try immediate publish first
	select {
	case q.messageQueue <- msg:
		log().Debug("Message published", "message_id", msg.ID)
		return nil
	case <-q.publisherCtx.Done():
		log().Debug("Publisher context cancelled, rejecting message", "message_id", msg.ID)
		return ErrQueueClosed
	default:
		// Queue full, start retry logic
	}

	// Retry with exponential backoff using configured timing
	retryDelay := q.config.Queue.RetryDelay
	if retryDelay == 0 {
		retryDelay = 100 * time.Millisecond // Default fallback
	}
	maxDelay := q.config.Queue.MaxRetryDelay
	if maxDelay == 0 {
		maxDelay = 1 * time.Second // Default fallback
	}
	totalTimeout := q.config.Queue.PublishTimeout
	if totalTimeout == 0 {
		totalTimeout = 5 * time.Second // Default fallback
	}
	startTime := time.Now()

	for {
		log().Warn("Queue full, retrying", "message_id", msg.ID, "retry_delay", retryDelay, "elapsed", time.Since(startTime))

		// Check if we've exceeded total timeout
		if time.Since(startTime) >= totalTimeout {
			log().Error("Queue full timeout exceeded, rejecting message", "message_id", msg.ID, "total_wait", time.Since(startTime))
			return ErrQueueFull
		}

		time.Sleep(retryDelay)

		// Try to publish again
		select {
		case q.messageQueue <- msg:
			log().Info("Message published after retry", "message_id", msg.ID, "total_wait", time.Since(startTime))
			return nil
		case <-q.publisherCtx.Done():
			log().Debug("Publisher context cancelled during retry", "message_id", msg.ID)
			return ErrQueueClosed
		default:
			// Still full, increase delay for next iteration
			if retryDelay < maxDelay {
				retryDelay *= 2
				if retryDelay > maxDelay {
					retryDelay = maxDelay
				}
			}
		}
	}
}

// Stop coordinates shutdown: stop publishers → wait → close channel → wait for processors
func (q *Queue) Stop(ctx context.Context) error {
	log().Info("Stopping message queue")

	// Phase 1: Signal publishers to stop
	log().Debug("Signaling publishers to stop")
	q.publisherCancel() // Call the stored cancel function

	// Phase 2: Wait for all publishers to finish (BLOCKING with timeout)
	log().Debug("Waiting for publishers to finish")
	publisherDone := make(chan struct{})
	go func() {
		q.publisherWg.Wait()
		close(publisherDone)
	}()

	select {
	case <-publisherDone:
		log().Debug("All publishers stopped")
	case <-ctx.Done():
		log().Warn("Publisher shutdown timeout - forcing channel close")
		// Don't return here - continue with channel close
	}

	// Phase 3: Close channel (publishers should be done, or we're forcing it)
	log().Debug("Closing message queue channel")
	close(q.messageQueue)

	// Phase 4: Wait for consumer loop to exit
	log().Debug("Waiting for consumer loop to exit")
	<-q.consumerDone

	// Phase 5: Wait for processors to finish
	log().Debug("Waiting for processors to finish")
	done := make(chan struct{})
	go func() {
		q.processorWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log().Info("Message queue stopped gracefully")
		return nil
	case <-ctx.Done():
		log().Warn("Processor shutdown timeout")
		return ctx.Err()
	}
}

func (q *Queue) processMessage(ctx context.Context, msg *Message) {
	log().Debug("Processing message", "message_id", msg.ID)

	spoolDir := q.config.Server.SpoolDir
	if err := MoveMessage(spoolDir, msg, MessageStateIncoming, MessageStateProcessing); err != nil {
		log().Error("Failed to move message to processing", "message_id", msg.ID, "error", err)
		return
	}

	messagePath := GetMessagePath(spoolDir, msg, MessageStateProcessing)

	// Collect one result per active delivery type
	outboundRecipients := mergeRecipients(msg.RelayRecipients, msg.ExternalRecipients)
	deliveryTypes := countNonEmpty(msg.LocalRecipients, msg.VirtualRecipients, outboundRecipients)
	resultChan := make(chan delivery.DeliveryResult, deliveryTypes)

	if len(msg.LocalRecipients) > 0 {
		go func() {
			maxWorkers := delivery.GetMaxWorkers(q.config.Delivery.Local.MaxWorkers, len(msg.LocalRecipients))
			resultChan <- delivery.DeliverWithWorkers(ctx, msg.LocalRecipients, maxWorkers, delivery.RecipientLocal,
				func(ctx context.Context, recipient string) error {
					return delivery.DeliverToLocalUser(ctx, msg, messagePath, recipient, &q.config.Delivery.Local)
				})
		}()
	}

	if len(msg.VirtualRecipients) > 0 {
		go func() {
			maxWorkers := delivery.GetMaxWorkers(q.config.Delivery.Virtual.MaxWorkers, len(msg.VirtualRecipients))
			resultChan <- delivery.DeliverWithWorkers(ctx, msg.VirtualRecipients, maxWorkers, delivery.RecipientVirtual,
				func(ctx context.Context, recipient string) error {
					return delivery.DeliverToVirtualUser(ctx, msg, messagePath, recipient, q.config.Delivery.Virtual.BaseDirPath)
				})
		}()
	}

	if len(outboundRecipients) > 0 {
		go func() {
			maxWorkers := delivery.GetMaxWorkers(q.config.Delivery.Outbound.MaxWorkers, len(outboundRecipients))
			resultChan <- delivery.DeliverOutboundWithWorkers(ctx, outboundRecipients, maxWorkers, msg, messagePath)
		}()
	}

	// Collect all results and track outcomes
	totalSuccessful := 0
	totalFailed := 0
	var bounces []*Message

	for i := 0; i < deliveryTypes; i++ {
		result := <-resultChan

		totalSuccessful += len(result.Successful)
		totalFailed += len(result.Failed) + len(result.TempFailed) + len(result.PermFailed)

		if len(result.Successful) > 0 {
			log().Info("Delivery successful", "message_id", msg.ID, "type", result.Type,
				"count", len(result.Successful), "recipients", result.Successful)
		}
		if len(result.Failed) > 0 {
			log().Warn("Delivery failed", "message_id", msg.ID, "type", result.Type,
				"count", len(result.Failed), "recipients", result.Failed)
		}

		// Handle retry state and bounce generation for outbound results
		if result.Type == delivery.RecipientExternal || result.Type == delivery.RecipientRelay {
			generated := delivery.HandleOutboundResult(
				result, msg, spoolDir,
				q.config.Server.Hostname,
				q.config.Delivery.Outbound.RetryInterval,
				q.config.Delivery.Outbound.RetryMaxAge,
			)
			bounces = append(bounces, generated...)
		}
	}

	// Inject any DSN bounces back into the queue for local delivery
	for _, bounce := range bounces {
		if err := WriteRawBody(spoolDir, bounce); err != nil {
			log().Error("Failed to write DSN to spool", "original_id", msg.ID, "error", err)
			continue
		}
		if err := q.PublishMessage(ctx, bounce); err != nil {
			log().Error("Failed to publish DSN to queue", "original_id", msg.ID, "error", err)
		} else {
			log().Info("DSN bounce injected", "original_id", msg.ID, "bounce_id", bounce.ID)
		}
	}

	var finalState MessageState
	if totalFailed == 0 {
		finalState = MessageStateDelivered
		log().Info("Message delivery completed successfully", "message_id", msg.ID,
			"successful_count", totalSuccessful)
	} else {
		finalState = MessageStateFailed
		log().Error("Message delivery failed", "message_id", msg.ID,
			"successful_count", totalSuccessful, "failed_count", totalFailed)
	}

	if err := MoveMessage(spoolDir, msg, MessageStateProcessing, finalState); err != nil {
		log().Error("Failed to move message to final state", "message_id", msg.ID,
			"final_state", finalState, "error", err)
	}

	log().Debug("Message processing completed", "message_id", msg.ID, "final_state", finalState)
}

// mergeRecipients merges multiple recipient maps into one without allocating if both empty.
func mergeRecipients(maps ...map[string]struct{}) map[string]struct{} {
	total := 0
	for _, m := range maps {
		total += len(m)
	}
	if total == 0 {
		return nil
	}
	merged := make(map[string]struct{}, total)
	for _, m := range maps {
		for k := range m {
			merged[k] = struct{}{}
		}
	}
	return merged
}

// countNonEmpty counts how many of the provided maps are non-empty.
func countNonEmpty(maps ...map[string]struct{}) int {
	n := 0
	for _, m := range maps {
		if len(m) > 0 {
			n++
		}
	}
	return n
}
