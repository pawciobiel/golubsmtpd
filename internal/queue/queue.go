package queue

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/delivery"
)

var (
	ErrQueueFull   = errors.New("queue full")
	ErrQueueClosed = errors.New("queue closed")
)

type Queue struct {
	messageQueue chan *Message
	logger       *slog.Logger
	config       *config.Config
	sem          chan struct{} // Limits concurrent processors
	processorWg  sync.WaitGroup
	consumerDone chan struct{} // Signals when consumer loop exits

	// Publisher coordination
	publisherCtx    context.Context
	publisherCancel context.CancelFunc // Function stored as struct field
	publisherWg     sync.WaitGroup     // Track active publishers
}

func NewQueue(ctx context.Context, config *config.Config, logger *slog.Logger) *Queue {
	publisherCtx, cancel := context.WithCancel(ctx) // cancel is a function

	return &Queue{
		messageQueue:    make(chan *Message, config.Queue.BufferSize),
		logger:          logger,
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
	q.logger.Debug("Starting message queue consumers")
	go func() {
		defer close(q.consumerDone) // Signal when consumer loop exits
		q.logger.Debug("Consumer loop started")
		for {
			select {
			case msg, ok := <-q.messageQueue:
				if !ok {
					// Channel closed, exit consumer loop
					q.logger.Debug("Channel closed, exit consumer loop")
					return
				}

				q.logger.Debug("Message received, acquiring semaphore", "message_id", msg.ID)
				// Try to acquire semaphore - this will block if at capacity
				q.sem <- struct{}{} // Acquire semaphore BEFORE spawning goroutine
				q.processorWg.Go(func() {
					defer func() { <-q.sem }() // Release semaphore
					q.processMessage(ctx, msg)
				})

			case <-ctx.Done():
				// Context cancelled, exit consumer loop
				q.logger.Debug("Context cancelled, exit consumer loop")
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
		q.logger.Debug("Publisher context cancelled, rejecting message", "message_id", msg.ID)
		return ErrQueueClosed
	default:
	}

	// Try immediate publish first
	select {
	case q.messageQueue <- msg:
		q.logger.Debug("Message published", "message_id", msg.ID)
		return nil
	case <-q.publisherCtx.Done():
		q.logger.Debug("Publisher context cancelled, rejecting message", "message_id", msg.ID)
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
		q.logger.Warn("Queue full, retrying", "message_id", msg.ID, "retry_delay", retryDelay, "elapsed", time.Since(startTime))

		// Check if we've exceeded total timeout
		if time.Since(startTime) >= totalTimeout {
			q.logger.Error("Queue full timeout exceeded, rejecting message", "message_id", msg.ID, "total_wait", time.Since(startTime))
			return ErrQueueFull
		}

		time.Sleep(retryDelay)

		// Try to publish again
		select {
		case q.messageQueue <- msg:
			q.logger.Info("Message published after retry", "message_id", msg.ID, "total_wait", time.Since(startTime))
			return nil
		case <-q.publisherCtx.Done():
			q.logger.Debug("Publisher context cancelled during retry", "message_id", msg.ID)
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
	q.logger.Info("Stopping message queue")

	// Phase 1: Signal publishers to stop
	q.logger.Debug("Signaling publishers to stop")
	q.publisherCancel() // Call the stored cancel function

	// Phase 2: Wait for all publishers to finish (BLOCKING with timeout)
	q.logger.Debug("Waiting for publishers to finish")
	publisherDone := make(chan struct{})
	go func() {
		q.publisherWg.Wait()
		close(publisherDone)
	}()

	select {
	case <-publisherDone:
		q.logger.Debug("All publishers stopped")
	case <-ctx.Done():
		q.logger.Warn("Publisher shutdown timeout - forcing channel close")
		// Don't return here - continue with channel close
	}

	// Phase 3: Close channel (publishers should be done, or we're forcing it)
	q.logger.Debug("Closing message queue channel")
	close(q.messageQueue)

	// Phase 4: Wait for consumer loop to exit
	q.logger.Debug("Waiting for consumer loop to exit")
	<-q.consumerDone

	// Phase 5: Wait for processors to finish
	q.logger.Debug("Waiting for processors to finish")
	done := make(chan struct{})
	go func() {
		q.processorWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		q.logger.Info("Message queue stopped gracefully")
		return nil
	case <-ctx.Done():
		q.logger.Warn("Processor shutdown timeout")
		return ctx.Err()
	}
}

func (q *Queue) processMessage(ctx context.Context, msg *Message) {
	q.logger.Debug("Processing message", "message_id", msg.ID)

	// Move message from incoming to processing
	spoolDir := q.config.Server.SpoolDir
	if err := MoveMessage(spoolDir, msg, MessageStateIncoming, MessageStateProcessing); err != nil {
		q.logger.Error("Failed to move message to processing", "message_id", msg.ID, "error", err)
		return
	}

	// Get message file path for delivery
	messagePath := GetMessagePath(spoolDir, msg, MessageStateProcessing)

	// TODO: Categorize recipients by domain type (local, virtual, relay)
	// For now, deliver to all recipients as configured types
	localRecipients := msg.LocalRecipients
	virtualRecipients := msg.VirtualRecipients

	// Calculate number of delivery types
	deliveryTypes := 0
	if len(localRecipients) > 0 {
		deliveryTypes++
	}
	if len(virtualRecipients) > 0 {
		deliveryTypes++
	}

	// Channel to collect delivery results
	resultChan := make(chan delivery.DeliveryResult, deliveryTypes)

	// Parallel delivery for local recipients using DeliverWithWorkers
	if len(localRecipients) > 0 {
		go func() {
			maxWorkers := delivery.GetMaxWorkers(q.config.Delivery.Local.MaxWorkers, len(localRecipients))
			result := delivery.DeliverWithWorkers(ctx, localRecipients, maxWorkers, delivery.RecipientLocal,
				func(ctx context.Context, recipient string) error {
					return delivery.DeliverToLocalUser(ctx, msg, messagePath, recipient, &q.config.Delivery.Local)
				})
			resultChan <- result
		}()
	}

	// Parallel delivery for virtual recipients
	if len(virtualRecipients) > 0 {
		go func() {
			maxWorkers := delivery.GetMaxWorkers(q.config.Delivery.Virtual.MaxWorkers, len(virtualRecipients))
			result := delivery.DeliverWithWorkers(ctx, virtualRecipients, maxWorkers, delivery.RecipientVirtual,
				func(ctx context.Context, recipient string) error {
					return delivery.DeliverToVirtualUser(ctx, msg, messagePath, recipient, q.config.Delivery.Virtual.BaseDirPath)
				})
			resultChan <- result
		}()
	}

	// Collect exactly the number of results we expect
	var deliveryResults []delivery.DeliveryResult
	for i := 0; i < deliveryTypes; i++ {
		result := <-resultChan
		deliveryResults = append(deliveryResults, result)
	}

	// Process delivery results and determine final message state
	totalSuccessful := 0
	totalFailed := 0
	for _, result := range deliveryResults {
		totalSuccessful += len(result.Successful)
		totalFailed += len(result.Failed)

		// Log delivery results
		if len(result.Successful) > 0 {
			q.logger.Info("Delivery successful", "message_id", msg.ID, "type", result.Type,
				"successful_count", len(result.Successful), "recipients", result.Successful)
		}
		if len(result.Failed) > 0 {
			q.logger.Warn("Delivery failed", "message_id", msg.ID, "type", result.Type,
				"failed_count", len(result.Failed), "recipients", result.Failed)
		}
	}

	// Move to final state based on delivery results
	var finalState MessageState
	if totalFailed == 0 {
		finalState = MessageStateDelivered
		q.logger.Info("Message delivery completed successfully", "message_id", msg.ID,
			"successful_count", totalSuccessful)
	} else {
		finalState = MessageStateFailed
		q.logger.Error("Message delivery failed", "message_id", msg.ID,
			"successful_count", totalSuccessful, "failed_count", totalFailed)
	}

	// Move message to final state
	if err := MoveMessage(spoolDir, msg, MessageStateProcessing, finalState); err != nil {
		q.logger.Error("Failed to move message to final state", "message_id", msg.ID,
			"final_state", finalState, "error", err)
		return
	}

	q.logger.Debug("Message processing completed", "message_id", msg.ID, "final_state", finalState)
}
