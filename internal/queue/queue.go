package queue

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

var (
	ErrQueueFull   = errors.New("queue full")
	ErrQueueClosed = errors.New("queue closed")
)

type Queue struct {
	messageQueue chan *Message
	logger       *slog.Logger
	sem          chan struct{} // Limits concurrent processors
	processorWg  sync.WaitGroup

	// Publisher coordination
	publisherCtx    context.Context
	publisherCancel context.CancelFunc // Function stored as struct field
	publisherWg     sync.WaitGroup     // Track active publishers
}

func NewQueue(ctx context.Context, bufferSize, maxProcessors int, logger *slog.Logger) *Queue {
	publisherCtx, cancel := context.WithCancel(ctx) // cancel is a function

	return &Queue{
		messageQueue:    make(chan *Message, bufferSize),
		logger:          logger,
		sem:             make(chan struct{}, maxProcessors),
		publisherCtx:    publisherCtx,
		publisherCancel: cancel, // Store the cancel function
	}
}

// StartConsumers starts the consumer loop in a goroutine (non-blocking)
func (q *Queue) StartConsumers(ctx context.Context) {
	q.logger.Debug("Starting message queue consumers")
	go func() {
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
				q.sem <- struct{}{}
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

	// Retry with exponential backoff up to 5 seconds total
	retryDelay := 100 * time.Millisecond
	maxDelay := 1 * time.Second
	totalTimeout := 5 * time.Second
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

	// Phase 4: Wait for processors to finish
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
	// TODO: Implement actual message processing logic
	q.logger.Debug("Message processing completed", "message_id", msg.ID)
}
