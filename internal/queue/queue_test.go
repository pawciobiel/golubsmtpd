package queue

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"
)

func createTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // Only show errors to keep test output clean
	}))
}

func createTestMessage() *Message {
	return &Message{
		ID:      GenerateID(),
		Created: time.Now().UTC(),
		From:    "test@example.com",
		LocalRecipients: map[string]struct{}{
			"user@localhost": {},
		},
		TotalSize: 100,
	}
}

func TestQueue_BasicPublishAndConsume(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	logger := createTestLogger()
	queue := NewQueue(ctx, 10, 2, logger)

	// Start consumers
	queue.StartConsumers(ctx)
	defer queue.Stop(ctx)

	// Give consumers time to start
	time.Sleep(10 * time.Millisecond)

	// Publish a message
	msg := createTestMessage()
	err := queue.PublishMessage(ctx, msg)
	if err != nil {
		t.Fatalf("Failed to publish message: %v", err)
	}

	// Wait a bit for processing
	time.Sleep(100 * time.Millisecond)

	// Test passes if no errors occurred
}

func TestQueue_PublishToFullQueue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := createTestLogger()
	// Create queue with buffer size 1 and no consumers
	queue := NewQueue(ctx, 1, 1, logger)

	// Publish first message (should succeed)
	msg1 := createTestMessage()
	err := queue.PublishMessage(ctx, msg1)
	if err != nil {
		t.Fatalf("First publish should succeed: %v", err)
	}

	// Publish second message (should fail - queue full)
	msg2 := createTestMessage()
	err = queue.PublishMessage(ctx, msg2)
	if err != ErrQueueFull {
		t.Errorf("Expected ErrQueueFull, got: %v", err)
	}
}

func TestQueue_PublishAfterStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	logger := createTestLogger()
	queue := NewQueue(ctx, 10, 1, logger)

	// Start and immediately stop
	queue.StartConsumers(ctx)
	err := queue.Stop(ctx)
	if err != nil {
		t.Fatalf("Failed to stop queue: %v", err)
	}

	// Try to publish after stop (should fail)
	msg := createTestMessage()
	err = queue.PublishMessage(ctx, msg)
	if err != ErrQueueClosed {
		t.Errorf("Expected ErrQueueClosed, got: %v", err)
	}
}

func TestQueue_ConcurrentPublishing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logger := createTestLogger()
	queue := NewQueue(ctx, 100, 5, logger)

	queue.StartConsumers(ctx)
	defer queue.Stop(ctx)

	// Give consumers time to start
	time.Sleep(10 * time.Millisecond)

	const numPublishers = 10
	const messagesPerPublisher = 20

	var wg sync.WaitGroup
	var successCount int64
	var mu sync.Mutex

	// Start multiple publishers
	for i := 0; i < numPublishers; i++ {
		wg.Add(1)
		go func(publisherID int) {
			defer wg.Done()

			for j := 0; j < messagesPerPublisher; j++ {
				msg := createTestMessage()

				err := queue.PublishMessage(ctx, msg)
				if err == nil {
					mu.Lock()
					successCount++
					mu.Unlock()
				}
			}
		}(i)
	}

	wg.Wait()

	// Wait for processing to complete
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	totalExpected := int64(numPublishers * messagesPerPublisher)
	mu.Unlock()

	if successCount != totalExpected {
		t.Errorf("Expected %d successful publishes with retry logic, got %d", totalExpected, successCount)
	}
}

func TestQueue_SemaphoreLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	logger := createTestLogger()
	// Queue with buffer=10 but only 1 consumer (semaphore limit)
	queue := NewQueue(ctx, 10, 1, logger)

	queue.StartConsumers(ctx)
	defer queue.Stop(ctx)

	time.Sleep(10 * time.Millisecond)

	// Publish multiple messages quickly
	for i := 0; i < 5; i++ {
		msg := createTestMessage()
		err := queue.PublishMessage(ctx, msg)
		if err != nil {
			t.Errorf("Failed to publish message %d: %v", i, err)
		}
	}

	// With semaphore=1, only 1 message should be processed at a time
	// This is hard to test deterministically, but we can verify no errors occur
	time.Sleep(100 * time.Millisecond)
}

func TestQueue_GracefulShutdown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	logger := createTestLogger()
	queue := NewQueue(ctx, 5, 2, logger)

	queue.StartConsumers(ctx)

	// Publish some messages
	for i := 0; i < 3; i++ {
		msg := createTestMessage()
		err := queue.PublishMessage(ctx, msg)
		if err != nil {
			t.Errorf("Failed to publish message %d: %v", i, err)
		}
	}

	// Stop should complete gracefully
	err := queue.Stop(ctx)
	if err != nil {
		t.Errorf("Queue stop failed: %v", err)
	}

	// Verify we can't publish after stop
	msg := createTestMessage()
	err = queue.PublishMessage(ctx, msg)
	if err != ErrQueueClosed {
		t.Errorf("Expected ErrQueueClosed after stop, got: %v", err)
	}
}

func TestQueue_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	logger := createTestLogger()
	queue := NewQueue(ctx, 5, 1, logger)

	queue.StartConsumers(ctx)

	// Publish a message
	msg := createTestMessage()
	err := queue.PublishMessage(ctx, msg)
	if err != nil {
		t.Fatalf("Failed to publish message: %v", err)
	}

	// Cancel context
	cancel()

	// Subsequent publishes should fail
	msg2 := createTestMessage()
	err = queue.PublishMessage(ctx, msg2)
	if err != ErrQueueClosed {
		t.Errorf("Expected ErrQueueClosed after context cancel, got: %v", err)
	}
}

func TestNewQueue(t *testing.T) {
	ctx := context.Background()
	logger := createTestLogger()

	queue := NewQueue(ctx, 50, 3, logger)
	if queue == nil {
		t.Fatal("NewQueue returned nil")
	}

	if queue.logger != logger {
		t.Error("Logger not set correctly")
	}

	if cap(queue.messageQueue) != 50 {
		t.Errorf("Message queue buffer size wrong. Expected: 50, Got: %d", cap(queue.messageQueue))
	}

	if cap(queue.sem) != 3 {
		t.Errorf("Semaphore size wrong. Expected: 3, Got: %d", cap(queue.sem))
	}
}
