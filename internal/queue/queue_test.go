package queue

import (
	"context"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/logging"
)

func TestMain(m *testing.M) {
	logging.InitTestLogging()
	code := m.Run()
	os.Exit(code)
}


func createQueueTestConfig() *config.Config {
	return &config.Config{
		Queue: config.QueueConfig{
			BufferSize:     10,
			MaxConsumers:   2,
			PublishTimeout: 500 * time.Millisecond,
			RetryDelay:     50 * time.Millisecond,
			MaxRetryDelay:  200 * time.Millisecond,
		},
	}
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

	cfg := createQueueTestConfig()
	queue := NewQueue(ctx, cfg)

	// Start consumers
	queue.StartConsumer(ctx)
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
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

			// Create queue with buffer size 1 and no consumers
		cfg := &config.Config{Queue: config.QueueConfig{BufferSize: 1, MaxConsumers: 1}}
		queue := NewQueue(ctx, cfg)

		// Publish first message (should succeed)
		msg1 := createTestMessage()
		err := queue.PublishMessage(ctx, msg1)
		if err != nil {
			t.Fatalf("First publish should succeed: %v", err)
		}

		// Start second publish in goroutine (will timeout due to retry logic)
		msg2 := createTestMessage()
		errChan := make(chan error, 1)
		go func() {
			errChan <- queue.PublishMessage(ctx, msg2)
		}()

		// Wait for the publish to timeout (synctest automatically advances time)
		// The goroutine will eventually complete and send to errChan
		var publishErr error
		select {
		case publishErr = <-errChan:
			// Got result
		}

		// Should get ErrQueueFull after timeout
		if publishErr != ErrQueueFull {
			t.Errorf("Expected ErrQueueFull, got: %v", publishErr)
		}
	})
}

func TestQueue_PublishAfterStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cfg := &config.Config{Queue: config.QueueConfig{BufferSize: 10, MaxConsumers: 1}}
	queue := NewQueue(ctx, cfg)

	// Start and immediately stop
	queue.StartConsumer(ctx)
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

	cfg := &config.Config{Queue: config.QueueConfig{BufferSize: 100, MaxConsumers: 5}}
	queue := NewQueue(ctx, cfg)

	queue.StartConsumer(ctx)
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

	// Queue with buffer=10 but only 1 consumer (semaphore limit)
	cfg := &config.Config{Queue: config.QueueConfig{BufferSize: 10, MaxConsumers: 1}}
	queue := NewQueue(ctx, cfg)

	queue.StartConsumer(ctx)
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

	cfg := &config.Config{Queue: config.QueueConfig{BufferSize: 5, MaxConsumers: 2}}
	queue := NewQueue(ctx, cfg)

	queue.StartConsumer(ctx)

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

	cfg := &config.Config{Queue: config.QueueConfig{BufferSize: 5, MaxConsumers: 1}}
	queue := NewQueue(ctx, cfg)

	queue.StartConsumer(ctx)

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

	cfg := &config.Config{Queue: config.QueueConfig{BufferSize: 50, MaxConsumers: 3}}
	queue := NewQueue(ctx, cfg)
	if queue == nil {
		t.Fatal("NewQueue returned nil")
	}


	if cap(queue.messageQueue) != 50 {
		t.Errorf("Message queue buffer size wrong. Expected: 50, Got: %d", cap(queue.messageQueue))
	}

	if cap(queue.sem) != 3 {
		t.Errorf("Semaphore size wrong. Expected: 3, Got: %d", cap(queue.sem))
	}
}
