package client

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const DefaultRecipient = "test@localhost"

type Config struct {
	Host       string
	Port       int
	User       string
	Password   string
	From       string
	Recipients []string
	Subject    string
	Timeout    time.Duration
}

type Message struct {
	ID        int
	From      string
	To        string
	Subject   string
	Body      string
	Timestamp time.Time
}

type Stats struct {
	Total     int64
	Success   int64
	Errors    int64
	StartTime time.Time
}

func (s *Stats) AddSuccess() {
	atomic.AddInt64(&s.Success, 1)
}

func (s *Stats) AddError() {
	atomic.AddInt64(&s.Errors, 1)
}

func (s *Stats) GetSuccess() int64 {
	return atomic.LoadInt64(&s.Success)
}

func (s *Stats) GetErrors() int64 {
	return atomic.LoadInt64(&s.Errors)
}

func (s *Stats) GetProcessed() int64 {
	return s.GetSuccess() + s.GetErrors()
}

func (s *Stats) Reset() {
	atomic.StoreInt64(&s.Success, 0)
	atomic.StoreInt64(&s.Errors, 0)
	s.StartTime = time.Now()
}

type Client struct {
	config *Config
	logger *slog.Logger
	stats  *Stats
}

func New(config *Config, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}

	return &Client{
		config: config,
		logger: logger,
		stats: &Stats{
			StartTime: time.Now(),
		},
	}
}

func (c *Client) Stats() *Stats {
	return c.stats
}

func (c *Client) generateMessage(id int, customBody string) *Message {
	// Select recipient in round-robin fashion
	recipient := c.config.Recipients[id%len(c.config.Recipients)]

	body := customBody
	if body == "" {
		randBytes := make([]byte, 8)
		if _, err := rand.Read(randBytes); err != nil {
			// Fallback to time-based randomness if crypto/rand fails
			body = fmt.Sprintf(`This is test message number %d for SMTP testing.
Generated at: %s
Random data: %d

Test complete.`, id, time.Now().Format(time.RFC3339), time.Now().UnixNano())
		} else {
			body = fmt.Sprintf(`This is test message number %d for SMTP testing.
Generated at: %s
Random data: %x

Test complete.`, id, time.Now().Format(time.RFC3339), randBytes)
		}
	}

	return &Message{
		ID:        id,
		From:      c.config.From,
		To:        recipient,
		Subject:   fmt.Sprintf("%s %d", c.config.Subject, id),
		Body:      body,
		Timestamp: time.Now(),
	}
}

func (c *Client) SendMessage(ctx context.Context, msg *Message) error {
	addr := fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)

	// Use strings.Builder for efficient message construction
	var builder strings.Builder
	builder.Grow(len(msg.Subject) + len(msg.From) + len(msg.To) + len(msg.Body) + 200)

	builder.WriteString("Subject: ")
	builder.WriteString(msg.Subject)
	builder.WriteString("\r\nFrom: ")
	builder.WriteString(msg.From)
	builder.WriteString("\r\nTo: ")
	builder.WriteString(msg.To)
	builder.WriteString("\r\nMessage-ID: <test-")
	builder.WriteString(fmt.Sprintf("%d-%d", msg.ID, time.Now().UnixNano()))
	builder.WriteString("@example.com>\r\n\r\n")
	builder.WriteString(msg.Body)

	messageBody := builder.String()

	// Setup authentication if provided
	var auth smtp.Auth
	if c.config.User != "" && c.config.Password != "" {
		auth = smtp.PlainAuth("", c.config.User, c.config.Password, c.config.Host)
	}

	// Use context with timeout for the entire operation
	timeoutCtx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	// Channel to capture the result of smtp.SendMail
	done := make(chan error, 1)

	go func() {
		err := smtp.SendMail(
			addr,
			auth,
			msg.From,
			[]string{msg.To},
			[]byte(messageBody),
		)
		done <- err
	}()

	select {
	case <-timeoutCtx.Done():
		return fmt.Errorf("timeout sending message %d: %w", msg.ID, timeoutCtx.Err())
	case err := <-done:
		if err != nil {
			return fmt.Errorf("send message %d failed: %w", msg.ID, err)
		}
		return nil
	}
}

type SendOptions struct {
	Messages   int
	Workers    int
	CustomBody string
	OnProgress func(processed, total int64, rate float64)
	OnMessage  func(msgID int, success bool, err error, duration time.Duration)
}

func (c *Client) SendMessages(ctx context.Context, opts SendOptions) error {
	if opts.Messages < 1 {
		return fmt.Errorf("messages must be >= 1")
	}
	if opts.Workers < 1 {
		opts.Workers = 1
	}

	c.stats.Reset()
	c.stats.Total = int64(opts.Messages)

	mode := "sequential"
	if opts.Workers > 1 {
		mode = "concurrent"
	}

	c.logger.Info("Starting SMTP test",
		"messages", opts.Messages,
		"workers", opts.Workers,
		"mode", mode,
		"recipients", len(c.config.Recipients),
		"target", fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
	)

	// Semaphore channel pattern from go-idioms
	type token struct{}
	sem := make(chan token, opts.Workers)
	var wg sync.WaitGroup

	// Progress reporter goroutine
	if opts.OnProgress != nil {
		progressCtx, cancelProgress := context.WithCancel(ctx)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-progressCtx.Done():
					return
				case <-ticker.C:
					success := c.stats.GetSuccess()
					processed := c.stats.GetProcessed()
					if processed > 0 && processed < int64(opts.Messages) {
						rate := float64(success) / time.Since(c.stats.StartTime).Seconds()
						opts.OnProgress(processed, int64(opts.Messages), rate)
					}
				}
			}
		}()

		// Ensure progress goroutine is cleaned up
		defer func() {
			cancelProgress()
		}()
	}

	// Send all messages using semaphore channel pattern
	for i := 1; i <= opts.Messages; i++ {
		sem <- token{} // Acquire semaphore
		wg.Add(1)
		go func(msgID int) {
			defer func() {
				<-sem // Release semaphore
				wg.Done()
			}()

			msg := c.generateMessage(msgID, opts.CustomBody)

			start := time.Now()
			err := c.SendMessage(ctx, msg)
			duration := time.Since(start)

			success := err == nil
			if success {
				c.stats.AddSuccess()
			} else {
				c.stats.AddError()
			}

			if opts.OnMessage != nil {
				opts.OnMessage(msgID, success, err, duration)
			}

			// Small delay between messages for sequential mode
			if opts.Workers == 1 {
				time.Sleep(100 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
	return nil
}

func (c *Client) PrintStats() {
	elapsed := time.Since(c.stats.StartTime)
	success := c.stats.GetSuccess()
	errors := c.stats.GetErrors()
	total := c.stats.GetProcessed()

	fmt.Printf("\n=== Test Results ===\n")
	fmt.Printf("Total messages: %d\n", c.stats.Total)
	fmt.Printf("Processed: %d\n", total)
	fmt.Printf("Success: %d (%.1f%%)\n", success, float64(success)/float64(c.stats.Total)*100)
	fmt.Printf("Errors: %d (%.1f%%)\n", errors, float64(errors)/float64(c.stats.Total)*100)
	fmt.Printf("Duration: %.2f seconds\n", elapsed.Seconds())
	if success > 0 && elapsed.Seconds() > 0 {
		fmt.Printf("Rate: %.1f messages/second\n", float64(success)/elapsed.Seconds())
	}
}
