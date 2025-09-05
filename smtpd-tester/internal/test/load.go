package test

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/pawciobiel/golubsmtpd/smtpd-tester/internal/client"
)

// SimpleLoadTestOptions configures a simple load test
type SimpleLoadTestOptions struct {
	Messages   int
	Workers    int
	CustomBody string
	Verbose    bool
}

// DefaultLoadTestOptions returns sensible defaults for load testing
func DefaultLoadTestOptions() SimpleLoadTestOptions {
	return SimpleLoadTestOptions{
		Messages: 1000,
		Workers:  10,
		Verbose:  false,
	}
}

// SimpleLoadTest performs a basic SMTP load test
func SimpleLoadTest(ctx context.Context, config *client.Config, opts SimpleLoadTestOptions, logger *slog.Logger) error {
	ValidateConfig(config)
	
	smtpClient := client.New(config, logger)
	
	fmt.Printf("SMTP Load Test\n")
	fmt.Printf("==============\n")
	fmt.Printf("Target: %s:%d\n", config.Host, config.Port)
	if config.User != "" {
		fmt.Printf("Authentication: %s\n", config.User)
	}
	fmt.Printf("Messages: %d\n", opts.Messages)
	fmt.Printf("From: %s\n", config.From)
	fmt.Printf("Recipients: %v\n", config.Recipients)
	fmt.Printf("Subject: %s\n", config.Subject)
	if opts.Workers == 1 {
		fmt.Printf("Mode: Sequential\n")
	} else {
		fmt.Printf("Mode: Concurrent (%d workers)\n", opts.Workers)
	}
	fmt.Printf("Timeout: %s\n", config.Timeout)
	fmt.Printf("\n")
	
	// Setup callbacks
	onProgress := func(processed, total int64, rate float64) {
		logger.Info("Progress",
			"processed", processed,
			"total", total,
			"success", smtpClient.Stats().GetSuccess(),
			"errors", smtpClient.Stats().GetErrors(),
			"rate", fmt.Sprintf("%.1f msg/sec", rate),
		)
	}
	
	onMessage := func(msgID int, success bool, err error, duration time.Duration) {
		if opts.Workers == 1 {
			if success {
				logger.Info("Message sent", "id", msgID, "total", opts.Messages, "duration", duration)
			} else {
				logger.Error("Message failed", "id", msgID, "error", err, "duration", duration)
			}
		} else {
			if !success {
				logger.Warn("Message failed", "id", msgID, "error", err, "duration", duration)
			} else if opts.Verbose {
				logger.Debug("Message sent", "id", msgID, "duration", duration)
			}
		}
	}
	
	sendOpts := client.SendOptions{
		Messages:   opts.Messages,
		Workers:    opts.Workers,
		CustomBody: opts.CustomBody,
		OnProgress: onProgress,
		OnMessage:  onMessage,
	}
	
	if err := smtpClient.SendMessages(ctx, sendOpts); err != nil {
		return fmt.Errorf("load test failed: %w", err)
	}
	
	smtpClient.PrintStats()
	return nil
}