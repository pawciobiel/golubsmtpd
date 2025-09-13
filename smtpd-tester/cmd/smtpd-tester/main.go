package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/pawciobiel/golubsmtpd/smtpd-tester/internal/client"
	"github.com/pawciobiel/golubsmtpd/smtpd-tester/internal/test"
)

func main() {
	var (
		host       = flag.String("host", "127.0.0.1", "SMTP server host")
		port       = flag.Int("port", 2525, "SMTP server port")
		user       = flag.String("user", "", "SMTP authentication username")
		password   = flag.String("password", "", "SMTP authentication password")
		messages   = flag.Int("messages", 10, "Number of messages to send")
		workers    = flag.Int("workers", 1, "Number of concurrent connections")
		from       = flag.String("from", "sender@example.com", "Sender email address")
		recipients = flag.String("recipients", "", "Comma-separated list of recipient email addresses")
		subject    = flag.String("subject", "Test Message", "Email subject prefix")
		timeout    = flag.Duration("timeout", 5*time.Second, "Connection timeout")
		verbose    = flag.Bool("verbose", false, "Enable verbose logging")
		tests      = flag.String("tests", "", "Comma-separated list of tests to run (use -list-tests to see available tests)")
		listTests  = flag.Bool("list-tests", false, "List available tests")
	)
	flag.Parse()

	// Handle list-tests flag
	if *listTests {
		fmt.Println("Available tests:")
		for name, info := range test.Registry {
			fmt.Printf("  %s - %s\n", name, info.Description)
		}
		os.Exit(0)
	}

	// Check if we should run tests or manual mode
	if *tests != "" {
		// Run predefined tests
		testNames := strings.Split(*tests, ",")
		for i, name := range testNames {
			testNames[i] = strings.TrimSpace(name)
		}

		recipientList := test.ParseRecipients(*recipients)

		// Setup logging
		logLevel := slog.LevelInfo
		if *verbose {
			logLevel = slog.LevelDebug
		}

		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: logLevel,
		}))

		config := &client.Config{
			Host:       *host,
			Port:       *port,
			User:       *user,
			Password:   *password,
			From:       *from,
			Recipients: recipientList,
			Subject:    *subject,
			Timeout:    *timeout,
		}

		test.ValidateConfig(config)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		for _, testName := range testNames {
			if err := test.RunTest(ctx, testName, config, logger); err != nil {
				logger.Error("Test failed", "test", testName, "error", err)
				os.Exit(1)
			}
		}
		return
	}

	// Validate flags for manual mode
	if *messages < 1 {
		fmt.Fprintf(os.Stderr, "Error: messages must be >= 1\n")
		os.Exit(1)
	}
	if *workers < 1 {
		fmt.Fprintf(os.Stderr, "Error: workers must be >= 1\n")
		os.Exit(1)
	}
	if *workers > 1000 {
		fmt.Printf("Warning: Very high worker count may overwhelm the server\n")
	}

	recipientList := test.ParseRecipients(*recipients)

	// Setup logging
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	config := &client.Config{
		Host:       *host,
		Port:       *port,
		User:       *user,
		Password:   *password,
		From:       *from,
		Recipients: recipientList,
		Subject:    *subject,
		Timeout:    *timeout,
	}

	// Validate and set defaults
	test.ValidateConfig(config)

	smtpClient := client.New(config, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Printf("SMTP Test Client\n")
	fmt.Printf("================\n")
	fmt.Printf("Target: %s:%d\n", config.Host, config.Port)
	if config.User != "" {
		fmt.Printf("Authentication: %s\n", config.User)
	}
	fmt.Printf("Messages: %d\n", *messages)
	fmt.Printf("From: %s\n", config.From)
	fmt.Printf("Recipients: %s\n", strings.Join(config.Recipients, ", "))
	fmt.Printf("Subject: %s\n", config.Subject)
	if *workers == 1 {
		fmt.Printf("Mode: Sequential\n")
	} else {
		fmt.Printf("Mode: Concurrent (%d workers)\n", *workers)
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
		if *workers == 1 {
			if success {
				logger.Info("Message sent", "id", msgID, "total", *messages, "duration", duration)
			} else {
				logger.Error("Message failed", "id", msgID, "error", err, "duration", duration)
			}
		} else {
			if !success {
				logger.Warn("Message failed", "id", msgID, "error", err, "duration", duration)
			} else {
				logger.Debug("Message sent", "id", msgID, "duration", duration)
			}
		}
	}

	opts := client.SendOptions{
		Messages:   *messages,
		Workers:    *workers,
		OnProgress: onProgress,
		OnMessage:  onMessage,
	}

	if err := smtpClient.SendMessages(ctx, opts); err != nil {
		logger.Error("Test failed", "error", err)
		os.Exit(1)
	}

	smtpClient.PrintStats()
}
