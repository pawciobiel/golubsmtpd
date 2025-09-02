package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/logging"
	"github.com/pawciobiel/golubsmtpd/internal/queue"
	"github.com/pawciobiel/golubsmtpd/internal/server"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	// Initialize spool directories
	if err := queue.InitializeSpoolDirectories(cfg.Server.SpoolDir); err != nil {
		log.Fatal("Failed to initialize spool directories:", err)
	}

	// Setup logging
	logger := logging.Setup(&cfg.Logging)
	logger.Info("Starting golubsmtpd", "version", "dev")

	// Create authenticator
	ctx := context.Background()
	authenticator, err := auth.CreateAuthenticator(ctx, &cfg.Auth, logger)
	if err != nil {
		log.Fatal("Failed to create authenticator:", err)
	}
	defer authenticator.Close()

	// Create server
	srv := server.New(cfg, logger, authenticator)

	// Start server
	if err := srv.Start(ctx); err != nil {
		log.Fatal("Failed to start server:", err)
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutdown signal received")

	// Graceful shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Stop(shutdownCtx); err != nil {
		logger.Error("Server shutdown error", "error", err)
	}

	logger.Info("golubsmtpd stopped")
}
