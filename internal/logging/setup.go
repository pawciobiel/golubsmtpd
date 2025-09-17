package logging

import (
	"log/slog"
	"os"
	"sync"

	"github.com/pawciobiel/golubsmtpd/internal/config"
)

func Setup(logConfig *config.LoggingConfig) *slog.Logger {
	var level slog.Level
	switch logConfig.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	switch logConfig.Format {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	default:
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger
}

var (
	logger *slog.Logger
	once   sync.Once
)

func InitLogging(logConfig *config.LoggingConfig) {
	once.Do(func() {
		logger = Setup(logConfig)
	})
}

func GetLogger() *slog.Logger {
	if logger == nil {
		panic("logger not initialized. Call logging.InitLogging(cfg) first.")
	}
	return logger
}

func InitTestLogging() {
	level := "error" // Quiet during tests by default
	if os.Getenv("DEBUG") == "1" {
		level = "debug"
	}

	logger = Setup(&config.LoggingConfig{
		Level:  level,
		Format: "text",
	})
}
