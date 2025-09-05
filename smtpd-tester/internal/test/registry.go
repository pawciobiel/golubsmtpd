package test

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/pawciobiel/golubsmtpd/smtpd-tester/internal/client"
)

// TestFunc represents a test function
type TestFunc func(ctx context.Context, config *client.Config, logger *slog.Logger) error

// TestInfo holds metadata about a test
type TestInfo struct {
	Name        string
	Description string
	Func        TestFunc
}

// Registry holds all available tests
var Registry = map[string]TestInfo{
	"load": {
		Name:        "load",
		Description: "Simple load test (1000 messages, 10 workers)",
		Func: func(ctx context.Context, config *client.Config, logger *slog.Logger) error {
			opts := DefaultLoadTestOptions()
			return SimpleLoadTest(ctx, config, opts, logger)
		},
	},
}

// ListTests returns all available test names
func ListTests() []string {
	tests := make([]string, 0, len(Registry))
	for name := range Registry {
		tests = append(tests, name)
	}
	return tests
}

// GetTest returns a test by name
func GetTest(name string) (TestInfo, error) {
	test, exists := Registry[name]
	if !exists {
		return TestInfo{}, fmt.Errorf("test '%s' not found", name)
	}
	return test, nil
}

// RunTest executes a test by name
func RunTest(ctx context.Context, testName string, config *client.Config, logger *slog.Logger) error {
	testInfo, err := GetTest(testName)
	if err != nil {
		return err
	}
	
	logger.Info("Running test", "name", testInfo.Name, "description", testInfo.Description)
	return testInfo.Func(ctx, config, logger)
}