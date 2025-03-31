// Package pvelog contains project-specific log helpers.
package pvelog

import (
	"log/slog"
	"os"
)

// Error returns a [slog.Attr] representing the given error.
func Error(err error) slog.Attr {
	if err == nil {
		return slog.String("error", "<nil>")
	}

	return slog.String("error", err.Error())
}

// Fatal is a helper function that logs an error message to the given logger
// and exits the program.
func Fatal(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
