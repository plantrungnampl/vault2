package logger

import (
	"log/slog"
	"os"
)

var globalLogger *slog.Logger

// InitLogger initializes the global logger
func InitLogger() {
	globalLogger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
}

// GetLogger returns the global logger
func GetLogger() *slog.Logger {
	if globalLogger == nil {
		InitLogger()
	}
	return globalLogger
}
