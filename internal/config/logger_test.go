package config

import (
	"io"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestNewJSONLoggerDevelopment verifies that logger uses text formatter in development
func TestNewJSONLoggerDevelopment(t *testing.T) {
	logger := NewJSONLogger(Development)

	// Check that it's using TextFormatter in development mode
	require.IsType(t, &logrus.TextFormatter{}, logger.Formatter)
	require.Equal(t, io.Stdout, logger.Out)
}

// TestNewJSONLoggerProduction verifies that logger uses JSON formatter in production
func TestNewJSONLoggerProduction(t *testing.T) {
	logger := NewJSONLogger(Production)

	// Check that it's using JSONFormatter in production mode
	require.IsType(t, &logrus.JSONFormatter{}, logger.Formatter)
	require.Equal(t, io.Stdout, logger.Out)
}

// TestLoggerInterface verifies that Logger implements LoggerInterface
func TestLoggerInterface(t *testing.T) {
	var _ LoggerInterface = NewJSONLogger(Development)
}

// TestLoggerMethods verifies that logger methods work correctly
func TestLoggerMethods(t *testing.T) {
	logger := NewJSONLogger(Development)

	// Test that methods don't panic
	logger.Info("info message")
	logger.Infof("info message with %s", "format")
	logger.Warn("warn message")
	logger.Warnf("warn message with %s", "format")
	logger.Error("error message")
	logger.Errorf("error message with %s", "format")
	logger.Debug("debug message")
	logger.Debugf("debug message with %s", "format")

	// Test WithField
	withField := logger.WithField("key", "value")
	require.NotNil(t, withField)

	// Test WithFields
	withFields := logger.WithFields(logrus.Fields{"key1": "val1", "key2": "val2"})
	require.NotNil(t, withFields)

	// Test WithError
	withError := logger.WithError(nil)
	require.NotNil(t, withError)
}