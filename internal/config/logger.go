package config

import (
	"os"

	"github.com/sirupsen/logrus"
)

// Logger wraps logrus.Logger for application use
type Logger struct {
	*logrus.Logger
}

// NewJSONLogger creates a new logger with JSON formatting
func NewJSONLogger(development bool) *Logger {
	logger := logrus.New()

	// Set output to stdout
	logger.Out = os.Stdout

	// Set formatter based on environment
	if development {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	} else {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z",
		})
	}

	// Set level (will be overridden by config)
	logger.SetLevel(logrus.InfoLevel)

	return &Logger{logger}
}

// WithField adds a field to the logger
func (l *Logger) WithField(key string, value interface{}) LoggerInterface {
	return &loggerEntry{l.Logger.WithField(key, value)}
}

// WithFields adds fields to the logger
func (l *Logger) WithFields(fields logrus.Fields) LoggerInterface {
	return &loggerEntry{l.Logger.WithFields(fields)}
}

// WithError adds an error field to the logger
func (l *Logger) WithError(err error) LoggerInterface {
	return &loggerEntry{l.Logger.WithError(err)}
}

// loggerEntry wraps logrus.Entry to implement LoggerInterface
type loggerEntry struct {
	*logrus.Entry
}

func (l *loggerEntry) WithField(key string, value interface{}) LoggerInterface {
	return &loggerEntry{l.Entry.WithField(key, value)}
}

func (l *loggerEntry) WithFields(fields logrus.Fields) LoggerInterface {
	return &loggerEntry{l.Entry.WithFields(fields)}
}

func (l *loggerEntry) WithError(err error) LoggerInterface {
	return &loggerEntry{l.Entry.WithError(err)}
}