package config

import (
	"github.com/sirupsen/logrus"
)

// LoggerInterface defines the methods a logger must implement
type LoggerInterface interface {
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Warn(args ...interface{})
	Warnf(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})

	WithField(key string, value interface{}) LoggerInterface
	WithFields(fields logrus.Fields) LoggerInterface
	WithError(err error) LoggerInterface
}