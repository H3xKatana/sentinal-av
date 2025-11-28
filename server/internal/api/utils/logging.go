package utils

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gorm.io/gorm/logger"
)

// GetLogger returns a configured zap logger
func GetLogger() *zap.Logger {
	// Configure the logger based on environment
	logLevel := zapcore.InfoLevel
	if os.Getenv("LOG_LEVEL") == "debug" {
		logLevel = zapcore.DebugLevel
	}

	// Create encoder config
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Create console and file cores
	consoleCore := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		logLevel,
	)

	// Create the logger
	log := zap.New(
		zapcore.NewTee(consoleCore), // Add file core if needed: zapcore.NewTee(consoleCore, fileCore)
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)

	return log
}

// GetGormLogger returns a configured GORM logger
func GetGormLogger() logger.Interface {
	logLevel := logger.Info
	if os.Getenv("LOG_LEVEL") == "debug" {
		logLevel = logger.Info
	} else if os.Getenv("LOG_LEVEL") == "silent" {
		logLevel = logger.Silent
	}

	return logger.New(
		zapWriter{logger: GetLogger().Sugar()}, // Custom writer implementation
		logger.Config{
			SlowThreshold:             0, // Slow SQL threshold
			LogLevel:                  logLevel, // Log level
			IgnoreRecordNotFoundError: false, // Ignore ErrRecordNotFound error for logger
			ParameterizedQueries:      false, // Don't include params in the SQL log
			Colorful:                  false, // Disable color
		},
	)
}

// zapWriter implements the logger.Writer interface using Zap logger
type zapWriter struct {
	logger *zap.SugaredLogger
}

// Printf implements the logger.Writer interface
func (w zapWriter) Printf(message string, data ...interface{}) {
	w.logger.Debugf(message, data...)
}