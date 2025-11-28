package utils

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/0xA1M/sentinel-server/internal/models"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gorm.io/gorm/logger"
)

// GetZapLogger returns a configured zap logger
func GetZapLogger() (*zap.Logger, error) {
	config := zap.NewProductionConfig()

	// Override the level based on environment variable
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		config.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	case "info":
		config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	case "warn":
		config.Level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
	case "error":
		config.Level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
	default:
		config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}

	return config.Build()
}

// GetGormLogger returns a logger that implements GORM's logger interface with Zap
func GetGormLogger() logger.Interface {
	return CustomGormLogger{}
}

// CustomGormLogger implements GORM's logger interface using Zap
type CustomGormLogger struct{}

func (l CustomGormLogger) LogMode(level logger.LogLevel) logger.Interface {
	return l
}

func (l CustomGormLogger) Info(ctx context.Context, msg string, data ...any) {
	logger, _ := GetZapLogger()
	if logger != nil {
		logger.Info(fmt.Sprintf(msg, data...))
		logger.Sync()
	}
}

func (l CustomGormLogger) Warn(ctx context.Context, msg string, data ...any) {
	logger, _ := GetZapLogger()
	if logger != nil {
		logger.Warn(fmt.Sprintf(msg, data...))
		logger.Sync()
	}
}

func (l CustomGormLogger) Error(ctx context.Context, msg string, data ...any) {
	logger, _ := GetZapLogger()
	if logger != nil {
		logger.Error(fmt.Sprintf(msg, data...))
		logger.Sync()
	}
}

func (l CustomGormLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	logger, _ := GetZapLogger()
	if logger != nil {
		elapsed := time.Since(begin)
		sql, rows := fc()
		if err != nil {
			logger.Error("Database query failed",
				zap.String("sql", sql),
				zap.Int64("rows", rows),
				zap.Duration("elapsed", elapsed),
				zap.Error(err))
		} else {
			logger.Info("Database query executed",
				zap.String("sql", sql),
				zap.Int64("rows", rows),
				zap.Duration("elapsed", elapsed))
		}
		logger.Sync()
	}
}

// LogRequest logs incoming HTTP requests
func LogRequest(method, url, remoteAddr string, userAgent string) {
	logger, err := GetZapLogger()
	if err != nil {
		log.Printf("Failed to get logger: %v", err)
		return
	}
	defer logger.Sync()

	logger.Info("HTTP Request",
		zap.String("method", method),
		zap.String("url", url),
		zap.String("remote_addr", remoteAddr),
		zap.String("user_agent", userAgent),
		zap.Time("timestamp", time.Now()),
	)
}

// LogEvent logs security events
func LogEvent(eventType, source, description, severity string, agentID uint) {
	logger, err := GetZapLogger()
	if err != nil {
		log.Printf("Failed to get logger: %v", err)
		return
	}
	defer logger.Sync()

	logger.Info("Security Event",
		zap.String("event_type", eventType),
		zap.String("source", source),
		zap.String("description", description),
		zap.String("severity", severity),
		zap.Uint("agent_id", agentID),
		zap.Time("timestamp", time.Now()),
	)
}

// LogThreat detected by the system
func LogThreat(threat *models.Threat, agentID string) {
	logger, err := GetZapLogger()
	if err != nil {
		log.Printf("Failed to get logger: %v", err)
		return
	}
	defer logger.Sync()

	logger.Info("Threat Detected",
		zap.String("file_path", threat.FilePath),
		zap.String("threat_type", threat.ThreatType),
		zap.String("threat_name", threat.ThreatName),
		zap.String("severity", threat.Severity),
		zap.String("action_taken", threat.ActionTaken),
		zap.String("agent_id", agentID),
		zap.Time("timestamp", time.Now()),
	)
}
