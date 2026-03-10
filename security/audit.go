package security

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EventType classifies security audit events.
type EventType string

const (
	EventAuthFailure    EventType = "auth_failure"
	EventAuthSuccess    EventType = "auth_success"
	EventProbeDetected  EventType = "probe_detected"
	EventRateLimitHit   EventType = "rate_limit_hit"
	EventBruteForce     EventType = "brute_force"
	EventIPBlocked      EventType = "ip_blocked"
	EventIPUnblocked    EventType = "ip_unblocked"
	EventConfigReload   EventType = "config_reload"
	EventServiceStart   EventType = "service_start"
	EventServiceStop    EventType = "service_stop"
	EventCertRenewal    EventType = "cert_renewal"
	EventGeoBlock       EventType = "geo_block"
	EventPortKnock      EventType = "port_knock"
	EventConnectionDrop EventType = "connection_drop"
)

// Severity classifies the severity of an audit event.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// AuditEvent is a single structured audit log entry.
type AuditEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	Event     EventType              `json:"event"`
	Severity  Severity               `json:"severity"`
	Source    string                 `json:"source,omitempty"`
	IPHash    string                 `json:"ip_hash,omitempty"`
	IP        string                 `json:"ip,omitempty"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// AuditLoggerConfig configures the audit logger.
type AuditLoggerConfig struct {
	// LogPath is the directory where audit logs are written.
	LogPath string

	// MaxFileSize is the maximum size of a single log file in bytes
	// before rotation occurs.
	MaxFileSize int64

	// MaxFiles is the maximum number of rotated log files to keep.
	MaxFiles int

	// LogSecurityIPs controls whether full IPs are logged for security events.
	// For regular events, only IP hashes are logged for privacy.
	LogSecurityIPs bool
}

// DefaultAuditLoggerConfig returns sensible defaults.
func DefaultAuditLoggerConfig() AuditLoggerConfig {
	return AuditLoggerConfig{
		LogPath:        "/var/log/hydraflow",
		MaxFileSize:    50 * 1024 * 1024, // 50MB
		MaxFiles:       10,
		LogSecurityIPs: true,
	}
}

// AuditLogger provides structured JSON logging for security events
// with log rotation support and privacy-preserving IP handling.
type AuditLogger struct {
	mu     sync.Mutex
	config AuditLoggerConfig
	logger *slog.Logger

	file        *os.File
	currentSize int64
	currentPath string
}

// NewAuditLogger creates a new audit logger.
func NewAuditLogger(config AuditLoggerConfig, logger *slog.Logger) (*AuditLogger, error) {
	if logger == nil {
		logger = slog.Default()
	}

	if config.LogPath == "" {
		config.LogPath = DefaultAuditLoggerConfig().LogPath
	}
	if config.MaxFileSize <= 0 {
		config.MaxFileSize = DefaultAuditLoggerConfig().MaxFileSize
	}
	if config.MaxFiles <= 0 {
		config.MaxFiles = DefaultAuditLoggerConfig().MaxFiles
	}

	// Ensure log directory exists.
	if err := os.MkdirAll(config.LogPath, 0750); err != nil {
		return nil, fmt.Errorf("create log directory %s: %w", config.LogPath, err)
	}

	al := &AuditLogger{
		config: config,
		logger: logger,
	}

	if err := al.openLogFile(); err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	return al, nil
}

// Log records a security audit event.
func (al *AuditLogger) Log(event AuditEvent) {
	al.mu.Lock()
	defer al.mu.Unlock()

	// Set timestamp if not provided.
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Privacy: hash IPs for non-security events.
	if event.IP != "" {
		if al.isSecurityEvent(event.Event) && al.config.LogSecurityIPs {
			// Keep full IP for security events.
			event.IPHash = hashIPForLog(event.IP)
		} else {
			// Hash IP for privacy.
			event.IPHash = hashIPForLog(event.IP)
			event.IP = "" // clear raw IP
		}
	}

	data, err := json.Marshal(event)
	if err != nil {
		al.logger.Error("failed to marshal audit event", "error", err)
		return
	}
	data = append(data, '\n')

	// Check if rotation is needed.
	if al.currentSize+int64(len(data)) > al.config.MaxFileSize {
		if err := al.rotate(); err != nil {
			al.logger.Error("log rotation failed", "error", err)
		}
	}

	if al.file != nil {
		n, err := al.file.Write(data)
		if err != nil {
			al.logger.Error("failed to write audit event", "error", err)
			return
		}
		al.currentSize += int64(n)
	}

	// Also log to slog for observability.
	al.logger.Info("audit event",
		"event", string(event.Event),
		"severity", string(event.Severity),
		"message", event.Message,
	)
}

// LogAuthFailure logs a failed authentication attempt.
func (al *AuditLogger) LogAuthFailure(ip, username, reason string) {
	al.Log(AuditEvent{
		Event:    EventAuthFailure,
		Severity: SeverityWarning,
		IP:       ip,
		Message:  fmt.Sprintf("authentication failed for user %q: %s", username, reason),
		Details: map[string]interface{}{
			"username": username,
			"reason":   reason,
		},
	})
}

// LogAuthSuccess logs a successful authentication.
func (al *AuditLogger) LogAuthSuccess(ip, username string) {
	al.Log(AuditEvent{
		Event:    EventAuthSuccess,
		Severity: SeverityInfo,
		IP:       ip,
		Message:  fmt.Sprintf("authentication successful for user %q", username),
		Details: map[string]interface{}{
			"username": username,
		},
	})
}

// LogProbeDetected logs a detected active probing attempt.
func (al *AuditLogger) LogProbeDetected(ip string, details map[string]interface{}) {
	al.Log(AuditEvent{
		Event:    EventProbeDetected,
		Severity: SeverityWarning,
		IP:       ip,
		Message:  "active probing attempt detected",
		Details:  details,
	})
}

// LogRateLimitHit logs a rate limit violation.
func (al *AuditLogger) LogRateLimitHit(ip string, limit int) {
	al.Log(AuditEvent{
		Event:    EventRateLimitHit,
		Severity: SeverityWarning,
		IP:       ip,
		Message:  fmt.Sprintf("rate limit exceeded (limit: %d)", limit),
		Details: map[string]interface{}{
			"limit": limit,
		},
	})
}

// LogBruteForce logs a brute force lockout.
func (al *AuditLogger) LogBruteForce(ip string, attempts int) {
	al.Log(AuditEvent{
		Event:    EventBruteForce,
		Severity: SeverityCritical,
		IP:       ip,
		Message:  fmt.Sprintf("IP locked out after %d failed attempts", attempts),
		Details: map[string]interface{}{
			"attempts": attempts,
		},
	})
}

// LogIPBlocked logs an IP being blocked.
func (al *AuditLogger) LogIPBlocked(ip, reason string) {
	al.Log(AuditEvent{
		Event:    EventIPBlocked,
		Severity: SeverityCritical,
		IP:       ip,
		Message:  fmt.Sprintf("IP blocked: %s", reason),
		Details: map[string]interface{}{
			"reason": reason,
		},
	})
}

// LogServiceEvent logs a service lifecycle event.
func (al *AuditLogger) LogServiceEvent(eventType EventType, message string) {
	al.Log(AuditEvent{
		Event:    eventType,
		Severity: SeverityInfo,
		Source:   "system",
		Message:  message,
	})
}

// Close flushes and closes the audit log file.
func (al *AuditLogger) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()

	if al.file != nil {
		return al.file.Close()
	}
	return nil
}

// ---- Internal methods ----

func (al *AuditLogger) openLogFile() error {
	path := filepath.Join(al.config.LogPath, "audit.log")

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}

	al.file = f
	al.currentSize = info.Size()
	al.currentPath = path
	return nil
}

func (al *AuditLogger) rotate() error {
	if al.file != nil {
		al.file.Close()
		al.file = nil
	}

	// Rotate existing files.
	basePath := filepath.Join(al.config.LogPath, "audit.log")

	// Remove the oldest file if at max.
	oldestPath := fmt.Sprintf("%s.%d", basePath, al.config.MaxFiles)
	os.Remove(oldestPath)

	// Shift files: audit.log.9 -> audit.log.10, etc.
	for i := al.config.MaxFiles - 1; i >= 1; i-- {
		oldPath := fmt.Sprintf("%s.%d", basePath, i)
		newPath := fmt.Sprintf("%s.%d", basePath, i+1)
		os.Rename(oldPath, newPath)
	}

	// Move current log to .1
	os.Rename(basePath, basePath+".1")

	// Open new log file.
	return al.openLogFile()
}

func (al *AuditLogger) isSecurityEvent(event EventType) bool {
	switch event {
	case EventAuthFailure, EventBruteForce, EventIPBlocked, EventProbeDetected:
		return true
	default:
		return false
	}
}
