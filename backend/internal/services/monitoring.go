package services

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// MetricType represents different types of metrics
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeSummary   MetricType = "summary"
	MetricTypeTimer     MetricType = "timer"
)

// AlertSeverity represents the severity level of alerts
type AlertSeverity string

const (
	AlertSeverityLow      AlertSeverity = "low"
	AlertSeverityMedium   AlertSeverity = "medium"
	AlertSeverityHigh     AlertSeverity = "high"
	AlertSeverityCritical AlertSeverity = "critical"
)

// AlertStatus represents the status of an alert
type AlertStatus string

const (
	AlertStatusOpen     AlertStatus = "open"
	AlertStatusAcknowledged AlertStatus = "acknowledged"
	AlertStatusResolved AlertStatus = "resolved"
	AlertStatusClosed   AlertStatus = "closed"
)

// Metric represents a system metric
type Metric struct {
	ID          string                 `json:"id" gorm:"primaryKey"`
	Name        string                 `json:"name"`
	Type        MetricType             `json:"type"`
	Value       float64                `json:"value"`
	Labels      map[string]string      `json:"labels" gorm:"type:jsonb"`
	Timestamp   time.Time              `json:"timestamp"`
	Source      string                 `json:"source"`
	Unit        string                 `json:"unit"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata" gorm:"type:jsonb"`
	CreatedAt   time.Time              `json:"created_at"`
}

// Alert represents a system alert
type Alert struct {
	ID             string                 `json:"id" gorm:"primaryKey"`
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	Severity       AlertSeverity          `json:"severity"`
	Status         AlertStatus            `json:"status"`
	Source         string                 `json:"source"`
	MetricName     string                 `json:"metric_name"`
	Threshold      float64                `json:"threshold"`
	CurrentValue   float64                `json:"current_value"`
	Condition      string                 `json:"condition"` // greater_than, less_than, equals, not_equals
	Duration       time.Duration          `json:"duration"`
	Recipients     []string               `json:"recipients" gorm:"type:jsonb"`
	Channels       []string               `json:"channels" gorm:"type:jsonb"` // email, sms, slack, webhook
	NotificationsSent int                 `json:"notifications_sent"`
	LastNotified   *time.Time             `json:"last_notified,omitempty"`
	AcknowledgedBy *string                `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time             `json:"acknowledged_at,omitempty"`
	ResolvedBy     *string                `json:"resolved_by,omitempty"`
	ResolvedAt     *time.Time             `json:"resolved_at,omitempty"`
	Tags           []string               `json:"tags" gorm:"type:jsonb"`
	Runbook        string                 `json:"runbook"`
	Metadata       map[string]interface{} `json:"metadata" gorm:"type:jsonb"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	TriggeredAt    time.Time              `json:"triggered_at"`
}

// PerformanceMetrics holds comprehensive system performance data
type PerformanceMetrics struct {
	SystemMetrics    SystemMetrics    `json:"system_metrics"`
	ApplicationMetrics ApplicationMetrics `json:"application_metrics"`
	DatabaseMetrics  DatabaseMetrics  `json:"database_metrics"`
	SecurityMetrics  SecurityMetrics  `json:"security_metrics"`
	BusinessMetrics  BusinessMetrics  `json:"business_metrics"`
	Timestamp        time.Time        `json:"timestamp"`
}

// SystemMetrics holds system-level performance metrics
type SystemMetrics struct {
	CPUUsage          float64          `json:"cpu_usage"`
	MemoryUsage       float64          `json:"memory_usage"`
	MemoryTotal       uint64           `json:"memory_total"`
	MemoryUsed        uint64           `json:"memory_used"`
	DiskUsage         map[string]float64 `json:"disk_usage"`
	NetworkRx         uint64           `json:"network_rx"`
	NetworkTx         uint64           `json:"network_tx"`
	LoadAverage       []float64        `json:"load_average"`
	Goroutines        int              `json:"goroutines"`
	GCStats           debug.GCStats    `json:"gc_stats"`
	Uptime            time.Duration    `json:"uptime"`
}

// ApplicationMetrics holds application-specific metrics
type ApplicationMetrics struct {
	RequestsTotal        int64             `json:"requests_total"`
	RequestsPerSecond    float64           `json:"requests_per_second"`
	ResponseTimeP50      time.Duration     `json:"response_time_p50"`
	ResponseTimeP95      time.Duration     `json:"response_time_p95"`
	ResponseTimeP99      time.Duration     `json:"response_time_p99"`
	ErrorRate            float64           `json:"error_rate"`
	ActiveConnections    int               `json:"active_connections"`
	QueueSize            int               `json:"queue_size"`
	CacheHitRate         float64           `json:"cache_hit_rate"`
	SessionCount         int               `json:"session_count"`
	EndpointMetrics      map[string]EndpointMetric `json:"endpoint_metrics"`
}

// EndpointMetric holds metrics for specific API endpoints
type EndpointMetric struct {
	Path           string        `json:"path"`
	Method         string        `json:"method"`
	RequestCount   int64         `json:"request_count"`
	ErrorCount     int64         `json:"error_count"`
	AverageLatency time.Duration `json:"average_latency"`
	MaxLatency     time.Duration `json:"max_latency"`
	MinLatency     time.Duration `json:"min_latency"`
}

// DatabaseMetrics holds database performance metrics
type DatabaseMetrics struct {
	ConnectionsActive    int           `json:"connections_active"`
	ConnectionsIdle      int           `json:"connections_idle"`
	ConnectionsTotal     int           `json:"connections_total"`
	QueriesTotal         int64         `json:"queries_total"`
	QueriesPerSecond     float64       `json:"queries_per_second"`
	QueryTimeP50         time.Duration `json:"query_time_p50"`
	QueryTimeP95         time.Duration `json:"query_time_p95"`
	QueryTimeP99         time.Duration `json:"query_time_p99"`
	SlowQueries          int64         `json:"slow_queries"`
	DatabaseSize         int64         `json:"database_size"`
	TableSizes           map[string]int64 `json:"table_sizes"`
	LockWaits            int64         `json:"lock_waits"`
	Deadlocks            int64         `json:"deadlocks"`
	BufferCacheHitRatio  float64       `json:"buffer_cache_hit_ratio"`
}

// SecurityMetrics holds security-related metrics
type SecurityMetrics struct {
	AuthenticationAttempts int64   `json:"authentication_attempts"`
	AuthenticationFailures int64   `json:"authentication_failures"`
	AuthenticationSuccessRate float64 `json:"authentication_success_rate"`
	SecurityIncidents      int64   `json:"security_incidents"`
	BlockedIPs             int64   `json:"blocked_ips"`
	ThreatScore            float64 `json:"threat_score"`
	VulnerabilityCount     int64   `json:"vulnerability_count"`
	ComplianceScore        float64 `json:"compliance_score"`
	EncryptionOperations   int64   `json:"encryption_operations"`
	MFAActivations         int64   `json:"mfa_activations"`
}

// BusinessMetrics holds business-related metrics
type BusinessMetrics struct {
	ActiveUsers            int64   `json:"active_users"`
	NewRegistrations       int64   `json:"new_registrations"`
	VaultItemsCreated      int64   `json:"vault_items_created"`
	VaultItemsAccessed     int64   `json:"vault_items_accessed"`
	BackupsCompleted       int64   `json:"backups_completed"`
	RestoreOperations      int64   `json:"restore_operations"`
	UserRetentionRate      float64 `json:"user_retention_rate"`
	AverageSessionDuration time.Duration `json:"average_session_duration"`
	FeatureUsageStats      map[string]int64 `json:"feature_usage_stats"`
}

// AlertRule defines conditions for triggering alerts
type AlertRule struct {
	ID          string                 `json:"id" gorm:"primaryKey"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	MetricName  string                 `json:"metric_name"`
	Condition   string                 `json:"condition"`
	Threshold   float64                `json:"threshold"`
	Duration    time.Duration          `json:"duration"`
	Severity    AlertSeverity          `json:"severity"`
	Recipients  []string               `json:"recipients" gorm:"type:jsonb"`
	Channels    []string               `json:"channels" gorm:"type:jsonb"`
	Tags        []string               `json:"tags" gorm:"type:jsonb"`
	Enabled     bool                   `json:"enabled"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// MonitoringService provides comprehensive system monitoring and alerting
type MonitoringService struct {
	db             *gorm.DB
	metrics        map[string]*Metric
	alerts         map[string]*Alert
	alertRules     map[string]*AlertRule
	mutex          sync.RWMutex
	startTime      time.Time
	metricsChan    chan *Metric
	alertsChan     chan *Alert
	notificationSvc interface{}
	auditSvc       interface{}
	config         *MonitoringConfig
}

// MonitoringConfig holds monitoring configuration
type MonitoringConfig struct {
	MetricsInterval    time.Duration `json:"metrics_interval"`
	AlertCheckInterval time.Duration `json:"alert_check_interval"`
	RetentionPeriod    time.Duration `json:"retention_period"`
	BatchSize          int           `json:"batch_size"`
	MaxMetrics         int           `json:"max_metrics"`
	EnableProfiling    bool          `json:"enable_profiling"`
	EnableHealthChecks bool          `json:"enable_health_checks"`
}

// NewMonitoringService creates a new monitoring service
func NewMonitoringService(db *gorm.DB) *MonitoringService {
	config := &MonitoringConfig{
		MetricsInterval:    30 * time.Second,
		AlertCheckInterval: 10 * time.Second,
		RetentionPeriod:    30 * 24 * time.Hour, // 30 days
		BatchSize:          100,
		MaxMetrics:         10000,
		EnableProfiling:    true,
		EnableHealthChecks: true,
	}

	ms := &MonitoringService{
		db:          db,
		metrics:     make(map[string]*Metric),
		alerts:      make(map[string]*Alert),
		alertRules:  make(map[string]*AlertRule),
		startTime:   time.Now(),
		metricsChan: make(chan *Metric, 1000),
		alertsChan:  make(chan *Alert, 100),
		config:      config,
	}

	// Auto-migrate database tables
	db.AutoMigrate(&Metric{}, &Alert{}, &AlertRule{})

	// Initialize default alert rules
	ms.initializeDefaultAlertRules()

	// Start background workers
	go ms.metricsCollectionWorker()
	go ms.alertProcessingWorker()
	go ms.cleanupWorker()

	return ms
}

// initializeDefaultAlertRules creates default alert rules
func (ms *MonitoringService) initializeDefaultAlertRules() {
	defaultRules := []*AlertRule{
		{
			ID:          uuid.New().String(),
			Name:        "High CPU Usage",
			Description: "CPU usage is above 80%",
			MetricName:  "system.cpu.usage",
			Condition:   "greater_than",
			Threshold:   80.0,
			Duration:    5 * time.Minute,
			Severity:    AlertSeverityHigh,
			Recipients:  []string{"admin@securevault.com"},
			Channels:    []string{"email", "slack"},
			Tags:        []string{"system", "performance"},
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          uuid.New().String(),
			Name:        "High Memory Usage",
			Description: "Memory usage is above 85%",
			MetricName:  "system.memory.usage",
			Condition:   "greater_than",
			Threshold:   85.0,
			Duration:    5 * time.Minute,
			Severity:    AlertSeverityHigh,
			Recipients:  []string{"admin@securevault.com"},
			Channels:    []string{"email"},
			Tags:        []string{"system", "memory"},
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          uuid.New().String(),
			Name:        "High Error Rate",
			Description: "Application error rate is above 5%",
			MetricName:  "app.error.rate",
			Condition:   "greater_than",
			Threshold:   5.0,
			Duration:    2 * time.Minute,
			Severity:    AlertSeverityCritical,
			Recipients:  []string{"admin@securevault.com", "dev@securevault.com"},
			Channels:    []string{"email", "sms", "slack"},
			Tags:        []string{"application", "errors"},
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          uuid.New().String(),
			Name:        "Database Connection Pool Exhausted",
			Description: "Database connection pool is at maximum capacity",
			MetricName:  "db.connections.active",
			Condition:   "greater_than",
			Threshold:   95.0,
			Duration:    1 * time.Minute,
			Severity:    AlertSeverityCritical,
			Recipients:  []string{"admin@securevault.com", "dba@securevault.com"},
			Channels:    []string{"email", "sms"},
			Tags:        []string{"database", "connections"},
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          uuid.New().String(),
			Name:        "Security Incident Threshold",
			Description: "High number of security incidents detected",
			MetricName:  "security.incidents.count",
			Condition:   "greater_than",
			Threshold:   10.0,
			Duration:    1 * time.Minute,
			Severity:    AlertSeverityCritical,
			Recipients:  []string{"security@securevault.com", "admin@securevault.com"},
			Channels:    []string{"email", "sms", "slack"},
			Tags:        []string{"security", "incidents"},
			Enabled:     true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for _, rule := range defaultRules {
		ms.alertRules[rule.ID] = rule
		ms.db.Create(rule)
	}
}

// CollectMetrics gathers comprehensive system metrics
func (ms *MonitoringService) CollectMetrics() *PerformanceMetrics {
	metrics := &PerformanceMetrics{
		SystemMetrics:      ms.collectSystemMetrics(),
		ApplicationMetrics: ms.collectApplicationMetrics(),
		DatabaseMetrics:    ms.collectDatabaseMetrics(),
		SecurityMetrics:    ms.collectSecurityMetrics(),
		BusinessMetrics:    ms.collectBusinessMetrics(),
		Timestamp:          time.Now(),
	}

	// Store individual metrics
	ms.storeSystemMetrics(metrics.SystemMetrics)
	ms.storeApplicationMetrics(metrics.ApplicationMetrics)
	ms.storeDatabaseMetrics(metrics.DatabaseMetrics)
	ms.storeSecurityMetrics(metrics.SecurityMetrics)
	ms.storeBusinessMetrics(metrics.BusinessMetrics)

	return metrics
}

// collectSystemMetrics gathers system-level metrics
func (ms *MonitoringService) collectSystemMetrics() SystemMetrics {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	var gcStats debug.GCStats
	debug.ReadGCStats(&gcStats)

	return SystemMetrics{
		CPUUsage:      ms.getCPUUsage(),
		MemoryUsage:   ms.getMemoryUsagePercentage(),
		MemoryTotal:   memStats.Sys,
		MemoryUsed:    memStats.Alloc,
		DiskUsage:     ms.getDiskUsage(),
		NetworkRx:     ms.getNetworkRx(),
		NetworkTx:     ms.getNetworkTx(),
		LoadAverage:   ms.getLoadAverage(),
		Goroutines:    runtime.NumGoroutine(),
		GCStats:       gcStats,
		Uptime:        time.Since(ms.startTime),
	}
}

// collectApplicationMetrics gathers application-specific metrics
func (ms *MonitoringService) collectApplicationMetrics() ApplicationMetrics {
	return ApplicationMetrics{
		RequestsTotal:     ms.getRequestsTotal(),
		RequestsPerSecond: ms.getRequestsPerSecond(),
		ResponseTimeP50:   ms.getResponseTimePercentile(50),
		ResponseTimeP95:   ms.getResponseTimePercentile(95),
		ResponseTimeP99:   ms.getResponseTimePercentile(99),
		ErrorRate:         ms.getErrorRate(),
		ActiveConnections: ms.getActiveConnections(),
		QueueSize:         ms.getQueueSize(),
		CacheHitRate:      ms.getCacheHitRate(),
		SessionCount:      ms.getSessionCount(),
		EndpointMetrics:   ms.getEndpointMetrics(),
	}
}

// collectDatabaseMetrics gathers database performance metrics
func (ms *MonitoringService) collectDatabaseMetrics() DatabaseMetrics {
	return DatabaseMetrics{
		ConnectionsActive:   ms.getDBConnectionsActive(),
		ConnectionsIdle:     ms.getDBConnectionsIdle(),
		ConnectionsTotal:    ms.getDBConnectionsTotal(),
		QueriesTotal:        ms.getDBQueriesTotal(),
		QueriesPerSecond:    ms.getDBQueriesPerSecond(),
		QueryTimeP50:        ms.getDBQueryTimePercentile(50),
		QueryTimeP95:        ms.getDBQueryTimePercentile(95),
		QueryTimeP99:        ms.getDBQueryTimePercentile(99),
		SlowQueries:         ms.getDBSlowQueries(),
		DatabaseSize:        ms.getDBSize(),
		TableSizes:          ms.getTableSizes(),
		LockWaits:           ms.getDBLockWaits(),
		Deadlocks:           ms.getDBDeadlocks(),
		BufferCacheHitRatio: ms.getDBBufferCacheHitRatio(),
	}
}

// collectSecurityMetrics gathers security-related metrics
func (ms *MonitoringService) collectSecurityMetrics() SecurityMetrics {
	return SecurityMetrics{
		AuthenticationAttempts:    ms.getAuthAttempts(),
		AuthenticationFailures:    ms.getAuthFailures(),
		AuthenticationSuccessRate: ms.getAuthSuccessRate(),
		SecurityIncidents:         ms.getSecurityIncidents(),
		BlockedIPs:                ms.getBlockedIPs(),
		ThreatScore:               ms.getThreatScore(),
		VulnerabilityCount:        ms.getVulnerabilityCount(),
		ComplianceScore:           ms.getComplianceScore(),
		EncryptionOperations:      ms.getEncryptionOperations(),
		MFAActivations:            ms.getMFAActivations(),
	}
}

// collectBusinessMetrics gathers business-related metrics
func (ms *MonitoringService) collectBusinessMetrics() BusinessMetrics {
	return BusinessMetrics{
		ActiveUsers:            ms.getActiveUsers(),
		NewRegistrations:       ms.getNewRegistrations(),
		VaultItemsCreated:      ms.getVaultItemsCreated(),
		VaultItemsAccessed:     ms.getVaultItemsAccessed(),
		BackupsCompleted:       ms.getBackupsCompleted(),
		RestoreOperations:      ms.getRestoreOperations(),
		UserRetentionRate:      ms.getUserRetentionRate(),
		AverageSessionDuration: ms.getAverageSessionDuration(),
		FeatureUsageStats:      ms.getFeatureUsageStats(),
	}
}

// RecordMetric records a new metric
func (ms *MonitoringService) RecordMetric(name string, metricType MetricType, value float64, labels map[string]string) {
	metric := &Metric{
		ID:          uuid.New().String(),
		Name:        name,
		Type:        metricType,
		Value:       value,
		Labels:      labels,
		Timestamp:   time.Now(),
		Source:      "application",
		CreatedAt:   time.Now(),
	}

	select {
	case ms.metricsChan <- metric:
		// Metric queued successfully
	default:
		// Channel full, metric dropped
		fmt.Printf("Warning: Metrics channel full, dropping metric: %s\n", name)
	}
}

// TriggerAlert creates and processes a new alert
func (ms *MonitoringService) TriggerAlert(ruleName, description string, severity AlertSeverity, value float64) {
	alert := &Alert{
		ID:           uuid.New().String(),
		Name:         ruleName,
		Description:  description,
		Severity:     severity,
		Status:       AlertStatusOpen,
		Source:       "monitoring",
		CurrentValue: value,
		TriggeredAt:  time.Now(),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	select {
	case ms.alertsChan <- alert:
		// Alert queued successfully
	default:
		// Channel full, alert dropped (should not happen for critical alerts)
		fmt.Printf("Warning: Alerts channel full, dropping alert: %s\n", ruleName)
	}
}

// GetMetrics retrieves metrics with filtering and pagination
func (ms *MonitoringService) GetMetrics(filters map[string]interface{}, page, limit int) ([]Metric, int64, error) {
	var metrics []Metric
	var total int64

	query := ms.db.Model(&Metric{})

	// Apply filters
	if name, ok := filters["name"]; ok {
		query = query.Where("name = ?", name)
	}
	if metricType, ok := filters["type"]; ok {
		query = query.Where("type = ?", metricType)
	}
	if source, ok := filters["source"]; ok {
		query = query.Where("source = ?", source)
	}
	if from, ok := filters["from"]; ok {
		query = query.Where("timestamp >= ?", from)
	}
	if to, ok := filters["to"]; ok {
		query = query.Where("timestamp <= ?", to)
	}

	query.Count(&total)

	offset := (page - 1) * limit
	err := query.Order("timestamp DESC").
		Offset(offset).
		Limit(limit).
		Find(&metrics).Error

	return metrics, total, err
}

// GetAlerts retrieves alerts with filtering and pagination
func (ms *MonitoringService) GetAlerts(filters map[string]interface{}, page, limit int) ([]Alert, int64, error) {
	var alerts []Alert
	var total int64

	query := ms.db.Model(&Alert{})

	// Apply filters
	if status, ok := filters["status"]; ok {
		query = query.Where("status = ?", status)
	}
	if severity, ok := filters["severity"]; ok {
		query = query.Where("severity = ?", severity)
	}
	if source, ok := filters["source"]; ok {
		query = query.Where("source = ?", source)
	}
	if from, ok := filters["from"]; ok {
		query = query.Where("created_at >= ?", from)
	}
	if to, ok := filters["to"]; ok {
		query = query.Where("created_at <= ?", to)
	}

	query.Count(&total)

	offset := (page - 1) * limit
	err := query.Order("created_at DESC").
		Offset(offset).
		Limit(limit).
		Find(&alerts).Error

	return alerts, total, err
}

// AcknowledgeAlert acknowledges an alert
func (ms *MonitoringService) AcknowledgeAlert(alertID, userID string) error {
	now := time.Now()
	return ms.db.Model(&Alert{}).
		Where("id = ?", alertID).
		Updates(map[string]interface{}{
			"status":           AlertStatusAcknowledged,
			"acknowledged_by":  userID,
			"acknowledged_at":  now,
			"updated_at":       now,
		}).Error
}

// ResolveAlert resolves an alert
func (ms *MonitoringService) ResolveAlert(alertID, userID string) error {
	now := time.Time{}
	return ms.db.Model(&Alert{}).
		Where("id = ?", alertID).
		Updates(map[string]interface{}{
			"status":      AlertStatusResolved,
			"resolved_by": userID,
			"resolved_at": now,
			"updated_at":  now,
		}).Error
}

// Background workers

// metricsCollectionWorker processes metrics in the background
func (ms *MonitoringService) metricsCollectionWorker() {
	ticker := time.NewTicker(ms.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case metric := <-ms.metricsChan:
			ms.processMetric(metric)
		case <-ticker.C:
			ms.CollectMetrics()
		}
	}
}

// alertProcessingWorker processes alerts in the background
func (ms *MonitoringService) alertProcessingWorker() {
	ticker := time.NewTicker(ms.config.AlertCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case alert := <-ms.alertsChan:
			ms.processAlert(alert)
		case <-ticker.C:
			ms.evaluateAlertRules()
		}
	}
}

// cleanupWorker removes old metrics and alerts
func (ms *MonitoringService) cleanupWorker() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-ms.config.RetentionPeriod)
		
		// Clean old metrics
		ms.db.Where("created_at < ?", cutoff).Delete(&Metric{})
		
		// Clean resolved alerts older than retention period
		ms.db.Where("created_at < ? AND status IN (?)", cutoff, []AlertStatus{AlertStatusResolved, AlertStatusClosed}).Delete(&Alert{})
	}
}

// Helper methods for collecting specific metrics
func (ms *MonitoringService) getCPUUsage() float64 {
	// Mock implementation - would use system calls in production
	return 45.2
}

func (ms *MonitoringService) getMemoryUsagePercentage() float64 {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	// Mock calculation - would use system memory info in production
	return 67.8
}

func (ms *MonitoringService) getDiskUsage() map[string]float64 {
	// Mock implementation
	return map[string]float64{
		"/":     25.4,
		"/data": 89.2,
		"/logs": 45.6,
	}
}

func (ms *MonitoringService) getNetworkRx() uint64 { return 1024 * 1024 * 150 } // 150MB
func (ms *MonitoringService) getNetworkTx() uint64 { return 1024 * 1024 * 89 }  // 89MB

func (ms *MonitoringService) getLoadAverage() []float64 {
	return []float64{1.2, 1.5, 1.8}
}

func (ms *MonitoringService) getRequestsTotal() int64        { return 125430 }
func (ms *MonitoringService) getRequestsPerSecond() float64  { return 45.2 }
func (ms *MonitoringService) getErrorRate() float64          { return 0.8 }
func (ms *MonitoringService) getActiveConnections() int     { return 234 }
func (ms *MonitoringService) getQueueSize() int            { return 12 }
func (ms *MonitoringService) getCacheHitRate() float64     { return 94.5 }
func (ms *MonitoringService) getSessionCount() int         { return 189 }

func (ms *MonitoringService) getResponseTimePercentile(percentile int) time.Duration {
	switch percentile {
	case 50:
		return 125 * time.Millisecond
	case 95:
		return 450 * time.Millisecond
	case 99:
		return 850 * time.Millisecond
	default:
		return 200 * time.Millisecond
	}
}

func (ms *MonitoringService) getEndpointMetrics() map[string]EndpointMetric {
	return map[string]EndpointMetric{
		"/api/v1/auth/login": {
			Path:           "/api/v1/auth/login",
			Method:         "POST",
			RequestCount:   5432,
			ErrorCount:     23,
			AverageLatency: 156 * time.Millisecond,
			MaxLatency:     890 * time.Millisecond,
			MinLatency:     45 * time.Millisecond,
		},
		"/api/v1/vault/items": {
			Path:           "/api/v1/vault/items",
			Method:         "GET",
			RequestCount:   8976,
			ErrorCount:     12,
			AverageLatency: 89 * time.Millisecond,
			MaxLatency:     234 * time.Millisecond,
			MinLatency:     23 * time.Millisecond,
		},
	}
}

// Database metrics helpers
func (ms *MonitoringService) getDBConnectionsActive() int { return 12 }
func (ms *MonitoringService) getDBConnectionsIdle() int   { return 8 }
func (ms *MonitoringService) getDBConnectionsTotal() int  { return 20 }
func (ms *MonitoringService) getDBQueriesTotal() int64    { return 89234 }
func (ms *MonitoringService) getDBQueriesPerSecond() float64 { return 67.3 }
func (ms *MonitoringService) getDBSlowQueries() int64     { return 23 }
func (ms *MonitoringService) getDBSize() int64            { return 1024 * 1024 * 1024 * 2 } // 2GB
func (ms *MonitoringService) getDBLockWaits() int64       { return 5 }
func (ms *MonitoringService) getDBDeadlocks() int64       { return 1 }
func (ms *MonitoringService) getDBBufferCacheHitRatio() float64 { return 98.5 }

func (ms *MonitoringService) getDBQueryTimePercentile(percentile int) time.Duration {
	switch percentile {
	case 50:
		return 15 * time.Millisecond
	case 95:
		return 89 * time.Millisecond
	case 99:
		return 234 * time.Millisecond
	default:
		return 25 * time.Millisecond
	}
}

func (ms *MonitoringService) getTableSizes() map[string]int64 {
	return map[string]int64{
		"users":        1024 * 1024 * 45,  // 45MB
		"vault_items":  1024 * 1024 * 234, // 234MB
		"audit_logs":   1024 * 1024 * 567, // 567MB
		"sessions":     1024 * 1024 * 12,  // 12MB
	}
}

// Security metrics helpers
func (ms *MonitoringService) getAuthAttempts() int64     { return 3456 }
func (ms *MonitoringService) getAuthFailures() int64     { return 89 }
func (ms *MonitoringService) getAuthSuccessRate() float64 { return 97.4 }
func (ms *MonitoringService) getSecurityIncidents() int64 { return 12 }
func (ms *MonitoringService) getBlockedIPs() int64       { return 234 }
func (ms *MonitoringService) getThreatScore() float64    { return 25.6 }
func (ms *MonitoringService) getVulnerabilityCount() int64 { return 3 }
func (ms *MonitoringService) getComplianceScore() float64 { return 94.8 }
func (ms *MonitoringService) getEncryptionOperations() int64 { return 89567 }
func (ms *MonitoringService) getMFAActivations() int64   { return 1234 }

// Business metrics helpers
func (ms *MonitoringService) getActiveUsers() int64           { return 1234 }
func (ms *MonitoringService) getNewRegistrations() int64      { return 45 }
func (ms *MonitoringService) getVaultItemsCreated() int64     { return 234 }
func (ms *MonitoringService) getVaultItemsAccessed() int64    { return 5678 }
func (ms *MonitoringService) getBackupsCompleted() int64      { return 12 }
func (ms *MonitoringService) getRestoreOperations() int64     { return 2 }
func (ms *MonitoringService) getUserRetentionRate() float64   { return 89.5 }
func (ms *MonitoringService) getAverageSessionDuration() time.Duration { return 25 * time.Minute }

func (ms *MonitoringService) getFeatureUsageStats() map[string]int64 {
	return map[string]int64{
		"password_generator": 567,
		"secure_sharing":     234,
		"two_factor_auth":    1234,
		"backup_restore":     45,
		"mobile_sync":        890,
	}
}

// Processing methods
func (ms *MonitoringService) processMetric(metric *Metric) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// Store in memory cache
	ms.metrics[metric.ID] = metric

	// Persist to database
	ms.db.Create(metric)

	// Check if metric should trigger any alerts
	ms.checkMetricAlerts(metric)
}

func (ms *MonitoringService) processAlert(alert *Alert) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// Store in memory cache
	ms.alerts[alert.ID] = alert

	// Persist to database
	ms.db.Create(alert)

	// Send notifications
	ms.sendAlertNotifications(alert)
}

func (ms *MonitoringService) checkMetricAlerts(metric *Metric) {
	for _, rule := range ms.alertRules {
		if !rule.Enabled || rule.MetricName != metric.Name {
			continue
		}

		shouldTrigger := false
		switch rule.Condition {
		case "greater_than":
			shouldTrigger = metric.Value > rule.Threshold
		case "less_than":
			shouldTrigger = metric.Value < rule.Threshold
		case "equals":
			shouldTrigger = metric.Value == rule.Threshold
		case "not_equals":
			shouldTrigger = metric.Value != rule.Threshold
		}

		if shouldTrigger {
			alert := &Alert{
				ID:           uuid.New().String(),
				Name:         rule.Name,
				Description:  rule.Description,
				Severity:     rule.Severity,
				Status:       AlertStatusOpen,
				Source:       "rule_engine",
				MetricName:   rule.MetricName,
				Threshold:    rule.Threshold,
				CurrentValue: metric.Value,
				Condition:    rule.Condition,
				Duration:     rule.Duration,
				Recipients:   rule.Recipients,
				Channels:     rule.Channels,
				Tags:         rule.Tags,
				TriggeredAt:  time.Now(),
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			}

			select {
			case ms.alertsChan <- alert:
				// Alert queued
			default:
				// Channel full
			}
		}
	}
}

func (ms *MonitoringService) evaluateAlertRules() {
	// This would be called periodically to evaluate complex alert rules
	// that might require aggregated metrics or time-based conditions
}

func (ms *MonitoringService) sendAlertNotifications(alert *Alert) {
	// Implementation would integrate with notification services
	// For now, just log the alert
	fmt.Printf("ALERT [%s]: %s - %s (Value: %.2f, Threshold: %.2f)\n",
		alert.Severity, alert.Name, alert.Description, alert.CurrentValue, alert.Threshold)
}

// Store methods for different metric types
func (ms *MonitoringService) storeSystemMetrics(metrics SystemMetrics) {
	ms.RecordMetric("system.cpu.usage", MetricTypeGauge, metrics.CPUUsage, map[string]string{"type": "system"})
	ms.RecordMetric("system.memory.usage", MetricTypeGauge, metrics.MemoryUsage, map[string]string{"type": "system"})
	ms.RecordMetric("system.goroutines", MetricTypeGauge, float64(metrics.Goroutines), map[string]string{"type": "runtime"})
}

func (ms *MonitoringService) storeApplicationMetrics(metrics ApplicationMetrics) {
	ms.RecordMetric("app.requests.total", MetricTypeCounter, float64(metrics.RequestsTotal), map[string]string{"type": "application"})
	ms.RecordMetric("app.requests.per_second", MetricTypeGauge, metrics.RequestsPerSecond, map[string]string{"type": "application"})
	ms.RecordMetric("app.error.rate", MetricTypeGauge, metrics.ErrorRate, map[string]string{"type": "application"})
}

func (ms *MonitoringService) storeDatabaseMetrics(metrics DatabaseMetrics) {
	ms.RecordMetric("db.connections.active", MetricTypeGauge, float64(metrics.ConnectionsActive), map[string]string{"type": "database"})
	ms.RecordMetric("db.queries.total", MetricTypeCounter, float64(metrics.QueriesTotal), map[string]string{"type": "database"})
	ms.RecordMetric("db.queries.per_second", MetricTypeGauge, metrics.QueriesPerSecond, map[string]string{"type": "database"})
}

func (ms *MonitoringService) storeSecurityMetrics(metrics SecurityMetrics) {
	ms.RecordMetric("security.incidents.count", MetricTypeCounter, float64(metrics.SecurityIncidents), map[string]string{"type": "security"})
	ms.RecordMetric("security.blocked_ips", MetricTypeGauge, float64(metrics.BlockedIPs), map[string]string{"type": "security"})
	ms.RecordMetric("security.threat_score", MetricTypeGauge, metrics.ThreatScore, map[string]string{"type": "security"})
}

func (ms *MonitoringService) storeBusinessMetrics(metrics BusinessMetrics) {
	ms.RecordMetric("business.active_users", MetricTypeGauge, float64(metrics.ActiveUsers), map[string]string{"type": "business"})
	ms.RecordMetric("business.new_registrations", MetricTypeCounter, float64(metrics.NewRegistrations), map[string]string{"type": "business"})
	ms.RecordMetric("business.vault_items.created", MetricTypeCounter, float64(metrics.VaultItemsCreated), map[string]string{"type": "business"})
}