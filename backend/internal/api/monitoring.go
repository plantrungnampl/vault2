package api

import (
	"net/http"
	"strconv"
	"time"

	"securevault/internal/services"

	"github.com/gin-gonic/gin"
)

// GetPerformanceMetrics returns comprehensive system performance metrics
func GetPerformanceMetrics(monitoringService *services.MonitoringService) gin.HandlerFunc {
	return func(c *gin.Context) {
		metrics := monitoringService.CollectMetrics()
		c.JSON(http.StatusOK, gin.H{"data": metrics})
	}
}

// GetMetrics returns metrics with filtering and pagination
func GetMetrics(monitoringService *services.MonitoringService) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))

		filters := make(map[string]interface{})
		if name := c.Query("name"); name != "" {
			filters["name"] = name
		}
		if metricType := c.Query("type"); metricType != "" {
			filters["type"] = metricType
		}
		if source := c.Query("source"); source != "" {
			filters["source"] = source
		}
		if from := c.Query("from"); from != "" {
			if timestamp, err := time.Parse(time.RFC3339, from); err == nil {
				filters["from"] = timestamp
			}
		}
		if to := c.Query("to"); to != "" {
			if timestamp, err := time.Parse(time.RFC3339, to); err == nil {
				filters["to"] = timestamp
			}
		}

		metrics, total, err := monitoringService.GetMetrics(filters, page, limit)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get metrics"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": metrics,
			"pagination": gin.H{
				"page":       page,
				"limit":      limit,
				"total":      total,
				"totalPages": (total + int64(limit) - 1) / int64(limit),
			},
		})
	}
}

// GetAlerts returns alerts with filtering and pagination
func GetAlerts(monitoringService *services.MonitoringService) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))

		filters := make(map[string]interface{})
		if status := c.Query("status"); status != "" {
			filters["status"] = status
		}
		if severity := c.Query("severity"); severity != "" {
			filters["severity"] = severity
		}
		if source := c.Query("source"); source != "" {
			filters["source"] = source
		}
		if from := c.Query("from"); from != "" {
			if timestamp, err := time.Parse(time.RFC3339, from); err == nil {
				filters["from"] = timestamp
			}
		}
		if to := c.Query("to"); to != "" {
			if timestamp, err := time.Parse(time.RFC3339, to); err == nil {
				filters["to"] = timestamp
			}
		}

		alerts, total, err := monitoringService.GetAlerts(filters, page, limit)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get alerts"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": alerts,
			"pagination": gin.H{
				"page":       page,
				"limit":      limit,
				"total":      total,
				"totalPages": (total + int64(limit) - 1) / int64(limit),
			},
		})
	}
}

// CreateAlert manually creates a new alert
func CreateAlert(monitoringService *services.MonitoringService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name        string                  `json:"name" binding:"required"`
			Description string                  `json:"description" binding:"required"`
			Severity    services.AlertSeverity  `json:"severity" binding:"required"`
			Value       float64                 `json:"value"`
			MetricName  string                  `json:"metric_name"`
			Tags        []string                `json:"tags"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Get user from claims
		claims, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		userClaims, ok := claims.(*services.JWTClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		// Trigger alert
		monitoringService.TriggerAlert(req.Name, req.Description, req.Severity, req.Value)

		// Log audit event
		auditService.LogEvent(userClaims.UserID, "create_manual_alert", "alert", req.Name, true, map[string]interface{}{
			"severity":    req.Severity,
			"value":       req.Value,
			"metric_name": req.MetricName,
			"tags":        req.Tags,
		}, getClientIP(c), c.GetHeader("User-Agent"))

		c.JSON(http.StatusOK, gin.H{"message": "Alert created successfully"})
	}
}

// AcknowledgeAlert acknowledges an alert
func AcknowledgeAlert(monitoringService *services.MonitoringService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		alertID := c.Param("id")
		if alertID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Alert ID is required"})
			return
		}

		// Get user from claims
		claims, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		userClaims, ok := claims.(*services.JWTClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		// Acknowledge alert
		if err := monitoringService.AcknowledgeAlert(alertID, userClaims.UserID.String()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to acknowledge alert"})
			return
		}

		// Log audit event
		auditService.LogEvent(userClaims.UserID, "acknowledge_alert", "alert", alertID, true, nil, getClientIP(c), c.GetHeader("User-Agent"))

		c.JSON(http.StatusOK, gin.H{"message": "Alert acknowledged successfully"})
	}
}

// ResolveAlert resolves an alert
func ResolveAlert(monitoringService *services.MonitoringService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		alertID := c.Param("id")
		if alertID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Alert ID is required"})
			return
		}

		// Get user from claims
		claims, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		userClaims, ok := claims.(*services.JWTClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		// Resolve alert
		if err := monitoringService.ResolveAlert(alertID, userClaims.UserID.String()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve alert"})
			return
		}

		// Log audit event
		auditService.LogEvent(userClaims.UserID, "resolve_alert", "alert", alertID, true, nil, getClientIP(c), c.GetHeader("User-Agent"))

		c.JSON(http.StatusOK, gin.H{"message": "Alert resolved successfully"})
	}
}

// GetSystemHealth returns real-time system health status
func GetSystemHealth(monitoringService *services.MonitoringService) gin.HandlerFunc {
	return func(c *gin.Context) {
		metrics := monitoringService.CollectMetrics()
		
		// Determine overall health status
		healthStatus := "healthy"
		if metrics.SystemMetrics.CPUUsage > 90 {
			healthStatus = "critical"
		} else if metrics.SystemMetrics.CPUUsage > 80 || metrics.SystemMetrics.MemoryUsage > 85 {
			healthStatus = "warning"
		}

		health := gin.H{
			"status":    healthStatus,
			"timestamp": metrics.Timestamp,
			"checks": gin.H{
				"cpu": gin.H{
					"status": getHealthStatus(metrics.SystemMetrics.CPUUsage, 80, 90),
					"value":  metrics.SystemMetrics.CPUUsage,
					"unit":   "percent",
				},
				"memory": gin.H{
					"status": getHealthStatus(metrics.SystemMetrics.MemoryUsage, 85, 95),
					"value":  metrics.SystemMetrics.MemoryUsage,
					"unit":   "percent",
				},
				"database": gin.H{
					"status": getHealthStatus(float64(metrics.DatabaseMetrics.ConnectionsActive), 80, 95),
					"value":  metrics.DatabaseMetrics.ConnectionsActive,
					"unit":   "connections",
				},
				"application": gin.H{
					"status": getHealthStatus(metrics.ApplicationMetrics.ErrorRate, 1, 5),
					"value":  metrics.ApplicationMetrics.ErrorRate,
					"unit":   "percent",
				},
				"security": gin.H{
					"status": getHealthStatus(metrics.SecurityMetrics.ThreatScore, 50, 80),
					"value":  metrics.SecurityMetrics.ThreatScore,
					"unit":   "score",
				},
			},
			"uptime": metrics.SystemMetrics.Uptime.String(),
		}

		c.JSON(http.StatusOK, gin.H{"data": health})
	}
}

// GetDashboardMetrics returns key metrics for dashboard display
func GetDashboardMetrics(monitoringService *services.MonitoringService) gin.HandlerFunc {
	return func(c *gin.Context) {
		metrics := monitoringService.CollectMetrics()

		dashboard := gin.H{
			"performance": gin.H{
				"cpu_usage":     metrics.SystemMetrics.CPUUsage,
				"memory_usage":  metrics.SystemMetrics.MemoryUsage,
				"response_time": metrics.ApplicationMetrics.ResponseTimeP95.Milliseconds(),
				"error_rate":    metrics.ApplicationMetrics.ErrorRate,
			},
			"traffic": gin.H{
				"requests_per_second": metrics.ApplicationMetrics.RequestsPerSecond,
				"active_connections":  metrics.ApplicationMetrics.ActiveConnections,
				"session_count":       metrics.ApplicationMetrics.SessionCount,
				"cache_hit_rate":      metrics.ApplicationMetrics.CacheHitRate,
			},
			"database": gin.H{
				"connections_active":    metrics.DatabaseMetrics.ConnectionsActive,
				"queries_per_second":    metrics.DatabaseMetrics.QueriesPerSecond,
				"query_time_p95":        metrics.DatabaseMetrics.QueryTimeP95.Milliseconds(),
				"buffer_cache_hit_ratio": metrics.DatabaseMetrics.BufferCacheHitRatio,
			},
			"security": gin.H{
				"auth_success_rate":  metrics.SecurityMetrics.AuthenticationSuccessRate,
				"security_incidents": metrics.SecurityMetrics.SecurityIncidents,
				"blocked_ips":        metrics.SecurityMetrics.BlockedIPs,
				"threat_score":       metrics.SecurityMetrics.ThreatScore,
			},
			"business": gin.H{
				"active_users":         metrics.BusinessMetrics.ActiveUsers,
				"new_registrations":    metrics.BusinessMetrics.NewRegistrations,
				"vault_items_created":  metrics.BusinessMetrics.VaultItemsCreated,
				"vault_items_accessed": metrics.BusinessMetrics.VaultItemsAccessed,
			},
			"timestamp": metrics.Timestamp,
		}

		c.JSON(http.StatusOK, gin.H{"data": dashboard})
	}
}

// GetMetricsHistory returns historical metrics data for charting
func GetMetricsHistory(monitoringService *services.MonitoringService) gin.HandlerFunc {
	return func(c *gin.Context) {
		metricName := c.Query("metric")
		if metricName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Metric name is required"})
			return
		}

		timeRange := c.DefaultQuery("range", "1h")
		interval := c.DefaultQuery("interval", "1m")

		// Parse time range
		var duration time.Duration
		switch timeRange {
		case "1h":
			duration = time.Hour
		case "6h":
			duration = 6 * time.Hour
		case "24h":
			duration = 24 * time.Hour
		case "7d":
			duration = 7 * 24 * time.Hour
		case "30d":
			duration = 30 * 24 * time.Hour
		default:
			duration = time.Hour
		}

		// Generate mock historical data points
		now := time.Now()
		var dataPoints []gin.H

		// Calculate number of points based on interval
		var step time.Duration
		switch interval {
		case "1m":
			step = time.Minute
		case "5m":
			step = 5 * time.Minute
		case "15m":
			step = 15 * time.Minute
		case "1h":
			step = time.Hour
		case "1d":
			step = 24 * time.Hour
		default:
			step = time.Minute
		}

		// Generate data points (mock implementation)
		for t := now.Add(-duration); t.Before(now); t = t.Add(step) {
			value := generateMockMetricValue(metricName, t)
			dataPoints = append(dataPoints, gin.H{
				"timestamp": t.Unix(),
				"value":     value,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"data": gin.H{
				"metric":     metricName,
				"range":      timeRange,
				"interval":   interval,
				"points":     dataPoints,
				"total":      len(dataPoints),
			},
		})
	}
}

// RecordCustomMetric allows recording custom application metrics
func RecordCustomMetric(monitoringService *services.MonitoringService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name        string            `json:"name" binding:"required"`
			Type        services.MetricType `json:"type" binding:"required"`
			Value       float64           `json:"value" binding:"required"`
			Labels      map[string]string `json:"labels"`
			Description string            `json:"description"`
			Unit        string            `json:"unit"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Get user from claims for audit
		claims, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		userClaims, ok := claims.(*services.JWTClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		// Record the metric
		monitoringService.RecordMetric(req.Name, req.Type, req.Value, req.Labels)

		// Log audit event
		auditService.LogEvent(userClaims.UserID, "record_custom_metric", "metric", req.Name, true, map[string]interface{}{
			"type":  req.Type,
			"value": req.Value,
			"labels": req.Labels,
			"unit":  req.Unit,
		}, getClientIP(c), c.GetHeader("User-Agent"))

		c.JSON(http.StatusOK, gin.H{"message": "Metric recorded successfully"})
	}
}

// Helper functions
func getHealthStatus(value, warningThreshold, criticalThreshold float64) string {
	if value >= criticalThreshold {
		return "critical"
	} else if value >= warningThreshold {
		return "warning"
	}
	return "healthy"
}

// generateMockMetricValue generates realistic mock values for different metrics
func generateMockMetricValue(metricName string, timestamp time.Time) float64 {
	// Use timestamp to create predictable but varying values
	hour := float64(timestamp.Hour())
	minute := float64(timestamp.Minute())
	
	switch metricName {
	case "system.cpu.usage":
		// CPU usage varies throughout the day, higher during business hours
		base := 30.0
		if hour >= 9 && hour <= 17 {
			base = 55.0
		}
		return base + (minute/60)*20 + (hour-12)*(hour-12)/50

	case "system.memory.usage":
		// Memory usage is more stable but increases slowly over time
		base := 60.0
		return base + (hour/24)*15 + (minute/60)*5

	case "app.requests.per_second":
		// Request rate peaks during business hours
		base := 20.0
		if hour >= 8 && hour <= 18 {
			base = 85.0
		}
		return base + (minute/60)*30

	case "app.error.rate":
		// Error rate is usually low but can spike
		base := 0.5
		if hour == 14 { // Spike at 2 PM for example
			base = 2.5
		}
		return base + (minute/60)*1.0

	case "db.connections.active":
		// Database connections follow request patterns
		base := 10.0
		if hour >= 9 && hour <= 17 {
			base = 25.0
		}
		return base + (minute/60)*10

	case "security.threat_score":
		// Security threat score varies but stays relatively low
		base := 15.0
		return base + (hour/24)*20 + (minute/60)*10

	default:
		// Default pattern for unknown metrics
		return 50.0 + (hour/24)*30 + (minute/60)*20
	}
}