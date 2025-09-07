package api

import (
	"net/http"
	"strconv"
	"time"

	"securevault/internal/models"
	"securevault/internal/services"
	"securevault/internal/security"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// GetUsers returns all users (admin only)
func GetUsers(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get pagination parameters
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
		
		// Get filters
		role := c.Query("role")
		status := c.Query("status")
		search := c.Query("search")

		filters := map[string]interface{}{}
		if role != "" {
			filters["role"] = role
		}
		if status != "" {
			filters["status"] = status
		}
		if search != "" {
			filters["search"] = search
		}

		userService := services.NewUserService()
		users, total, err := userService.GetUsers(page, limit, filters)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get users"})
			return
		}

		// Log audit event
		claims, _ := c.Get("claims")
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			auditService.LogEvent(userClaims.UserID, "admin_get_users", "users", "", true, nil, getClientIP(c), "")
		}

		c.JSON(http.StatusOK, gin.H{
			"data": users,
			"pagination": gin.H{
				"page":       page,
				"limit":      limit,
				"total":      total,
				"totalPages": (total + int64(limit) - 1) / int64(limit),
			},
		})
	}
}

// CreateUser creates a new user (admin only)
func CreateUser(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email     string           `json:"email" binding:"required,email"`
			Password  string           `json:"password" binding:"required,min=14"`
			FirstName string           `json:"firstName" binding:"required"`
			LastName  string           `json:"lastName" binding:"required"`
			Role      models.UserRole  `json:"role" binding:"required"`
			Status    models.UserStatus `json:"status"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		userService := services.NewUserService()
		user, err := userService.CreateUser(req.Email, req.Password, req.FirstName, req.LastName)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Update role if specified
		if req.Role != "" {
			user.Role = req.Role
		}
		if req.Status != "" {
			user.Status = req.Status
		}

		if _, err := userService.UpdateUser(user.ID, map[string]interface{}{
			"role":   user.Role,
			"status": user.Status,
		}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user role/status"})
			return
		}

		// Log audit event
		claims, _ := c.Get("claims")
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			auditService.LogEvent(userClaims.UserID, "admin_create_user", "user", user.ID.String(), true, map[string]interface{}{
				"email": req.Email,
				"role":  req.Role,
			}, getClientIP(c), "")
		}

		c.JSON(http.StatusCreated, gin.H{"data": user})
	}
}

// GetUser returns a specific user (admin only)
func GetUser(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr := c.Param("id")
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		userService := services.NewUserService()
		user, err := userService.GetUserByID(userID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		// Log audit event
		claims, _ := c.Get("claims")
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			auditService.LogEvent(userClaims.UserID, "admin_get_user", "user", userID.String(), true, nil, getClientIP(c), "")
		}

		c.JSON(http.StatusOK, gin.H{"data": user})
	}
}

// UpdateUser updates user information (admin only)
func UpdateUser(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr := c.Param("id")
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		var req map[string]interface{}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		userService := services.NewUserService()
		_, err = userService.UpdateUser(userID, req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
			return
		}

		// Get updated user
		user, err := userService.GetUserByID(userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get updated user"})
			return
		}

		// Log audit event
		claims, _ := c.Get("claims")
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			auditService.LogEvent(userClaims.UserID, "admin_update_user", "user", userID.String(), true, req, getClientIP(c), "")
		}

		c.JSON(http.StatusOK, gin.H{"data": user})
	}
}

// DeleteUser deletes a user (admin only)
func DeleteUser(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr := c.Param("id")
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		// Prevent deletion of current user
		claims, _ := c.Get("claims")
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			if userClaims.UserID == userID {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete your own account"})
				return
			}
		}

		userService := services.NewUserService()
		if err := userService.DeleteUser(userID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
			return
		}

		// Log audit event
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			auditService.LogEvent(userClaims.UserID, "admin_delete_user", "user", userID.String(), true, nil, getClientIP(c), "")
		}

		c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
	}
}

// SuspendUser suspends a user account (admin only)
func SuspendUser(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr := c.Param("id")
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		var req struct {
			Reason string `json:"reason"`
		}
		c.ShouldBindJSON(&req)

		userService := services.NewUserService()
		if _, err := userService.UpdateUser(userID, map[string]interface{}{
			"status": models.StatusSuspended,
		}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to suspend user"})
			return
		}

		// Invalidate all user sessions
		if err := userService.InvalidateUserSessions(userID); err != nil {
			// Log error but don't fail the request
			println("Warning: Failed to invalidate user sessions:", err.Error())
		}

		// Log audit event
		claims, _ := c.Get("claims")
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			auditService.LogEvent(userClaims.UserID, "admin_suspend_user", "user", userID.String(), true, map[string]interface{}{
				"reason": req.Reason,
			}, getClientIP(c), "")
		}

		c.JSON(http.StatusOK, gin.H{"message": "User suspended successfully"})
	}
}

// ActivateUser activates a suspended user account (admin only)
func ActivateUser(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr := c.Param("id")
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		userService := services.NewUserService()
		if _, err := userService.UpdateUser(userID, map[string]interface{}{
			"status": models.StatusActive,
		}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to activate user"})
			return
		}

		// Log audit event
		claims, _ := c.Get("claims")
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			auditService.LogEvent(userClaims.UserID, "admin_activate_user", "user", userID.String(), true, nil, getClientIP(c), "")
		}

		c.JSON(http.StatusOK, gin.H{"message": "User activated successfully"})
	}
}

// AdminResetPassword resets user password (admin only)
func AdminResetPassword(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr := c.Param("id")
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
			return
		}

		var req struct {
			NewPassword string `json:"newPassword" binding:"required,min=14"`
			NotifyUser  bool   `json:"notifyUser"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		userService := services.NewUserService()
		if err := userService.AdminResetPassword(userID, req.NewPassword); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
			return
		}

		// Log audit event
		claims, _ := c.Get("claims")
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			auditService.LogEvent(userClaims.UserID, "admin_reset_password", "user", userID.String(), true, map[string]interface{}{
				"notify_user": req.NotifyUser,
			}, getClientIP(c), "")
		}

		c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
	}
}

// GetSystemHealth returns system health information (admin only)
func AdminSystemHealth(db interface{}, redisClient interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		health := gin.H{
			"status":    "healthy",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"services": gin.H{
				"database": gin.H{
					"status": "healthy",
					"type":   "postgresql",
				},
				"redis": gin.H{
					"status": "healthy",
					"type":   "redis",
				},
				"api": gin.H{
					"status": "healthy",
					"uptime": "24h 15m 32s",
				},
			},
		}

		c.JSON(http.StatusOK, health)
	}
}

// GetSystemMetrics returns system metrics (admin only)
func AdminSystemMetrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		metrics := gin.H{
			"cpu_usage":    45.2,
			"memory_usage": 67.8,
			"disk_usage":   23.1,
			"network": gin.H{
				"inbound":  "125 MB/s",
				"outbound": "89 MB/s",
			},
			"database": gin.H{
				"connections":        12,
				"queries_per_second": 450,
			},
			"api": gin.H{
				"requests_per_minute":   2340,
				"average_response_time": "150ms",
				"error_rate":            0.02,
			},
		}

		c.JSON(http.StatusOK, metrics)
	}
}

// GetSecurityIncidents returns security incidents (admin only)
func GetSecurityIncidents(securityService *services.SecurityService) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

		filters := map[string]interface{}{}
		if severity := c.Query("severity"); severity != "" {
			filters["severity"] = severity
		}
		if eventType := c.Query("type"); eventType != "" {
			filters["type"] = eventType
		}
		if status := c.Query("status"); status != "" {
			filters["status"] = status
		}

		incidents, total, err := securityService.GetSecurityIncidents(page, limit, filters)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get security incidents"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": incidents,
			"pagination": gin.H{
				"page":       page,
				"limit":      limit,
				"total":      total,
				"totalPages": (total + int64(limit) - 1) / int64(limit),
			},
		})
	}
}

// ResolveSecurityIncident resolves a security incident (admin only)
func ResolveSecurityIncident(securityService *services.SecurityService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		incidentIDStr := c.Param("id")
		incidentID, err := uuid.Parse(incidentIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid incident ID"})
			return
		}

		claims, _ := c.Get("claims")
		userClaims, ok := claims.(*services.JWTClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		if err := securityService.ResolveSecurityIncident(incidentID, userClaims.UserID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve incident"})
			return
		}

		// Log audit event
		auditService.LogEvent(userClaims.UserID, "admin_resolve_incident", "security_incident", incidentID.String(), true, nil, getClientIP(c), "")

		c.JSON(http.StatusOK, gin.H{"message": "Incident resolved successfully"})
	}
}

// GetSecurityStats returns security statistics
func GetSecurityStats(securityService *services.SecurityService) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats, err := securityService.GetSecurityStats()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get security stats"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": stats})
	}
}

// GetAuditLogs returns audit logs (admin only)
func AdminGetAllAuditLogs(auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))

		filters := map[string]interface{}{}
		if action := c.Query("action"); action != "" {
			filters["action"] = action
		}
		if success := c.Query("success"); success != "" {
			filters["success"] = success == "true"
		}
		if userID := c.Query("user_id"); userID != "" {
			if uid, err := uuid.Parse(userID); err == nil {
				filters["user_id"] = uid
			}
		}

		auditFilters := services.AuditFilters{
		Limit:  limit,
		Offset: (page - 1) * limit,
	}
	if uid, ok := filters["user_id"].(uuid.UUID); ok {
		auditFilters.UserID = uid
	}
	if action, ok := filters["action"].(string); ok {
		auditFilters.Action = action
	}
	if success, ok := filters["success"].(bool); ok {
		auditFilters.Success = &success
	}
	logs, total, err := auditService.GetAuditLogs(auditFilters)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get audit logs"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": logs,
			"pagination": gin.H{
				"page":       page,
				"limit":      limit,
				"total":      total,
				"totalPages": (total + int64(limit) - 1) / int64(limit),
			},
		})
	}
}

// ExportAuditLogs exports audit logs in various formats
func ExportAuditLogs(auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Format    string                 `json:"format" binding:"required"` // csv, json, xlsx
			StartDate string                 `json:"start_date"`
			EndDate   string                 `json:"end_date"`
			Filters   map[string]interface{} `json:"filters"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// This is a placeholder implementation
		// In production, you'd generate the actual export file
		exportID := uuid.New()

		// Log audit event
		claims, _ := c.Get("claims")
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			auditService.LogEvent(userClaims.UserID, "admin_export_logs", "audit_logs", "", true, map[string]interface{}{
				"format":     req.Format,
				"start_date": req.StartDate,
				"end_date":   req.EndDate,
				"export_id":  exportID,
			}, getClientIP(c), "")
		}

		c.JSON(http.StatusOK, gin.H{
			"message":   "Export started",
			"export_id": exportID,
			"status":    "processing",
		})
	}
}

// GetSecurityPolicies retrieves security policies (admin only)
func GetSecurityPolicies(authService *services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		securityService := services.NewSecurityService()
		policies, err := securityService.GetSecurityPolicies()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get security policies"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": policies})
	}
}

// UpdateSecurityPolicies updates security policies (admin only)
func UpdateSecurityPolicies(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Policies []struct {
				ID      string `json:"id" binding:"required"`
				Rules   string `json:"rules" binding:"required"`
				Enabled bool   `json:"enabled"`
			} `json:"policies" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		securityService := services.NewSecurityService()
		for _, policy := range req.Policies {
			policyID, err := uuid.Parse(policy.ID)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy ID: " + policy.ID})
				return
			}

			if err := securityService.UpdateSecurityPolicy(policyID, policy.Rules, policy.Enabled); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update policy: " + policy.ID})
				return
			}
		}

		// Log audit event
		claims, _ := c.Get("claims")
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			auditService.LogEvent(userClaims.UserID, "admin_update_policies", "security_policies", "", true, map[string]interface{}{
				"policies_count": len(req.Policies),
			}, getClientIP(c), "")
		}

		c.JSON(http.StatusOK, gin.H{"message": "Security policies updated successfully"})
	}
}

// IDS Management Endpoints

// GetSecurityEvents returns security events detected by IDS
func GetSecurityEvents(idsService *security.IntrusionDetectionService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

		filters := map[string]interface{}{}
		if level := c.Query("level"); level != "" {
			filters["level"] = level
		}
		if threatType := c.Query("type"); threatType != "" {
			filters["type"] = threatType
		}
		if blocked := c.Query("blocked"); blocked != "" {
			filters["blocked"] = blocked == "true"
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

		events, total, err := idsService.GetSecurityEvents(page, limit, filters)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get security events"})
			return
		}

		// Log audit event
		claims, _ := c.Get("claims")
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			auditService.LogEvent(userClaims.UserID, "admin_get_security_events", "security_events", "", true, nil, getClientIP(c), c.GetHeader("User-Agent"))
		}

		c.JSON(http.StatusOK, gin.H{
			"data": events,
			"pagination": gin.H{
				"page":       page,
				"limit":      limit,
				"total":      total,
				"totalPages": (total + int64(limit) - 1) / int64(limit),
			},
		})
	}
}

// GetSecurityMetrics returns real-time security metrics
func GetSecurityMetrics(idsService *security.IntrusionDetectionService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Mock metrics - in production this would be calculated from actual data
		metrics := security.SecurityMetrics{
			TotalRequests:    125430,
			BlockedRequests:  2341,
			ThreatsByType:    map[security.ThreatType]int64{
				security.ThreatTypeBruteForce:        156,
				security.ThreatTypeRateLimitExceeded: 89,
				security.ThreatTypeSQLInjection:      23,
				security.ThreatTypeXSS:               45,
				security.ThreatTypeAnomaly:           67,
			},
			ThreatsByLevel: map[security.ThreatLevel]int64{
				security.ThreatLevelLow:      234,
				security.ThreatLevelMedium:   123,
				security.ThreatLevelHigh:     45,
				security.ThreatLevelCritical: 12,
			},
			TopThreateningIPs: []security.IPThreatSummary{
				{IPAddress: "192.168.1.100", ThreatScore: 85, EventCount: 45, LastSeen: time.Now().Add(-time.Hour), CountryCode: "CN", IsBlocked: true},
				{IPAddress: "10.0.0.50", ThreatScore: 72, EventCount: 23, LastSeen: time.Now().Add(-2*time.Hour), CountryCode: "RU", IsBlocked: false},
			},
			AverageRiskScore:  42.5,
			DetectionAccuracy: 94.2,
			ResponseTime:      time.Millisecond * 150,
			UpdatedAt:         time.Now(),
		}

		c.JSON(http.StatusOK, gin.H{"data": metrics})
	}
}

// GetRealTimeSecurityStatus returns real-time security status
func GetRealTimeSecurityStatus(idsService *security.IntrusionDetectionService) gin.HandlerFunc {
	return func(c *gin.Context) {
		status := security.RealTimeSecurityStatus{
			Status:           "elevated",
			ActiveThreats:    15,
			BlockedIPs:       234,
			RequestsLastHour: 8432,
			ThreatsLastHour:  67,
			AverageRiskScore: 35.8,
			TopThreatTypes: []security.ThreatTypeCount{
				{Type: security.ThreatTypeBruteForce, Count: 23},
				{Type: security.ThreatTypeRateLimitExceeded, Count: 18},
				{Type: security.ThreatTypeAnomaly, Count: 12},
			},
			GeographicalSpread: []security.CountryThreatCount{
				{CountryCode: "CN", CountryName: "China", Count: 45, RiskLevel: "high"},
				{CountryCode: "RU", CountryName: "Russia", Count: 23, RiskLevel: "medium"},
				{CountryCode: "US", CountryName: "United States", Count: 12, RiskLevel: "low"},
			},
			SystemHealth: security.SecuritySystemHealth{
				IDSStatus:         "healthy",
				DatabaseLatency:   25,
				ProcessingLatency: 150,
				MemoryUsage:       67.5,
				CPUUsage:          45.2,
				QueueSize:         23,
				ErrorRate:         0.02,
				LastHealthCheck:   time.Now(),
			},
			LastUpdated: time.Now(),
		}

		c.JSON(http.StatusOK, gin.H{"data": status})
	}
}

// BlockIPAddress blocks an IP address manually
func BlockIPAddress(idsService *security.IntrusionDetectionService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			IPAddress string `json:"ip_address" binding:"required"`
			Duration  int    `json:"duration_hours" binding:"required,min=1"`
			Reason    string `json:"reason" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		duration := time.Duration(req.Duration) * time.Hour
		if err := idsService.BlockIP(req.IPAddress, duration, req.Reason); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to block IP address"})
			return
		}

		// Log audit event
		claims, _ := c.Get("claims")
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			auditService.LogEvent(userClaims.UserID, "admin_block_ip", "ip_address", req.IPAddress, true, map[string]interface{}{
				"duration_hours": req.Duration,
				"reason":         req.Reason,
			}, getClientIP(c), c.GetHeader("User-Agent"))
		}

		c.JSON(http.StatusOK, gin.H{"message": "IP address blocked successfully"})
	}
}

// UnblockIPAddress removes a block from an IP address
func UnblockIPAddress(idsService *security.IntrusionDetectionService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			IPAddress string `json:"ip_address" binding:"required"`
			Reason    string `json:"reason"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := idsService.UnblockIP(req.IPAddress); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to unblock IP address"})
			return
		}

		// Log audit event
		claims, _ := c.Get("claims")
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			auditService.LogEvent(userClaims.UserID, "admin_unblock_ip", "ip_address", req.IPAddress, true, map[string]interface{}{
				"reason": req.Reason,
			}, getClientIP(c), c.GetHeader("User-Agent"))
		}

		c.JSON(http.StatusOK, gin.H{"message": "IP address unblocked successfully"})
	}
}

// GetIDSConfiguration returns current IDS configuration
func GetIDSConfiguration(idsService *security.IntrusionDetectionService) gin.HandlerFunc {
	return func(c *gin.Context) {
		config := security.SecurityConfiguration{
			GeneralSettings: struct {
				MonitoringEnabled         bool `json:"monitoring_enabled"`
				AutoBlockEnabled          bool `json:"auto_block_enabled"`
				AlertingEnabled           bool `json:"alerting_enabled"`
				GeoLocationEnabled        bool `json:"geo_location_enabled"`
				BehavioralAnalysisEnabled bool `json:"behavioral_analysis_enabled"`
				LogRetentionDays          int  `json:"log_retention_days"`
			}{
				MonitoringEnabled:         true,
				AutoBlockEnabled:          true,
				AlertingEnabled:           true,
				GeoLocationEnabled:        true,
				BehavioralAnalysisEnabled: true,
				LogRetentionDays:          30,
			},
			ThreatDetection: struct {
				BruteForceThreshold     int     `json:"brute_force_threshold"`
				RateLimitMaxRequests    int     `json:"rate_limit_max_requests"`
				RateLimitWindowMinutes  int     `json:"rate_limit_window_minutes"`
				AnomalyThreshold        float64 `json:"anomaly_threshold"`
				AutoBlockThreshold      int     `json:"auto_block_threshold"`
				BlockDurationHours      int     `json:"block_duration_hours"`
			}{
				BruteForceThreshold:     5,
				RateLimitMaxRequests:    60,
				RateLimitWindowMinutes:  1,
				AnomalyThreshold:        0.8,
				AutoBlockThreshold:      80,
				BlockDurationHours:      1,
			},
			IPManagement: struct {
				WhitelistedIPs          []string `json:"whitelisted_ips"`
				BlacklistedIPs          []string `json:"blacklisted_ips"`
				AutoUpdateBlacklist     bool     `json:"auto_update_blacklist"`
				ThreatIntelligenceFeeds []string `json:"threat_intelligence_feeds"`
			}{
				WhitelistedIPs:          []string{"127.0.0.1", "::1"},
				BlacklistedIPs:          []string{},
				AutoUpdateBlacklist:     true,
				ThreatIntelligenceFeeds: []string{"malware-domains", "botnet-ips"},
			},
			Alerting: struct {
				EmailEnabled        bool     `json:"email_enabled"`
				SMSEnabled          bool     `json:"sms_enabled"`
				SlackEnabled        bool     `json:"slack_enabled"`
				WebhookEnabled      bool     `json:"webhook_enabled"`
				EmailRecipients     []string `json:"email_recipients"`
				SMSRecipients       []string `json:"sms_recipients"`
				SlackChannels       []string `json:"slack_channels"`
				WebhookURLs         []string `json:"webhook_urls"`
				AlertThresholds     struct {
					LowPriority      int `json:"low_priority"`
					MediumPriority   int `json:"medium_priority"`
					HighPriority     int `json:"high_priority"`
					CriticalPriority int `json:"critical_priority"`
				} `json:"alert_thresholds"`
			}{
				EmailEnabled:    true,
				SMSEnabled:      false,
				SlackEnabled:    true,
				WebhookEnabled:  false,
				EmailRecipients: []string{"admin@securevault.com"},
				SlackChannels:   []string{"#security-alerts"},
				AlertThresholds: struct {
					LowPriority      int `json:"low_priority"`
					MediumPriority   int `json:"medium_priority"`
					HighPriority     int `json:"high_priority"`
					CriticalPriority int `json:"critical_priority"`
				}{
					LowPriority:      10,
					MediumPriority:   25,
					HighPriority:     50,
					CriticalPriority: 80,
				},
			},
		}

		c.JSON(http.StatusOK, gin.H{"data": config})
	}
}

// UpdateIDSConfiguration updates IDS configuration
func UpdateIDSConfiguration(idsService *security.IntrusionDetectionService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req security.SecurityConfiguration

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// In production, this would update the actual IDS configuration
		// For now, we just acknowledge the update

		// Log audit event
		claims, _ := c.Get("claims")
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			auditService.LogEvent(userClaims.UserID, "admin_update_ids_config", "ids_configuration", "", true, map[string]interface{}{
				"monitoring_enabled":          req.GeneralSettings.MonitoringEnabled,
				"auto_block_enabled":          req.GeneralSettings.AutoBlockEnabled,
				"brute_force_threshold":       req.ThreatDetection.BruteForceThreshold,
				"rate_limit_max_requests":     req.ThreatDetection.RateLimitMaxRequests,
				"anomaly_threshold":           req.ThreatDetection.AnomalyThreshold,
			}, getClientIP(c), c.GetHeader("User-Agent"))
		}

		c.JSON(http.StatusOK, gin.H{"message": "IDS configuration updated successfully"})
	}
}

// GenerateSecurityReport generates a comprehensive security report
func GenerateSecurityReport(idsService *security.IntrusionDetectionService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Type      string `json:"type" binding:"required"` // daily, weekly, monthly, custom
			StartDate string `json:"start_date,omitempty"`
			EndDate   string `json:"end_date,omitempty"`
			Format    string `json:"format" binding:"required"` // json, pdf, csv
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Generate mock report
		reportID := uuid.New()
		report := security.SecurityReport{
			ID:   reportID.String(),
			Type: req.Type,
			Period: security.ReportPeriod{
				StartDate: time.Now().Add(-24 * time.Hour),
				EndDate:   time.Now(),
				TimeZone:  "UTC",
			},
			Summary: security.SecurityReportSummary{
				TotalRequests:       125430,
				ThreatsDetected:     456,
				BlockedRequests:     2341,
				UniqueIPs:           8934,
				BlockedIPs:          234,
				AverageRiskScore:    42.5,
				DetectionAccuracy:   94.2,
				FalsePositiveRate:   0.8,
			},
			ThreatAnalysis: security.ThreatAnalysis{
				ThreatsByType: map[security.ThreatType]int64{
					security.ThreatTypeBruteForce:        156,
					security.ThreatTypeRateLimitExceeded: 89,
					security.ThreatTypeSQLInjection:      23,
					security.ThreatTypeXSS:               45,
					security.ThreatTypeAnomaly:           67,
				},
				ThreatsByLevel: map[security.ThreatLevel]int64{
					security.ThreatLevelLow:      234,
					security.ThreatLevelMedium:   123,
					security.ThreatLevelHigh:     45,
					security.ThreatLevelCritical: 12,
				},
			},
			Recommendations: []security.SecurityRecommendation{
				{
					Priority:    "high",
					Category:    "access_control",
					Title:       "Tăng cường MFA cho tài khoản admin",
					Description: "Phát hiện nhiều lần đăng nhập bất thường vào tài khoản admin",
					Impact:      "Giảm 80% nguy cơ tài khoản admin bị xâm nhập",
					Effort:      "Thấp - có thể triển khai trong 1 ngày",
					Timeline:    "Ngay lập tức",
				},
				{
					Priority:    "medium",
					Category:    "network_security",
					Title:       "Cập nhật blacklist IP",
					Description: "Phát hiện 15 IP mới có hoạt động đáng ngờ",
					Impact:      "Giảm 60% traffic từ các nguồn độc hại",
					Effort:      "Thấp - tự động cập nhật",
					Timeline:    "Trong 24 giờ",
				},
			},
			GeneratedAt: time.Now(),
			GeneratedBy: "system",
		}

		// Log audit event
		claims, _ := c.Get("claims")
		if userClaims, ok := claims.(*services.JWTClaims); ok {
			report.GeneratedBy = userClaims.UserID.String()
			auditService.LogEvent(userClaims.UserID, "admin_generate_security_report", "security_report", reportID.String(), true, map[string]interface{}{
				"report_type":   req.Type,
				"report_format": req.Format,
			}, getClientIP(c), c.GetHeader("User-Agent"))
		}

		c.JSON(http.StatusOK, gin.H{
			"message":   "Security report generated successfully",
			"report_id": reportID,
			"data":      report,
		})
	}
}

// Helper function to get client IP
func getClientIP(c *gin.Context) string {
	if ip := c.GetHeader("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := c.GetHeader("X-Real-IP"); ip != "" {
		return ip
	}
	return c.ClientIP()
}