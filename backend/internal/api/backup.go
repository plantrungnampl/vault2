package api

import (
	"net/http"
	"strconv"
	"time"

	"securevault/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CreateBackup creates a new backup
func CreateBackup(backupService *services.BackupService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Type    services.BackupType       `json:"type" binding:"required"`
			Options map[string]interface{}    `json:"options"`
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

		// Create backup
		backup, err := backupService.CreateBackup(req.Type, userClaims.UserID.String(), req.Options)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create backup"})
			return
		}

		// Log audit event
		auditService.LogEvent(userClaims.UserID, "create_backup", "backup", backup.ID, true, map[string]interface{}{
			"backup_type": req.Type,
			"options":     req.Options,
		}, getClientIP(c), c.GetHeader("User-Agent"))

		c.JSON(http.StatusOK, gin.H{
			"message": "Backup created successfully",
			"data":    backup,
		})
	}
}

// GetBackups retrieves backup records
func GetBackups(backupService *services.BackupService) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

		filters := make(map[string]interface{})
		if backupType := c.Query("type"); backupType != "" {
			filters["type"] = backupType
		}
		if status := c.Query("status"); status != "" {
			filters["status"] = status
		}
		if createdBy := c.Query("created_by"); createdBy != "" {
			filters["created_by"] = createdBy
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

		backups, total, err := backupService.GetBackups(page, limit, filters)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get backups"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": backups,
			"pagination": gin.H{
				"page":       page,
				"limit":      limit,
				"total":      total,
				"totalPages": (total + int64(limit) - 1) / int64(limit),
			},
		})
	}
}

// RestoreBackup initiates a restore operation
func RestoreBackup(backupService *services.BackupService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		backupID := c.Param("id")
		if backupID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Backup ID is required"})
			return
		}

		var req struct {
			TargetPath string                 `json:"target_path" binding:"required"`
			Options    map[string]interface{} `json:"options"`
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

		// Initiate restore
		restore, err := backupService.RestoreBackup(backupID, req.TargetPath, userClaims.UserID.String(), req.Options)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Log audit event
		auditService.LogEvent(userClaims.UserID, "restore_backup", "backup", backupID, true, map[string]interface{}{
			"restore_id":  restore.ID,
			"target_path": req.TargetPath,
			"options":     req.Options,
		}, getClientIP(c), c.GetHeader("User-Agent"))

		c.JSON(http.StatusOK, gin.H{
			"message": "Restore operation initiated",
			"data":    restore,
		})
	}
}

// GetBackupMetrics returns backup system metrics
func GetBackupMetrics(backupService *services.BackupService) gin.HandlerFunc {
	return func(c *gin.Context) {
		metrics, err := backupService.GetBackupMetrics()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get backup metrics"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": metrics})
	}
}

// GetRestoreOperations retrieves restore operations
func GetRestoreOperations(backupService *services.BackupService) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))

		operations, total, err := backupService.GetRestoreOperations(page, limit)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get restore operations"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": operations,
			"pagination": gin.H{
				"page":       page,
				"limit":      limit,
				"total":      total,
				"totalPages": (total + int64(limit) - 1) / int64(limit),
			},
		})
	}
}

// TestDisasterRecovery tests disaster recovery procedures
func TestDisasterRecovery(backupService *services.BackupService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			PlanID string `json:"plan_id" binding:"required"`
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

		// Run DR test
		testResult, err := backupService.TestDisasterRecovery(req.PlanID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Log audit event
		auditService.LogEvent(userClaims.UserID, "test_disaster_recovery", "dr_plan", req.PlanID, testResult.Success, map[string]interface{}{
			"test_id":      testResult.TestID,
			"duration":     testResult.Duration.String(),
			"rto_achieved": testResult.RTOAchieved.String(),
			"success":      testResult.Success,
			"issues":       testResult.Issues,
		}, getClientIP(c), c.GetHeader("User-Agent"))

		c.JSON(http.StatusOK, gin.H{
			"message": "Disaster recovery test completed",
			"data":    testResult,
		})
	}
}

// GetBackupStatus returns the current status of a specific backup
func GetBackupStatus(backupService *services.BackupService) gin.HandlerFunc {
	return func(c *gin.Context) {
		backupID := c.Param("id")
		if backupID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Backup ID is required"})
			return
		}

		// This would query the backup service for real-time status
		// For now, return a mock progress response
		progress := services.BackupProgress{
			BackupID:       backupID,
			Status:         "running",
			Progress:       65,
			CurrentFile:    "/var/data/vault_items.json",
			FilesProcessed: 245,
			TotalFiles:     378,
			BytesProcessed: 1024 * 1024 * 150, // 150MB
			TotalBytes:     1024 * 1024 * 230,  // 230MB
			Speed:          1024 * 1024 * 5,    // 5MB/s
			ETA:            16,                  // 16 seconds
			ErrorCount:     0,
			StartTime:      time.Now().Add(-5 * time.Minute),
		}

		c.JSON(http.StatusOK, gin.H{"data": progress})
	}
}

// GetRestoreStatus returns the current status of a specific restore operation
func GetRestoreStatus(backupService *services.BackupService) gin.HandlerFunc {
	return func(c *gin.Context) {
		restoreID := c.Param("id")
		if restoreID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Restore ID is required"})
			return
		}

		// Mock restore progress
		progress := map[string]interface{}{
			"restore_id":       restoreID,
			"status":          "running",
			"progress":        45,
			"current_file":    "/backup/database/users.json",
			"files_extracted": 123,
			"total_files":     274,
			"bytes_extracted": 1024 * 1024 * 89, // 89MB
			"total_bytes":     1024 * 1024 * 198, // 198MB
			"speed":           1024 * 1024 * 3,   // 3MB/s
			"eta":             36,                // 36 seconds
			"error_count":     0,
			"start_time":      time.Now().Add(-3 * time.Minute),
		}

		c.JSON(http.StatusOK, gin.H{"data": progress})
	}
}

// CreateDisasterRecoveryPlan creates a new DR plan
func CreateDisasterRecoveryPlan(backupService *services.BackupService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name                   string                        `json:"name" binding:"required"`
			Description            string                        `json:"description"`
			Priority               int                           `json:"priority"`
			RecoveryTimeObjective  int                           `json:"rto_minutes"`
			RecoveryPointObjective int                           `json:"rpo_minutes"`
			TriggerConditions      []string                      `json:"trigger_conditions"`
			RecoverySteps          []services.RecoveryStep       `json:"recovery_steps"`
			ContactList            []services.EmergencyContact   `json:"contact_list"`
			Dependencies           []string                      `json:"dependencies"`
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

		// Create DR plan
		plan := &services.DisasterRecoveryPlan{
			ID:                     uuid.New().String(),
			Name:                   req.Name,
			Description:            req.Description,
			Priority:               req.Priority,
			RecoveryTimeObjective:  time.Duration(req.RecoveryTimeObjective) * time.Minute,
			RecoveryPointObjective: time.Duration(req.RecoveryPointObjective) * time.Minute,
			TriggerConditions:      req.TriggerConditions,
			RecoverySteps:          req.RecoverySteps,
			ContactList:            req.ContactList,
			Dependencies:           req.Dependencies,
			TestResults:            []services.DRTestResult{},
			IsActive:               true,
			CreatedAt:              time.Now(),
			UpdatedAt:              time.Now(),
		}

		// Save to database (would use backupService.CreateDRPlan in production)
		// For now, just return success

		// Log audit event
		auditService.LogEvent(userClaims.UserID, "create_dr_plan", "dr_plan", plan.ID, true, map[string]interface{}{
			"plan_name":   req.Name,
			"priority":    req.Priority,
			"rto_minutes": req.RecoveryTimeObjective,
			"rpo_minutes": req.RecoveryPointObjective,
		}, getClientIP(c), c.GetHeader("User-Agent"))

		c.JSON(http.StatusOK, gin.H{
			"message": "Disaster recovery plan created successfully",
			"data":    plan,
		})
	}
}

// GetDisasterRecoveryPlans retrieves all DR plans
func GetDisasterRecoveryPlans(backupService *services.BackupService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Mock DR plans for demonstration
		plans := []services.DisasterRecoveryPlan{
			{
				ID:                     "dr-001",
				Name:                   "Database Failure Recovery",
				Description:            "Recovery procedures for database system failure",
				Priority:               10,
				RecoveryTimeObjective:  4 * time.Hour,
				RecoveryPointObjective: 15 * time.Minute,
				TriggerConditions:      []string{"database_connection_lost", "data_corruption_detected"},
				RecoverySteps:          []services.RecoveryStep{
					{
						ID:          "step-1",
						Name:        "Assess Database Status",
						Description: "Check database connectivity and integrity",
						Order:       1,
						Type:        "manual",
						TimeoutMinutes: 10,
						Dependencies: []string{},
						SuccessCondition: "database_accessible",
						OnFailure:    "continue",
					},
					{
						ID:          "step-2",
						Name:        "Restore from Latest Backup",
						Description: "Restore database from the most recent backup",
						Order:       2,
						Type:        "automated",
						Command:     "restore-database --latest",
						TimeoutMinutes: 60,
						Dependencies: []string{"step-1"},
						SuccessCondition: "database_operational",
						OnFailure:    "abort",
					},
				},
				ContactList: []services.EmergencyContact{
					{Name: "John Doe", Role: "Database Administrator", Phone: "+1-555-0101", Email: "john.doe@securevault.com", Priority: 1},
					{Name: "Jane Smith", Role: "System Administrator", Phone: "+1-555-0102", Email: "jane.smith@securevault.com", Priority: 2},
				},
				Dependencies:  []string{"backup_system", "monitoring_alerts"},
				TestResults:   []services.DRTestResult{},
				LastTestedAt:  nil,
				IsActive:      true,
				CreatedAt:     time.Now().Add(-30 * 24 * time.Hour),
				UpdatedAt:     time.Now().Add(-7 * 24 * time.Hour),
			},
			{
				ID:                     "dr-002",
				Name:                   "Complete System Recovery",
				Description:            "Full system recovery for catastrophic failure",
				Priority:               9,
				RecoveryTimeObjective:  8 * time.Hour,
				RecoveryPointObjective: 30 * time.Minute,
				TriggerConditions:      []string{"system_failure", "data_center_outage"},
				RecoverySteps:          []services.RecoveryStep{
					{
						ID:          "step-1",
						Name:        "Activate Disaster Recovery Site",
						Description: "Switch to backup data center",
						Order:       1,
						Type:        "manual",
						TimeoutMinutes: 30,
					},
					{
						ID:          "step-2",
						Name:        "Restore All Systems",
						Description: "Restore complete system from backups",
						Order:       2,
						Type:        "automated",
						Command:     "full-system-restore",
						TimeoutMinutes: 240,
					},
				},
				ContactList: []services.EmergencyContact{
					{Name: "Emergency Team", Role: "Incident Commander", Phone: "+1-555-0911", Email: "emergency@securevault.com", Priority: 1},
				},
				Dependencies:  []string{"backup_system", "dr_site", "network_connectivity"},
				TestResults:   []services.DRTestResult{},
				LastTestedAt:  nil,
				IsActive:      true,
				CreatedAt:     time.Now().Add(-60 * 24 * time.Hour),
				UpdatedAt:     time.Now().Add(-14 * 24 * time.Hour),
			},
		}

		c.JSON(http.StatusOK, gin.H{
			"data": plans,
			"pagination": gin.H{
				"page":       1,
				"limit":      20,
				"total":      int64(len(plans)),
				"totalPages": 1,
			},
		})
	}
}

