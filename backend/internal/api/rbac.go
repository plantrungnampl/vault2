package api

import (
	"net/http"
	"strconv"
	"time"

	"securevault/internal/models"
	"securevault/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// GetUserPermissions returns all effective permissions for a user
// GET /api/v1/admin/rbac/users/:id/permissions
func GetUserPermissions(rbacService *services.RBACService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ID người dùng không hợp lệ"})
			return
		}

		permissions, err := rbacService.GetUserPermissions(c.Request.Context(), userID)
		if err != nil {
			auditService.LogEvent(
				GetUserID(c), "rbac.permissions.read", "user_permissions", userID.String(),
				false, map[string]interface{}{"error": err.Error()}, c.ClientIP(), c.Request.UserAgent(),
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Không thể lấy quyền người dùng"})
			return
		}

		auditService.LogEvent(
			GetUserID(c), "rbac.permissions.read", "user_permissions", userID.String(),
			true, map[string]interface{}{
				"permission_count": len(permissions),
			}, c.ClientIP(), c.Request.UserAgent(),
		)

		c.JSON(http.StatusOK, gin.H{
			"user_id":     userID,
			"permissions": permissions,
			"count":       len(permissions),
		})
	}
}

// GetRolePermissions returns all permissions for a specific role
// GET /api/v1/admin/rbac/roles/:id/permissions
func GetRolePermissions(rbacService *services.RBACService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ID vai trò không hợp lệ"})
			return
		}

		permissions, err := rbacService.GetRolePermissions(c.Request.Context(), roleID)
		if err != nil {
			auditService.LogEvent(
				GetUserID(c), "rbac.role_permissions.read", "role_permissions", roleID.String(),
				false, map[string]interface{}{"error": err.Error()}, c.ClientIP(), c.Request.UserAgent(),
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Không thể lấy quyền vai trò"})
			return
		}

		auditService.LogEvent(
			GetUserID(c), "rbac.role_permissions.read", "role_permissions", roleID.String(),
			true, map[string]interface{}{
				"permission_count": len(permissions),
			}, c.ClientIP(), c.Request.UserAgent(),
		)

		c.JSON(http.StatusOK, gin.H{
			"role_id":     roleID,
			"permissions": permissions,
			"count":       len(permissions),
		})
	}
}

// CheckPermissionRequest represents permission check request
type CheckPermissionRequest struct {
	UserID       uuid.UUID `json:"user_id" binding:"required"`
	Resource     string    `json:"resource" binding:"required"`
	Action       string    `json:"action" binding:"required"`
	ResourceID   *uuid.UUID `json:"resource_id,omitempty"`
	MFAVerified  bool      `json:"mfa_verified"`
}

// CheckPermission checks if a user has permission to perform an action
// POST /api/v1/admin/rbac/check-permission
func CheckPermission(rbacService *services.RBACService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CheckPermissionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Dữ liệu yêu cầu không hợp lệ: " + err.Error()})
			return
		}

		// Build permission context
		permCtx := models.PermissionContext{
			UserID:       req.UserID,
			IPAddress:    c.ClientIP(),
			UserAgent:    c.Request.UserAgent(),
			Resource:     req.Resource,
			ResourceID:   req.ResourceID,
			Action:       req.Action,
			Time:         time.Now(),
			MFAVerified:  req.MFAVerified,
			SecurityLevel: models.SecurityLevelStandard,
			RiskScore:    0.0,
		}

		// Perform permission check
		hasPermission, err := rbacService.CheckPermission(c.Request.Context(), permCtx)
		if err != nil {
			auditService.LogEvent(
				GetUserID(c), "rbac.permission.check", "permission_check", req.UserID.String(),
				false, map[string]interface{}{
					"target_user": req.UserID.String(),
					"resource":    req.Resource,
					"action":      req.Action,
					"error":       err.Error(),
				}, c.ClientIP(), c.Request.UserAgent(),
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Không thể kiểm tra quyền"})
			return
		}

		auditService.LogEvent(
			GetUserID(c), "rbac.permission.check", "permission_check", req.UserID.String(),
			true, map[string]interface{}{
				"target_user":    req.UserID.String(),
				"resource":       req.Resource,
				"action":         req.Action,
				"has_permission": hasPermission,
			}, c.ClientIP(), c.Request.UserAgent(),
		)

		c.JSON(http.StatusOK, gin.H{
			"user_id":        req.UserID,
			"resource":       req.Resource,
			"action":         req.Action,
			"has_permission": hasPermission,
			"checked_at":     time.Now(),
		})
	}
}

// GrantPermissionRequest represents permission grant request
type GrantPermissionRequest struct {
	PermissionID uuid.UUID              `json:"permission_id" binding:"required"`
	Conditions   map[string]interface{} `json:"conditions"`
	ExpiresAt    *time.Time             `json:"expires_at"`
	Reason       string                 `json:"reason"`
}

// GrantPermissionToRole grants a permission to a role
// POST /api/v1/admin/rbac/roles/:id/permissions/grant
func GrantPermissionToRole(rbacService *services.RBACService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ID vai trò không hợp lệ"})
			return
		}

		var req GrantPermissionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Dữ liệu yêu cầu không hợp lệ: " + err.Error()})
			return
		}

		currentUserID := GetUserID(c)
		
		err = rbacService.GrantPermissionToRole(
			c.Request.Context(), 
			roleID, 
			req.PermissionID, 
			currentUserID,
			req.Conditions,
		)
		
		if err != nil {
			auditService.LogEvent(
				currentUserID, "rbac.permission.grant_to_role", "role_permission", roleID.String(),
				false, map[string]interface{}{
					"role_id":       roleID.String(),
					"permission_id": req.PermissionID.String(),
					"reason":        req.Reason,
					"error":         err.Error(),
				}, c.ClientIP(), c.Request.UserAgent(),
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Không thể cấp quyền cho vai trò"})
			return
		}

		auditService.LogEvent(
			currentUserID, "rbac.permission.grant_to_role", "role_permission", roleID.String(),
			true, map[string]interface{}{
				"role_id":       roleID.String(),
				"permission_id": req.PermissionID.String(),
				"reason":        req.Reason,
			}, c.ClientIP(), c.Request.UserAgent(),
		)

		c.JSON(http.StatusOK, gin.H{
			"message":       "Đã cấp quyền cho vai trò thành công",
			"role_id":       roleID,
			"permission_id": req.PermissionID,
			"granted_by":    currentUserID,
			"granted_at":    time.Now(),
		})
	}
}

// RevokePermissionFromRole revokes a permission from a role
// POST /api/v1/admin/rbac/roles/:id/permissions/:permission_id/revoke
func RevokePermissionFromRole(rbacService *services.RBACService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ID vai trò không hợp lệ"})
			return
		}

		permissionID, err := uuid.Parse(c.Param("permission_id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ID quyền không hợp lệ"})
			return
		}

		currentUserID := GetUserID(c)

		err = rbacService.RevokePermissionFromRole(c.Request.Context(), roleID, permissionID)
		if err != nil {
			auditService.LogEvent(
				currentUserID, "rbac.permission.revoke_from_role", "role_permission", roleID.String(),
				false, map[string]interface{}{
					"role_id":       roleID.String(),
					"permission_id": permissionID.String(),
					"error":         err.Error(),
				}, c.ClientIP(), c.Request.UserAgent(),
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Không thể thu hồi quyền từ vai trò"})
			return
		}

		auditService.LogEvent(
			currentUserID, "rbac.permission.revoke_from_role", "role_permission", roleID.String(),
			true, map[string]interface{}{
				"role_id":       roleID.String(),
				"permission_id": permissionID.String(),
			}, c.ClientIP(), c.Request.UserAgent(),
		)

		c.JSON(http.StatusOK, gin.H{
			"message":       "Đã thu hồi quyền từ vai trò thành công",
			"role_id":       roleID,
			"permission_id": permissionID,
			"revoked_by":    currentUserID,
			"revoked_at":    time.Now(),
		})
	}
}

// GrantPermissionToUser grants a specific permission to a user
// POST /api/v1/admin/rbac/users/:id/permissions/grant
func GrantPermissionToUser(rbacService *services.RBACService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ID người dùng không hợp lệ"})
			return
		}

		var req GrantPermissionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Dữ liệu yêu cầu không hợp lệ: " + err.Error()})
			return
		}

		currentUserID := GetUserID(c)

		err = rbacService.GrantPermissionToUser(
			c.Request.Context(),
			userID,
			req.PermissionID,
			currentUserID,
			req.Reason,
			req.ExpiresAt,
		)

		if err != nil {
			auditService.LogEvent(
				currentUserID, "rbac.permission.grant_to_user", "user_permission", userID.String(),
				false, map[string]interface{}{
					"target_user":   userID.String(),
					"permission_id": req.PermissionID.String(),
					"reason":        req.Reason,
					"expires_at":    req.ExpiresAt,
					"error":         err.Error(),
				}, c.ClientIP(), c.Request.UserAgent(),
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Không thể cấp quyền cho người dùng"})
			return
		}

		auditService.LogEvent(
			currentUserID, "rbac.permission.grant_to_user", "user_permission", userID.String(),
			true, map[string]interface{}{
				"target_user":   userID.String(),
				"permission_id": req.PermissionID.String(),
				"reason":        req.Reason,
				"expires_at":    req.ExpiresAt,
			}, c.ClientIP(), c.Request.UserAgent(),
		)

		c.JSON(http.StatusOK, gin.H{
			"message":       "Đã cấp quyền cho người dùng thành công",
			"user_id":       userID,
			"permission_id": req.PermissionID,
			"granted_by":    currentUserID,
			"granted_at":    time.Now(),
			"expires_at":    req.ExpiresAt,
			"reason":        req.Reason,
		})
	}
}

// RevokePermissionFromUser revokes a specific permission from a user
// POST /api/v1/admin/rbac/users/:id/permissions/:permission_id/revoke
func RevokePermissionFromUser(rbacService *services.RBACService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ID người dùng không hợp lệ"})
			return
		}

		permissionID, err := uuid.Parse(c.Param("permission_id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ID quyền không hợp lệ"})
			return
		}

		type RevokeRequest struct {
			Reason string `json:"reason" binding:"required"`
		}

		var req RevokeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Dữ liệu yêu cầu không hợp lệ: " + err.Error()})
			return
		}

		currentUserID := GetUserID(c)

		err = rbacService.RevokePermissionFromUser(
			c.Request.Context(),
			userID,
			permissionID,
			currentUserID,
			req.Reason,
		)

		if err != nil {
			auditService.LogEvent(
				currentUserID, "rbac.permission.revoke_from_user", "user_permission", userID.String(),
				false, map[string]interface{}{
					"target_user":   userID.String(),
					"permission_id": permissionID.String(),
					"reason":        req.Reason,
					"error":         err.Error(),
				}, c.ClientIP(), c.Request.UserAgent(),
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Không thể thu hồi quyền từ người dùng"})
			return
		}

		auditService.LogEvent(
			currentUserID, "rbac.permission.revoke_from_user", "user_permission", userID.String(),
			true, map[string]interface{}{
				"target_user":   userID.String(),
				"permission_id": permissionID.String(),
				"reason":        req.Reason,
			}, c.ClientIP(), c.Request.UserAgent(),
		)

		c.JSON(http.StatusOK, gin.H{
			"message":       "Đã thu hồi quyền từ người dùng thành công",
			"user_id":       userID,
			"permission_id": permissionID,
			"revoked_by":    currentUserID,
			"revoked_at":    time.Now(),
			"reason":        req.Reason,
		})
	}
}

// GetAllRoles returns all system roles
// GET /api/v1/admin/rbac/roles
func GetAllRoles(rbacService *services.RBACService) gin.HandlerFunc {
	return func(c *gin.Context) {
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
		
		if page < 1 {
			page = 1
		}
		if limit < 1 || limit > 100 {
			limit = 20
		}

		offset := (page - 1) * limit

		var roles []models.Role
		var total int64

		// Get total count
		if err := rbacService.GetDB().Model(&models.Role{}).Count(&total).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Không thể đếm vai trò"})
			return
		}

		// Get roles with pagination
		if err := rbacService.GetDB().Preload("RolePermissions.Permission").
			Offset(offset).Limit(limit).Find(&roles).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Không thể lấy danh sách vai trò"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"roles":       roles,
			"total":       total,
			"page":        page,
			"limit":       limit,
			"total_pages": (total + int64(limit) - 1) / int64(limit),
		})
	}
}

// GetAllPermissions returns all system permissions
// GET /api/v1/admin/rbac/permissions
func GetAllPermissions(rbacService *services.RBACService) gin.HandlerFunc {
	return func(c *gin.Context) {
		category := c.Query("category")
		page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		
		if page < 1 {
			page = 1
		}
		if limit < 1 || limit > 100 {
			limit = 50
		}

		offset := (page - 1) * limit

		var permissions []models.Permission
		var total int64
		
		query := rbacService.GetDB().Model(&models.Permission{})
		
		if category != "" {
			query = query.Where("category = ?", category)
		}

		// Get total count
		if err := query.Count(&total).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Không thể đếm quyền"})
			return
		}

		// Get permissions with pagination
		if err := query.Offset(offset).Limit(limit).Find(&permissions).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Không thể lấy danh sách quyền"})
			return
		}

		// Group by category
		categoryMap := make(map[string][]models.Permission)
		for _, perm := range permissions {
			categoryMap[perm.Category] = append(categoryMap[perm.Category], perm)
		}

		c.JSON(http.StatusOK, gin.H{
			"permissions":        permissions,
			"permissions_by_category": categoryMap,
			"total":              total,
			"page":               page,
			"limit":              limit,
			"total_pages":        (total + int64(limit) - 1) / int64(limit),
		})
	}
}

// GetUserID extracts user ID from the Gin context
func GetUserID(c *gin.Context) uuid.UUID {
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(uuid.UUID); ok {
			return id
		}
	}
	// Return nil UUID if not found
	return uuid.Nil
}