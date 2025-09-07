package middleware

import (
	"net/http"
	"time"

	"securevault/internal/models"
	"securevault/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequirePermission is middleware that checks if the current user has the required permission
func RequirePermission(rbacService *services.RBACService, resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from context (set by auth middleware)
		userIDInterface, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Không tìm thấy thông tin người dùng"})
			c.Abort()
			return
		}

		userID, ok := userIDInterface.(uuid.UUID)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "ID người dùng không hợp lệ"})
			c.Abort()
			return
		}

		// Get user role from context (set by auth middleware)
		roleInterface, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Không tìm thấy vai trò người dùng"})
			c.Abort()
			return
		}

		role, ok := roleInterface.(models.UserRole)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Vai trò người dùng không hợp lệ"})
			c.Abort()
			return
		}

		// Get MFA verification status
		mfaVerified, _ := c.Get("mfa_verified")
		mfaStatus, _ := mfaVerified.(bool)

		// Extract resource ID from URL parameter if available
		var resourceID *uuid.UUID
		if idParam := c.Param("id"); idParam != "" {
			if parsedID, err := uuid.Parse(idParam); err == nil {
				resourceID = &parsedID
			}
		}

		// Build permission context
		permCtx := models.PermissionContext{
			UserID:        userID,
			Role:          role,
			IPAddress:     c.ClientIP(),
			UserAgent:     c.Request.UserAgent(),
			Resource:      resource,
			ResourceID:    resourceID,
			Action:        action,
			Time:          time.Now(),
			MFAVerified:   mfaStatus,
			SecurityLevel: models.SecurityLevelStandard,
			RiskScore:     0.0,
		}

		// Check permission
		hasPermission, err := rbacService.CheckPermission(c.Request.Context(), permCtx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Lỗi kiểm tra quyền truy cập"})
			c.Abort()
			return
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Bạn không có quyền thực hiện hành động này",
				"required_permission": map[string]string{
					"resource": resource,
					"action":   action,
				},
			})
			c.Abort()
			return
		}

		// Permission granted, continue to next handler
		c.Next()
	}
}

// RequireAnyPermission checks if user has any of the specified permissions
func RequireAnyPermission(rbacService *services.RBACService, permissions []Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDInterface, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Không tìm thấy thông tin người dùng"})
			c.Abort()
			return
		}

		userID, ok := userIDInterface.(uuid.UUID)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "ID người dùng không hợp lệ"})
			c.Abort()
			return
		}

		roleInterface, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Không tìm thấy vai trò người dùng"})
			c.Abort()
			return
		}

		role, ok := roleInterface.(models.UserRole)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Vai trò người dùng không hợp lệ"})
			c.Abort()
			return
		}

		mfaVerified, _ := c.Get("mfa_verified")
		mfaStatus, _ := mfaVerified.(bool)

		var resourceID *uuid.UUID
		if idParam := c.Param("id"); idParam != "" {
			if parsedID, err := uuid.Parse(idParam); err == nil {
				resourceID = &parsedID
			}
		}

		// Check each permission until one is granted
		for _, perm := range permissions {
			permCtx := models.PermissionContext{
				UserID:        userID,
				Role:          role,
				IPAddress:     c.ClientIP(),
				UserAgent:     c.Request.UserAgent(),
				Resource:      perm.Resource,
				ResourceID:    resourceID,
				Action:        perm.Action,
				Time:          time.Now(),
				MFAVerified:   mfaStatus,
				SecurityLevel: models.SecurityLevelStandard,
				RiskScore:     0.0,
			}

			hasPermission, err := rbacService.CheckPermission(c.Request.Context(), permCtx)
			if err == nil && hasPermission {
				c.Next()
				return
			}
		}

		// No permissions granted
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Bạn không có quyền thực hiện hành động này",
			"required_permissions": permissions,
		})
		c.Abort()
	}
}

// Permission represents a resource-action pair for permission checking
type Permission struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// RequireRoleLevel checks if user has a role at or above the specified level
func RequireRoleLevel(rbacService *services.RBACService, minLevel int) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleInterface, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Không tìm thấy vai trò người dùng"})
			c.Abort()
			return
		}

		role, ok := roleInterface.(models.UserRole)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Vai trò người dùng không hợp lệ"})
			c.Abort()
			return
		}

		userLevel := getRoleLevel(role)
		if userLevel < minLevel {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Quyền truy cập không đủ",
				"required_level": minLevel,
				"current_level":  userLevel,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// getRoleLevel returns the hierarchical level for a role
func getRoleLevel(role models.UserRole) int {
	levelMap := map[models.UserRole]int{
		models.RoleBasicUser:     1,
		models.RolePremiumUser:   2,
		models.RoleTeamMember:    3,
		models.RoleVaultAdmin:    4,
		models.RoleSecurityAdmin: 5,
		models.RoleSuperAdmin:    6,
	}
	
	if level, exists := levelMap[role]; exists {
		return level
	}
	
	return 0 // Unknown role
}


// RequireHighSecurity combines MFA requirement with high-level role requirement
func RequireHighSecurity(rbacService *services.RBACService, authService *services.AuthService) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// First check MFA
		RequireMFA(authService)(c)
		if c.IsAborted() {
			return
		}

		// Then check role level (admin level or higher)
		RequireRoleLevel(rbacService, 4)(c)
		if c.IsAborted() {
			return
		}

		c.Next()
	})
}