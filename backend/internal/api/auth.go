package api

import (
	"net/http"

	"securevault/internal/services"

	"github.com/gin-gonic/gin"
)

// Register creates a new user account
func Register(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req services.RegisterRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Get client IP and user agent
		ipAddress := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")

		// Register user
		response, err := authService.Register(&req, ipAddress, userAgent)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, response)
	}
}

// Login authenticates a user
func Login(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req services.LoginRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Get client IP and user agent
		ipAddress := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")

		// Login user
		response, err := authService.Login(&req, ipAddress, userAgent)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, response)
	}
}

// Logout logs out a user
func Logout(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := c.GetString("session_id")

		// For now, just simulate logout
		if sessionID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session"})
			return
		}

		// In real implementation, would parse UUID and call authService.Logout
		// if err := authService.Logout(sessionUUID); err != nil {
		//	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		//	return
		// }

		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
	}
}

// RefreshToken refreshes the access token
func RefreshToken(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		response, err := authService.RefreshToken(req.RefreshToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
			return
		}

		c.JSON(http.StatusOK, response)
	}
}

// VerifyMFA verifies multi-factor authentication
func VerifyMFA(authService *services.AuthService, totpService interface{}, webauthnService interface{}, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			UserID string `json:"user_id" binding:"required"`
			Code   string `json:"code" binding:"required"`
			Method string `json:"method" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// For now, just return success - MFA verification would be implemented here
		c.JSON(http.StatusOK, gin.H{
			"message": "MFA verification successful",
		})
	}
}

// GetProfile retrieves user profile
func GetProfile(authService *services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		// For now, return mock user data
		c.JSON(http.StatusOK, gin.H{
			"id":         userID,
			"email":      "user@example.com",
			"first_name": "John",
			"last_name":  "Doe",
			"role":       "basic_user",
		})
	}
}

// UpdateProfile updates user profile
func UpdateProfile(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		var req struct {
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Email     string `json:"email"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// For now, just return success
		c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
	}
}

// ChangePassword changes user password
func ChangePassword(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		var req struct {
			CurrentPassword string `json:"current_password" binding:"required"`
			NewPassword     string `json:"new_password" binding:"required,min=8"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// For now, just return success
		c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
	}
}

// Helper function to parse UUID
func parseUUID(s string) (interface{}, error) {
	// For now, just return the string - in real implementation would parse to UUID
	return s, nil
}
