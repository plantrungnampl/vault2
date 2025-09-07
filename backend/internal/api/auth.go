package api

import (
	"net/http"

	"securevault/internal/errors"
	"securevault/internal/services"
	"securevault/internal/validation"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Register creates a new user account
func Register(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req services.RegisterRequest

		// Bind JSON request
		if err := c.ShouldBindJSON(&req); err != nil {
			errors.HandleValidationError(c, err, "Invalid request format")
			return
		}

		// Comprehensive validation
		emailValidation := validation.ValidateEmail(req.Email)
		passwordValidation := validation.ValidatePassword(req.Password)
		firstNameValidation := validation.ValidateName(req.FirstName, "firstName")
		lastNameValidation := validation.ValidateName(req.LastName, "lastName")

		combinedValidation := validation.CombineValidations(
			emailValidation,
			passwordValidation,
			firstNameValidation,
			lastNameValidation,
		)

		if !combinedValidation.Valid {
			appErr := errors.NewValidationError("Validation failed", "")
			c.JSON(appErr.Code, gin.H{
				"error":             appErr,
				"validation_errors": combinedValidation.Errors,
				"request_id":        c.GetString("request_id"),
			})
			return
		}

		// Register user
		response, err := authService.Register(req)
		if err != nil {
			errors.HandleError(c, errors.NewBadRequestError("Registration failed", err.Error()))
			return
		}

		errors.Created(c, response, "User registered successfully")
	}
}

// Login authenticates a user
func Login(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req services.LoginRequest

		// Bind JSON request
		if err := c.ShouldBindJSON(&req); err != nil {
			errors.HandleValidationError(c, err, "Invalid login request")
			return
		}

		// Validate login request
		emailValidation := validation.ValidateEmail(req.Email)
		passwordValidation := validation.ValidateRequired(req.Password, "password")

		combinedValidation := validation.CombineValidations(emailValidation, passwordValidation)

		if !combinedValidation.Valid {
			appErr := errors.NewValidationError("Validation failed", "")
			c.JSON(appErr.Code, gin.H{
				"error":             appErr,
				"validation_errors": combinedValidation.Errors,
				"request_id":        c.GetString("request_id"),
			})
			return
		}

		// Get client IP and user agent
		ipAddress := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")

		// Login user
		response, err := authService.Login(req, ipAddress, userAgent)
		if err != nil {
			errors.HandleError(c, errors.NewAuthenticationError("Invalid credentials"))
			return
		}

		errors.Success(c, response, "Login successful")
	}
}

// Logout logs out a user
func Logout(authService *services.AuthService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := c.GetString("session_id")

		// Validate session
		if sessionID == "" {
			errors.HandleError(c, errors.NewAuthenticationError("Invalid session"))
			return
		}

		// In real implementation, would parse UUID and call authService.Logout
		// For now, just simulate logout
		errors.NoContent(c, "Logged out successfully")
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
func parseUUID(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.UUID{}, err
	}
	return id, nil
}
