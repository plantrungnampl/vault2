package middleware

import (
	"net/http"
	"strings"

	"securevault/internal/services"

	"github.com/gin-gonic/gin"
)

// RequireAuth middleware validates JWT token
func RequireAuth(authService *services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		token := tokenParts[1]

		// Validate token
		claims, err := authService.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Set claims in context
		c.Set("claims", claims)
		
		// Set user information in context for easy access
		c.Set("user_id", claims.UserID.String())
		c.Set("user_email", claims.Email)
		c.Set("user_role", string(claims.Role))
		c.Set("session_id", claims.SessionID.String())
		c.Set("mfa_verified", claims.MFAVerified)

		c.Next()
	}
}

// RequireAdminAuth middleware requires admin role
func RequireAdminAuth(authService *services.AuthService) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// First check authentication
		RequireAuth(authService)(c)
		if c.IsAborted() {
			return
		}

		// Check if user has admin role
		userRole := c.GetString("user_role")
		if !isAdminRole(userRole) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			c.Abort()
			return
		}

		c.Next()
	})
}

// RequireMFA middleware requires MFA verification
func RequireMFA(authService *services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		mfaVerified := c.GetBool("mfa_verified")
		if !mfaVerified {
			c.JSON(http.StatusForbidden, gin.H{"error": "MFA verification required"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Helper function to check if role is admin
func isAdminRole(role string) bool {
	adminRoles := []string{
		"vault_admin",
		"security_admin",
		"super_admin",
	}

	for _, adminRole := range adminRoles {
		if role == adminRole {
			return true
		}
	}
	return false
}
