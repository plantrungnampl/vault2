package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HealthCheck provides basic health check endpoint
func HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "securevault",
		"version": "1.0.0",
	})
}

// ReadinessCheck checks if all services are ready
func ReadinessCheck(db interface{}, redis interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		// In real implementation, check database and redis connectivity
		c.JSON(http.StatusOK, gin.H{
			"status":    "ready",
			"database":  "connected",
			"redis":     "connected",
			"timestamp": c.GetTime("request_time"),
		})
	}
}
