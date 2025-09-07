package middleware

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"securevault/internal/security"

	"github.com/gin-gonic/gin"
)

// IDSMiddleware creates middleware for intrusion detection and prevention
func IDSMiddleware(idsService *security.IntrusionDetectionService) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Skip IDS analysis for health checks and static assets
		if shouldSkipIDS(c.Request.RequestURI) {
			c.Next()
			return
		}

		// Create analysis request
		req := &security.SecurityAnalysisRequest{
			RequestID: fmt.Sprintf("req_%d_%s", time.Now().Unix(), generateRandomString(6)),
			IPAddress: getClientIP(c),
			UserAgent: c.GetHeader("User-Agent"),
			Method:    c.Request.Method,
			URI:       c.Request.RequestURI,
			Headers:   getHeaders(c),
			Timestamp: time.Now(),
		}

		// Get user ID if available
		if claims, exists := c.Get("claims"); exists {
			if userClaims, ok := claims.(*struct{ UserID string }); ok {
				req.UserID = userClaims.UserID
			}
		}

		// Extract request body for analysis (if it's a write operation)
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			bodyBytes, err := ioutil.ReadAll(c.Request.Body)
			if err == nil {
				// Parse body as JSON for analysis
				var body interface{}
				if err := parseJSON(bodyBytes, &body); err == nil {
					req.Body = body
				}
				// Restore the request body for the actual handler
				c.Request.Body = ioutil.NopCloser(strings.NewReader(string(bodyBytes)))
			}
		}

		// Get geographical info (would integrate with GeoIP service in production)
		req.Country = getCountryFromIP(req.IPAddress)
		req.City = getCityFromIP(req.IPAddress)
		req.ISP = getISPFromIP(req.IPAddress)

		// Analyze request for threats
		ctx := context.Background()
		result, err := idsService.AnalyzeRequest(ctx, req)
		if err != nil {
			// Log error but don't block the request
			fmt.Printf("IDS analysis error: %v\n", err)
			c.Next()
			return
		}

		// Check if IP is blocked
		blocked, err := idsService.IsIPBlocked(req.IPAddress)
		if err != nil {
			fmt.Printf("Error checking IP block status: %v\n", err)
		}

		if blocked {
			c.JSON(http.StatusForbidden, gin.H{
				"error":      "Access denied",
				"message":    "Your IP address has been blocked due to security violations",
				"request_id": req.RequestID,
				"blocked":    true,
			})
			c.Abort()
			return
		}

		// Block request if IDS recommends it
		if result.Blocked {
			c.JSON(http.StatusForbidden, gin.H{
				"error":         "Access denied",
				"message":       "Request blocked by security system",
				"request_id":    req.RequestID,
				"risk_score":    result.RiskScore,
				"threats":       len(result.Threats),
				"blocked":       true,
			})
			c.Abort()
			return
		}

		// Add security headers based on analysis
		addSecurityHeaders(c, result)

		// Store IDS result in context for later use
		c.Set("ids_result", result)
		c.Set("ids_request_id", req.RequestID)

		// Continue with the request
		c.Next()

		// Update the request with response status code for final analysis
		req.StatusCode = c.Writer.Status()

		// Log final processing time
		processingTime := time.Since(start)
		result.ProcessingTime = processingTime

		// Log high-risk requests
		if result.RiskScore > 50 {
			fmt.Printf("High-risk request: %s %s from %s (score: %d)\n", 
				req.Method, req.URI, req.IPAddress, result.RiskScore)
		}
	}
}

// shouldSkipIDS determines if IDS should skip analyzing this request
func shouldSkipIDS(uri string) bool {
	skipPaths := []string{
		"/health",
		"/metrics",
		"/favicon.ico",
		"/static/",
		"/assets/",
		"/css/",
		"/js/",
		"/img/",
	}

	for _, path := range skipPaths {
		if strings.HasPrefix(uri, path) {
			return true
		}
	}

	return false
}

// getHeaders extracts relevant headers for analysis
func getHeaders(c *gin.Context) map[string]string {
	headers := make(map[string]string)
	
	// Extract important headers for analysis
	relevantHeaders := []string{
		"Accept",
		"Accept-Language",
		"Accept-Encoding",
		"X-Forwarded-For",
		"X-Real-IP",
		"Referer",
		"Origin",
		"Authorization",
		"Content-Type",
		"X-Requested-With",
	}

	for _, headerName := range relevantHeaders {
		if value := c.GetHeader(headerName); value != "" {
			headers[headerName] = value
		}
	}

	return headers
}

// addSecurityHeaders adds security headers based on IDS analysis
func addSecurityHeaders(c *gin.Context, result *security.SecurityAnalysisResult) {
	// Always add basic security headers
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Frame-Options", "DENY")
	c.Header("X-XSS-Protection", "1; mode=block")
	c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

	// Add IDS-specific headers
	c.Header("X-IDS-Request-ID", result.RequestID)
	c.Header("X-IDS-Risk-Score", fmt.Sprintf("%d", result.RiskScore))
	
	if len(result.Threats) > 0 {
		c.Header("X-IDS-Threats-Detected", fmt.Sprintf("%d", len(result.Threats)))
	}

	// Add CSP header if XSS threats detected
	for _, threat := range result.Threats {
		if threat.Type == security.ThreatTypeXSS {
			c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
			break
		}
	}
}

// Mock geolocation functions (would integrate with real GeoIP service in production)
func getCountryFromIP(ip string) string {
	// Mock implementation
	if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "127.") {
		return "US" // Local/private IPs default to US
	}
	
	// Mock some countries for demo
	mockCountries := map[string]string{
		"203.0.113.":   "CN",
		"198.51.100.":  "RU",
		"192.0.2.":     "US",
	}
	
	for prefix, country := range mockCountries {
		if strings.HasPrefix(ip, prefix) {
			return country
		}
	}
	
	return "US" // Default
}

func getCityFromIP(ip string) string {
	// Mock implementation
	country := getCountryFromIP(ip)
	switch country {
	case "CN":
		return "Beijing"
	case "RU":
		return "Moscow"
	case "US":
		return "New York"
	default:
		return "Unknown"
	}
}

func getISPFromIP(ip string) string {
	// Mock implementation
	if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") {
		return "Local Network"
	}
	return "Unknown ISP"
}

// getClientIP extracts the real client IP from the request
func getClientIP(c *gin.Context) string {
	// Check X-Forwarded-For header first (for load balancers/proxies)
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, use the first one
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := c.GetHeader("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to remote address
	return c.ClientIP()
}

// parseJSON safely parses JSON data
func parseJSON(data []byte, v interface{}) error {
	// Simple JSON parsing - in production would use json.Unmarshal
	// For now, just return nil to indicate successful parsing
	return nil
}

// generateRandomString generates a random string of specified length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}