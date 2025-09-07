package middleware

import (
	"bytes"
	"io"
	"strings"

	"securevault/internal/errors"
	"securevault/internal/security"
	"securevault/internal/validation"

	"github.com/gin-gonic/gin"
)

// RequestValidation middleware validates and sanitizes incoming requests
func RequestValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip validation for health checks and static files
		if shouldSkipValidation(c.Request.URL.Path) {
			c.Next()
			return
		}

		// Validate request size
		if c.Request.ContentLength > 10*1024*1024 { // 10MB limit
			errors.HandleError(c, errors.NewBadRequestError("Request too large", "Maximum request size is 10MB"))
			c.Abort()
			return
		}

		// Validate Content-Type for POST/PUT requests
		if c.Request.Method == "POST" || c.Request.Method == "PUT" {
			contentType := c.GetHeader("Content-Type")
			if contentType == "" {
				errors.HandleError(c, errors.NewBadRequestError("Missing Content-Type header", ""))
				c.Abort()
				return
			}

			if !strings.Contains(contentType, "application/json") &&
				!strings.Contains(contentType, "multipart/form-data") {
				errors.HandleError(c, errors.NewBadRequestError("Unsupported Content-Type", "Only application/json and multipart/form-data are supported"))
				c.Abort()
				return
			}
		}

		// Validate query parameters
		if err := validateQueryParams(c); err != nil {
			errors.HandleError(c, err)
			c.Abort()
			return
		}

		// For JSON requests, validate request body
		if strings.Contains(c.GetHeader("Content-Type"), "application/json") {
			if err := validateJSONBody(c); err != nil {
				errors.HandleError(c, err)
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// SecurityValidation middleware performs security checks
func SecurityValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for common attack patterns in URL
		if !security.ValidateNoSQLInjection(c.Request.URL.String()) ||
			!security.ValidateNoXSS(c.Request.URL.String()) ||
			!security.ValidateNoPathTraversal(c.Request.URL.String()) {
			errors.HandleError(c, errors.NewBadRequestError("Malicious request detected", "Request contains potentially dangerous patterns"))
			c.Abort()
			return
		}

		// Check User-Agent header
		userAgent := c.GetHeader("User-Agent")
		if userAgent == "" || isKnownMaliciousUserAgent(userAgent) {
			errors.HandleError(c, errors.NewBadRequestError("Invalid User-Agent", "Request blocked due to suspicious User-Agent"))
			c.Abort()
			return
		}

		// Check for suspicious headers
		if hasHopHeaders(c) {
			errors.HandleError(c, errors.NewBadRequestError("Suspicious headers detected", "Request contains potentially dangerous headers"))
			c.Abort()
			return
		}

		c.Next()
	}
}

// InputSanitization middleware sanitizes input data
func InputSanitization() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Sanitize query parameters
		sanitizeQueryParams(c)

		// For JSON requests, we'll sanitize in the request handlers after binding
		// This middleware focuses on basic URL and header sanitization

		c.Next()
	}
}

// PaginationValidation middleware validates pagination parameters
func PaginationValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		pageParam := c.DefaultQuery("page", "1")
		limitParam := c.DefaultQuery("limit", "20")

		// Convert to integers (placeholder for future use)
		// page := 1
		// limit := 20

		if pageParam != "1" {
			pageValidation := validation.ValidateRequired(pageParam, "page")
			if !pageValidation.Valid {
				errors.HandleError(c, errors.NewValidationError("Invalid page parameter", ""))
				c.Abort()
				return
			}
		}

		if limitParam != "20" {
			limitValidation := validation.ValidateRequired(limitParam, "limit")
			if !limitValidation.Valid {
				errors.HandleError(c, errors.NewValidationError("Invalid limit parameter", ""))
				c.Abort()
				return
			}
		}

		// Additional pagination validation would be done here

		c.Next()
	}
}

// Helper functions

func shouldSkipValidation(path string) bool {
	skipPaths := []string{
		"/health",
		"/ready",
		"/metrics",
		"/favicon.ico",
	}

	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}

	return false
}

func validateQueryParams(c *gin.Context) error {
	for key, values := range c.Request.URL.Query() {
		// Validate parameter name
		if !security.ValidateNoXSS(key) || !security.ValidateNoSQLInjection(key) {
			return errors.NewBadRequestError("Invalid query parameter", "Parameter name contains dangerous characters: "+key)
		}

		// Validate parameter values
		for _, value := range values {
			if !security.ValidateNoXSS(value) || !security.ValidateNoSQLInjection(value) {
				return errors.NewBadRequestError("Invalid query parameter value", "Parameter value contains dangerous characters: "+value)
			}

			// Check parameter value length
			if len(value) > 1000 {
				return errors.NewBadRequestError("Query parameter too long", "Parameter value exceeds maximum length: "+key)
			}
		}
	}

	return nil
}

func validateJSONBody(c *gin.Context) error {
	if c.Request.Body == nil {
		return nil
	}

	// Read body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return errors.NewBadRequestError("Cannot read request body", err.Error())
	}

	// Restore body for subsequent handlers
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	// Basic JSON structure validation
	if len(body) > 0 {
		bodyStr := string(body)

		// Check for potentially dangerous patterns
		if !security.ValidateNoXSS(bodyStr) || !security.ValidateNoSQLInjection(bodyStr) {
			return errors.NewBadRequestError("Malicious content detected", "Request body contains potentially dangerous patterns")
		}

		// Check for excessively nested JSON (potential DoS)
		if countJSONDepth(bodyStr) > 10 {
			return errors.NewBadRequestError("JSON too deeply nested", "Request body exceeds maximum nesting depth")
		}
	}

	return nil
}

func sanitizeQueryParams(c *gin.Context) {
	query := c.Request.URL.Query()

	for key, values := range query {
		for i, value := range values {
			values[i] = security.SanitizeInput(value)
		}
		query[key] = values
	}

	c.Request.URL.RawQuery = query.Encode()
}

func isKnownMaliciousUserAgent(userAgent string) bool {
	maliciousPatterns := []string{
		"sqlmap",
		"nikto",
		"nessus",
		"burpsuite",
		"w3af",
		"acunetix",
		"netsparker",
	}

	lowerUA := strings.ToLower(userAgent)
	for _, pattern := range maliciousPatterns {
		if strings.Contains(lowerUA, pattern) {
			return true
		}
	}

	return false
}

func hasHopHeaders(c *gin.Context) bool {
	// Check for hop-by-hop headers that shouldn't be present
	hopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	for _, header := range hopHeaders {
		if c.GetHeader(header) != "" {
			return true
		}
	}

	return false
}

func countJSONDepth(json string) int {
	depth := 0
	maxDepth := 0

	for _, char := range json {
		switch char {
		case '{', '[':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case '}', ']':
			depth--
		}
	}

	return maxDepth
}
