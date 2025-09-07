package middleware

import (
	"fmt"
	"log/slog"
	"runtime/debug"

	"securevault/internal/errors"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ErrorRecovery middleware handles panics and provides detailed error recovery
func ErrorRecovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		log := slog.Default()
		
		// Get request ID for tracking
		requestID := getRequestID(c)
		userID := getUserID(c)
		
		// Log the panic with full details
		stack := string(debug.Stack())
		log.Error("Panic recovered in request handler",
			"error", recovered,
			"request_id", requestID,
			"user_id", userID,
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"ip", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
			"stack", stack,
		)

		// Create enhanced internal error
		appErr := errors.NewInternalError(
			"Internal server error",
			fmt.Sprintf("Panic: %v", recovered),
		).WithRequestID(requestID).WithUserID(userID)

		// Send structured error response
		handleEnhancedError(c, appErr)
	})
}

// ErrorHandler middleware for handling custom application errors
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Check for errors after processing
		if len(c.Errors) > 0 {
			log := slog.Default()
			
			// Log all accumulated errors
			for _, err := range c.Errors {
				log.Error("Request error",
					"error", err.Error(),
					"type", err.Type,
					"path", c.Request.URL.Path,
					"method", c.Request.Method,
					"ip", c.ClientIP(),
				)
			}

			// Get the last error and handle it
			lastError := c.Errors.Last()
			if lastError != nil {
				appErr := errors.NewInternalError("Request processing failed", lastError.Error())
				errors.HandleError(c, appErr)
			}
		}
	}
}

// ValidationErrorHandler middleware for input validation errors
func ValidationErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Check if validation errors exist in context
		if validationErrors, exists := c.Get("validation_errors"); exists {
			if errList, ok := validationErrors.([]error); ok {
				log := slog.Default()
				
				log.Warn("Validation errors",
					"error_count", len(errList),
					"path", c.Request.URL.Path,
					"method", c.Request.Method,
					"ip", c.ClientIP(),
				)

				// Handle validation errors
				if len(errList) > 0 {
					err := errors.NewValidationError("Multiple validation errors", "")
					errors.HandleError(c, err)
				}
			}
		}
	}
}

// RateLimitErrorHandler handles rate limiting errors
func RateLimitErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Check for rate limit exceeded
		if rateLimited, exists := c.Get("rate_limited"); exists {
			if limited, ok := rateLimited.(bool); ok && limited {
				err := errors.NewRateLimitError("Too many requests")
				errors.HandleError(c, err)
				c.Abort()
			}
		}
	}
}

// NotFoundHandler handles 404 errors
func NotFoundHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := errors.NewNotFoundError("Endpoint")
		errors.HandleError(c, err)
	}
}

// MethodNotAllowedHandler handles 405 errors
func MethodNotAllowedHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := errors.NewBadRequestError("Method not allowed", 
			fmt.Sprintf("Method %s is not allowed for this endpoint", c.Request.Method))
		errors.HandleError(c, err)
	}
}

// Helper functions for enhanced error handling

// handleEnhancedError provides comprehensive error handling with logging and response
func handleEnhancedError(c *gin.Context, appErr *errors.AppError) {
	// Don't send response if already sent
	if c.Writer.Written() {
		return
	}

	// Log the error with appropriate level
	logEnhancedError(appErr, c)

	// Send user-safe response
	response := gin.H{
		"error": gin.H{
			"id":      appErr.ID,
			"code":    appErr.ErrorCode,
			"message": getUserFriendlyMessage(appErr),
			"type":    appErr.Type,
		},
		"timestamp":  appErr.Timestamp,
		"request_id": appErr.RequestID,
		"path":       c.Request.URL.Path,
		"method":     c.Request.Method,
	}

	// Add safe details for debugging
	if appErr.Details != nil {
		safeDetails := make(map[string]interface{})
		for key, value := range appErr.Details {
			if isSafeForUser(key) {
				safeDetails[key] = value
			}
		}
		if len(safeDetails) > 0 {
			response["details"] = safeDetails
		}
	}

	c.JSON(appErr.Code, response)
}

// logEnhancedError logs errors with contextual information
func logEnhancedError(appErr *errors.AppError, c *gin.Context) {
	log := slog.Default()
	
	logFields := []interface{}{
		"error_id", appErr.ID,
		"error_code", appErr.ErrorCode,
		"message", appErr.Message,
		"http_status", appErr.Code,
		"method", c.Request.Method,
		"path", c.Request.URL.Path,
		"ip", c.ClientIP(),
		"user_agent", c.Request.UserAgent(),
	}

	if appErr.RequestID != "" {
		logFields = append(logFields, "request_id", appErr.RequestID)
	}

	if appErr.UserID != "" {
		logFields = append(logFields, "user_id", appErr.UserID)
	}

	if appErr.Cause != nil {
		logFields = append(logFields, "cause", appErr.Cause.Error())
	}

	// Add context fields
	for key, value := range appErr.Context {
		logFields = append(logFields, fmt.Sprintf("ctx_%s", key), value)
	}

	// Log with appropriate level
	switch {
	case appErr.Code >= 500:
		log.Error("Server error occurred", logFields...)
		if len(appErr.Stack) > 0 {
			log.Error("Stack trace", "stack", formatStackTrace(appErr))
		}
	case appErr.Code >= 400:
		log.Warn("Client error occurred", logFields...)
	default:
		log.Info("Request completed with error", logFields...)
	}
}

// formatStackTrace formats stack trace for logging
func formatStackTrace(appErr *errors.AppError) string {
	if len(appErr.Stack) == 0 {
		return ""
	}

	var trace string
	for _, frame := range appErr.Stack {
		trace += fmt.Sprintf("\n\tat %s (%s:%d)", frame.Function, frame.File, frame.Line)
	}
	return trace
}

// getUserFriendlyMessage returns localized user-friendly messages
func getUserFriendlyMessage(appErr *errors.AppError) string {
	if appErr.UserMessage != "" {
		return appErr.UserMessage
	}

	// Default Vietnamese messages based on error code
	switch appErr.ErrorCode {
	case "VALIDATION_FAILED":
		return "Dữ liệu nhập vào không hợp lệ"
	case "AUTH_UNAUTHORIZED":
		return "Vui lòng đăng nhập để tiếp tục"
	case "AUTH_FORBIDDEN", "PERMISSION_DENIED":
		return "Bạn không có quyền thực hiện hành động này"
	case "MFA_REQUIRED":
		return "Cần xác thực đa yếu tố để tiếp tục"
	case "RECORD_NOT_FOUND":
		return "Không tìm thấy dữ liệu yêu cầu"
	case "DUPLICATE_RECORD":
		return "Dữ liệu đã tồn tại"
	case "SERVICE_UNAVAILABLE":
		return "Dịch vụ tạm thời không khả dụng"
	case "RATE_LIMIT":
		return "Quá nhiều yêu cầu. Vui lòng thử lại sau"
	case "ENCRYPTION_FAILED":
		return "Lỗi mã hóa dữ liệu"
	case "DATABASE_ERROR":
		return "Lỗi cơ sở dữ liệu"
	default:
		return "Đã xảy ra lỗi hệ thống"
	}
}

// isSafeForUser determines if error details are safe to expose to users
func isSafeForUser(key string) bool {
	safeKeys := map[string]bool{
		"field":              true,
		"validation":         true,
		"expected_format":    true,
		"min_length":         true,
		"max_length":         true,
		"allowed_values":     true,
		"validation_errors":  true,
		"retry_after":        true,
		"expires_at":         true,
	}
	
	return safeKeys[key]
}

// getRequestID safely extracts request ID from context
func getRequestID(c *gin.Context) string {
	if requestID, exists := c.Get("request_id"); exists {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}

// getUserID safely extracts user ID from context
func getUserID(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(uuid.UUID); ok {
			return id.String()
		}
	}
	return ""
}