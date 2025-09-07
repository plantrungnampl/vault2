package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Custom error types
type AppError struct {
	ID          string                 `json:"id"`
	Code        int                    `json:"code"`
	ErrorCode   string                 `json:"error_code"`
	Message     string                 `json:"message"`
	Type        string                 `json:"type"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Cause       error                  `json:"-"`
	UserMessage string                 `json:"user_message,omitempty"`
	Stack       []StackFrame           `json:"stack,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	RequestID   string                 `json:"request_id,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
}

// StackFrame represents a single stack frame
type StackFrame struct {
	Function string `json:"function"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %s)", e.ErrorCode, e.Message, e.Cause.Error())
	}
	return fmt.Sprintf("%s: %s", e.ErrorCode, e.Message)
}

// Error types
const (
	ErrorTypeValidation    = "validation_error"
	ErrorTypeAuthentication = "authentication_error"
	ErrorTypeAuthorization  = "authorization_error"
	ErrorTypeNotFound      = "not_found_error"
	ErrorTypeConflict      = "conflict_error"
	ErrorTypeInternal      = "internal_error"
	ErrorTypeRateLimit     = "rate_limit_error"
	ErrorTypeBadRequest    = "bad_request_error"
)

// Enhanced error constructors
func NewValidationError(message string, details string) *AppError {
	return &AppError{
		ID:          uuid.New().String(),
		Code:        http.StatusBadRequest,
		ErrorCode:   "VALIDATION_FAILED",
		Message:     message,
		Type:        ErrorTypeValidation,
		Details:     map[string]interface{}{"validation": details, "message": details},
		Stack:       captureStack(2),
		Timestamp:   time.Now(),
		UserMessage: "Dữ liệu nhập vào không hợp lệ",
	}
}

func NewAuthenticationError(message string) *AppError {
	return &AppError{
		ID:          uuid.New().String(),
		Code:        http.StatusUnauthorized,
		ErrorCode:   "AUTH_UNAUTHORIZED",
		Message:     message,
		Type:        ErrorTypeAuthentication,
		Stack:       captureStack(2),
		Timestamp:   time.Now(),
		UserMessage: "Vui lòng đăng nhập để tiếp tục",
	}
}

func NewAuthorizationError(message string) *AppError {
	return &AppError{
		ID:          uuid.New().String(),
		Code:        http.StatusForbidden,
		ErrorCode:   "AUTH_FORBIDDEN",
		Message:     message,
		Type:        ErrorTypeAuthorization,
		Stack:       captureStack(2),
		Timestamp:   time.Now(),
		UserMessage: "Bạn không có quyền thực hiện hành động này",
	}
}

func NewNotFoundError(resource string) *AppError {
	return &AppError{
		ID:          uuid.New().String(),
		Code:        http.StatusNotFound,
		ErrorCode:   "RECORD_NOT_FOUND",
		Message:     fmt.Sprintf("%s not found", resource),
		Type:        ErrorTypeNotFound,
		Details:     map[string]interface{}{"resource": resource},
		Stack:       captureStack(2),
		Timestamp:   time.Now(),
		UserMessage: "Không tìm thấy dữ liệu yêu cầu",
	}
}

func NewConflictError(message string) *AppError {
	return &AppError{
		ID:          uuid.New().String(),
		Code:        http.StatusConflict,
		ErrorCode:   "DUPLICATE_RECORD",
		Message:     message,
		Type:        ErrorTypeConflict,
		Stack:       captureStack(2),
		Timestamp:   time.Now(),
		UserMessage: "Dữ liệu đã tồn tại",
	}
}

func NewInternalError(message string, details string) *AppError {
	return &AppError{
		ID:        uuid.New().String(),
		Code:      http.StatusInternalServerError,
		ErrorCode: "INTERNAL_ERROR",
		Message:   message,
		Type:      ErrorTypeInternal,
		Details:   map[string]interface{}{"details": details},
		Stack:     captureStack(2),
		Timestamp: time.Now(),
		UserMessage: "Đã xảy ra lỗi hệ thống. Vui lòng thử lại sau",
	}
}

func NewBadRequestError(message string, details string) *AppError {
	return &AppError{
		ID:        uuid.New().String(),
		Code:      http.StatusBadRequest,
		ErrorCode: "BAD_REQUEST",
		Message:   message,
		Type:      ErrorTypeBadRequest,
		Details:   map[string]interface{}{"details": details},
		Stack:     captureStack(2),
		Timestamp: time.Now(),
		UserMessage: "Yêu cầu không hợp lệ",
	}
}

func NewRateLimitError(message string) *AppError {
	return &AppError{
		ID:        uuid.New().String(),
		Code:      http.StatusTooManyRequests,
		ErrorCode: "RATE_LIMIT",
		Message:   message,
		Type:      ErrorTypeRateLimit,
		Stack:     captureStack(2),
		Timestamp: time.Now(),
		UserMessage: "Quá nhiều yêu cầu. Vui lòng thử lại sau",
	}
}

// Error response structure
type ErrorResponse struct {
	Error     *AppError          `json:"error"`
	RequestID string             `json:"request_id,omitempty"`
	Timestamp string             `json:"timestamp"`
	Path      string             `json:"path"`
	Method    string             `json:"method"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// HandleError sends a standardized error response
func HandleError(c *gin.Context, err error) {
	var appErr *AppError
	
	switch e := err.(type) {
	case *AppError:
		appErr = e
	default:
		// Convert unknown errors to internal errors
		appErr = NewInternalError("An unexpected error occurred", e.Error())
	}

	requestID, _ := c.Get("request_id")
	
	response := ErrorResponse{
		Error:     appErr,
		RequestID: fmt.Sprintf("%v", requestID),
		Timestamp: getCurrentTimestamp(),
		Path:      c.Request.URL.Path,
		Method:    c.Request.Method,
	}

	c.JSON(appErr.Code, response)
}

// HandleValidationError handles binding/validation errors
func HandleValidationError(c *gin.Context, err error, customMessage ...string) {
	message := "Validation failed"
	if len(customMessage) > 0 {
		message = customMessage[0]
	}

	requestID, _ := c.Get("request_id")
	
	response := ErrorResponse{
		Error: &AppError{
			ID:        uuid.New().String(),
			Code:      http.StatusBadRequest,
			ErrorCode: "VALIDATION_FAILED",
			Message:   message,
			Type:      ErrorTypeValidation,
			Details:   map[string]interface{}{"validation": err.Error()},
			Stack:     captureStack(2),
			Timestamp: time.Now(),
			UserMessage: "Dữ liệu nhập vào không hợp lệ",
		},
		RequestID: fmt.Sprintf("%v", requestID),
		Timestamp: getCurrentTimestamp(),
		Path:      c.Request.URL.Path,
		Method:    c.Request.Method,
	}

	c.JSON(http.StatusBadRequest, response)
}

// Success response helpers
func Success(c *gin.Context, data interface{}, message ...string) {
	response := gin.H{
		"success": true,
		"data":    data,
	}
	
	if len(message) > 0 {
		response["message"] = message[0]
	}
	
	if requestID, exists := c.Get("request_id"); exists {
		response["request_id"] = requestID
	}
	
	c.JSON(http.StatusOK, response)
}

func SuccessWithPagination(c *gin.Context, data interface{}, pagination gin.H, message ...string) {
	response := gin.H{
		"success":    true,
		"data":       data,
		"pagination": pagination,
	}
	
	if len(message) > 0 {
		response["message"] = message[0]
	}
	
	if requestID, exists := c.Get("request_id"); exists {
		response["request_id"] = requestID
	}
	
	c.JSON(http.StatusOK, response)
}

func Created(c *gin.Context, data interface{}, message ...string) {
	response := gin.H{
		"success": true,
		"data":    data,
	}
	
	if len(message) > 0 {
		response["message"] = message[0]
	}
	
	if requestID, exists := c.Get("request_id"); exists {
		response["request_id"] = requestID
	}
	
	c.JSON(http.StatusCreated, response)
}

func NoContent(c *gin.Context, message ...string) {
	response := gin.H{
		"success": true,
	}
	
	if len(message) > 0 {
		response["message"] = message[0]
	}
	
	if requestID, exists := c.Get("request_id"); exists {
		response["request_id"] = requestID
	}
	
	c.JSON(http.StatusOK, response)
}

func getCurrentTimestamp() string {
	return time.Now().Format(time.RFC3339)
}

// captureStack captures the current stack trace
func captureStack(skip int) []StackFrame {
	var frames []StackFrame
	
	for i := skip; ; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		
		function := runtime.FuncForPC(pc)
		var funcName string
		if function != nil {
			funcName = function.Name()
		}
		
		// Clean up file path to show relative path
		if idx := strings.LastIndex(file, "/securevault/"); idx != -1 {
			file = file[idx+1:]
		}
		
		frames = append(frames, StackFrame{
			Function: funcName,
			File:     file,
			Line:     line,
		})
		
		// Limit stack depth
		if len(frames) >= 10 {
			break
		}
	}
	
	return frames
}

// WithContext adds contextual information to an error
func (e *AppError) WithContext(key string, value interface{}) *AppError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithRequestID adds request ID for tracing
func (e *AppError) WithRequestID(requestID string) *AppError {
	e.RequestID = requestID
	return e
}

// WithUserID adds user ID for audit purposes
func (e *AppError) WithUserID(userID string) *AppError {
	e.UserID = userID
	return e
}

// ToJSON converts the error to JSON for logging
func (e *AppError) ToJSON() string {
	data, _ := json.MarshalIndent(e, "", "  ")
	return string(data)
}

// Wrap creates a new AppError wrapping an existing error
func WrapError(err error, code int, errorCode, message string) *AppError {
	if err == nil {
		return nil
	}

	return &AppError{
		ID:        uuid.New().String(),
		Code:      code,
		ErrorCode: errorCode,
		Message:   message,
		Cause:     err,
		Stack:     captureStack(2),
		Timestamp: time.Now(),
	}
}

// Common enhanced error constructors
func NewMFAError(message string) *AppError {
	return &AppError{
		ID:          uuid.New().String(),
		Code:        http.StatusUnauthorized,
		ErrorCode:   "MFA_REQUIRED",
		Message:     message,
		Type:        ErrorTypeAuthentication,
		Stack:       captureStack(2),
		Timestamp:   time.Now(),
		UserMessage: "Cần xác thực đa yếu tố để tiếp tục",
	}
}

func NewEncryptionError(message string) *AppError {
	return &AppError{
		ID:          uuid.New().String(),
		Code:        http.StatusInternalServerError,
		ErrorCode:   "ENCRYPTION_FAILED",
		Message:     message,
		Type:        ErrorTypeInternal,
		Stack:       captureStack(2),
		Timestamp:   time.Now(),
		UserMessage: "Lỗi mã hóa dữ liệu",
	}
}

func NewPermissionError(message string) *AppError {
	return &AppError{
		ID:          uuid.New().String(),
		Code:        http.StatusForbidden,
		ErrorCode:   "PERMISSION_DENIED",
		Message:     message,
		Type:        ErrorTypeAuthorization,
		Stack:       captureStack(2),
		Timestamp:   time.Now(),
		UserMessage: "Bạn không có quyền thực hiện hành động này",
	}
}

func NewDatabaseError(err error) *AppError {
	appErr := WrapError(err, http.StatusInternalServerError, "DATABASE_ERROR", "Database operation failed")
	return appErr.WithContext("error_type", "database")
}

func NewServiceError(service, message string) *AppError {
	return &AppError{
		ID:        uuid.New().String(),
		Code:      http.StatusServiceUnavailable,
		ErrorCode: "SERVICE_UNAVAILABLE",
		Message:   message,
		Type:      ErrorTypeInternal,
		Stack:     captureStack(2),
		Timestamp: time.Now(),
		Context: map[string]interface{}{
			"service": service,
		},
		UserMessage: "Dịch vụ tạm thời không khả dụng",
	}
}