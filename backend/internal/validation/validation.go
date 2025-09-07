package validation

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/uuid"
)

// Validation rules and constants
const (
	MinPasswordLength = 14
	MaxPasswordLength = 128
	MinUsernameLength = 3
	MaxUsernameLength = 50
)

var (
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	phoneRegex = regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
)

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// ValidationResult holds validation results
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors,omitempty"`
}

// Add error to validation result
func (vr *ValidationResult) AddError(field, message, code string) {
	vr.Valid = false
	vr.Errors = append(vr.Errors, ValidationError{
		Field:   field,
		Message: message,
		Code:    code,
	})
}

// Email validation
func ValidateEmail(email string) ValidationResult {
	result := ValidationResult{Valid: true}
	
	if email == "" {
		result.AddError("email", "Email is required", "required")
		return result
	}
	
	if len(email) > 254 {
		result.AddError("email", "Email too long", "max_length")
		return result
	}
	
	if !emailRegex.MatchString(email) {
		result.AddError("email", "Invalid email format", "invalid_format")
		return result
	}
	
	return result
}

// Password validation
func ValidatePassword(password string) ValidationResult {
	result := ValidationResult{Valid: true}
	
	if password == "" {
		result.AddError("password", "Password is required", "required")
		return result
	}
	
	if len(password) < MinPasswordLength {
		result.AddError("password", fmt.Sprintf("Password must be at least %d characters", MinPasswordLength), "min_length")
	}
	
	if len(password) > MaxPasswordLength {
		result.AddError("password", fmt.Sprintf("Password must be no more than %d characters", MaxPasswordLength), "max_length")
	}
	
	// Password strength requirements
	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)
	
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	
	if !hasUpper {
		result.AddError("password", "Password must contain at least one uppercase letter", "missing_uppercase")
	}
	
	if !hasLower {
		result.AddError("password", "Password must contain at least one lowercase letter", "missing_lowercase")
	}
	
	if !hasNumber {
		result.AddError("password", "Password must contain at least one number", "missing_number")
	}
	
	if !hasSpecial {
		result.AddError("password", "Password must contain at least one special character", "missing_special")
	}
	
	return result
}

// UUID validation
func ValidateUUID(id string) ValidationResult {
	result := ValidationResult{Valid: true}
	
	if id == "" {
		result.AddError("id", "ID is required", "required")
		return result
	}
	
	if _, err := uuid.Parse(id); err != nil {
		result.AddError("id", "Invalid ID format", "invalid_format")
	}
	
	return result
}

// Name validation (first name, last name, etc.)
func ValidateName(name, fieldName string) ValidationResult {
	result := ValidationResult{Valid: true}
	
	if name == "" {
		result.AddError(fieldName, fmt.Sprintf("%s is required", fieldName), "required")
		return result
	}
	
	if len(strings.TrimSpace(name)) < 2 {
		result.AddError(fieldName, fmt.Sprintf("%s must be at least 2 characters", fieldName), "min_length")
	}
	
	if len(name) > 50 {
		result.AddError(fieldName, fmt.Sprintf("%s must be no more than 50 characters", fieldName), "max_length")
	}
	
	// Check for valid characters (letters, spaces, hyphens, apostrophes)
	validName := regexp.MustCompile(`^[a-zA-ZÀ-ÿ\s'-]+$`)
	if !validName.MatchString(name) {
		result.AddError(fieldName, fmt.Sprintf("%s contains invalid characters", fieldName), "invalid_characters")
	}
	
	return result
}

// Phone number validation
func ValidatePhone(phone string) ValidationResult {
	result := ValidationResult{Valid: true}
	
	if phone == "" {
		result.AddError("phone", "Phone number is required", "required")
		return result
	}
	
	if !phoneRegex.MatchString(phone) {
		result.AddError("phone", "Invalid phone number format", "invalid_format")
	}
	
	return result
}

// Role validation
func ValidateRole(role string) ValidationResult {
	result := ValidationResult{Valid: true}
	
	validRoles := []string{
		"basic_user",
		"premium_user",
		"business_user",
		"vault_admin",
		"security_admin",
		"super_admin",
	}
	
	if role == "" {
		result.AddError("role", "Role is required", "required")
		return result
	}
	
	isValid := false
	for _, validRole := range validRoles {
		if role == validRole {
			isValid = true
			break
		}
	}
	
	if !isValid {
		result.AddError("role", "Invalid role", "invalid_value")
	}
	
	return result
}

// Status validation
func ValidateStatus(status string) ValidationResult {
	result := ValidationResult{Valid: true}
	
	validStatuses := []string{
		"active",
		"inactive",
		"suspended",
		"pending",
	}
	
	if status == "" {
		result.AddError("status", "Status is required", "required")
		return result
	}
	
	isValid := false
	for _, validStatus := range validStatuses {
		if status == validStatus {
			isValid = true
			break
		}
	}
	
	if !isValid {
		result.AddError("status", "Invalid status", "invalid_value")
	}
	
	return result
}

// Pagination validation
func ValidatePagination(page, limit int) ValidationResult {
	result := ValidationResult{Valid: true}
	
	if page < 1 {
		result.AddError("page", "Page must be at least 1", "invalid_value")
	}
	
	if limit < 1 {
		result.AddError("limit", "Limit must be at least 1", "invalid_value")
	}
	
	if limit > 1000 {
		result.AddError("limit", "Limit cannot exceed 1000", "invalid_value")
	}
	
	return result
}

// Generic required field validation
func ValidateRequired(value, fieldName string) ValidationResult {
	result := ValidationResult{Valid: true}
	
	if strings.TrimSpace(value) == "" {
		result.AddError(fieldName, fmt.Sprintf("%s is required", fieldName), "required")
	}
	
	return result
}

// String length validation
func ValidateLength(value, fieldName string, minLen, maxLen int) ValidationResult {
	result := ValidationResult{Valid: true}
	
	if len(value) < minLen {
		result.AddError(fieldName, fmt.Sprintf("%s must be at least %d characters", fieldName, minLen), "min_length")
	}
	
	if len(value) > maxLen {
		result.AddError(fieldName, fmt.Sprintf("%s must be no more than %d characters", fieldName, maxLen), "max_length")
	}
	
	return result
}

// Combine multiple validation results
func CombineValidations(results ...ValidationResult) ValidationResult {
	combined := ValidationResult{Valid: true}
	
	for _, result := range results {
		if !result.Valid {
			combined.Valid = false
			combined.Errors = append(combined.Errors, result.Errors...)
		}
	}
	
	return combined
}