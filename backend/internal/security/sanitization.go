package security

import (
	"html"
	"regexp"
	"strings"
	"unicode"
)

// SQL injection patterns to detect and block
var sqlInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(union|select|insert|delete|update|drop|create|alter|exec|execute)`),
	regexp.MustCompile(`(?i)(script|javascript|vbscript|onload|onerror|onclick)`),
	regexp.MustCompile(`(?i)(<|>|&lt;|&gt;|%3c|%3e)`),
	regexp.MustCompile(`(?i)(--|#|/\*|\*/)`),
	regexp.MustCompile(`(?i)(\||&|\||\|\||&&)`),
}

// XSS patterns to detect and block
var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`),
	regexp.MustCompile(`(?i)<iframe[^>]*>.*?</iframe>`),
	regexp.MustCompile(`(?i)<object[^>]*>.*?</object>`),
	regexp.MustCompile(`(?i)<embed[^>]*>.*?</embed>`),
	regexp.MustCompile(`(?i)<form[^>]*>.*?</form>`),
	regexp.MustCompile(`(?i)javascript:`),
	regexp.MustCompile(`(?i)data:text/html`),
	regexp.MustCompile(`(?i)on\w+\s*=`),
}

// Path traversal patterns
var pathTraversalPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.\.\/`),
	regexp.MustCompile(`\.\.\\`),
	regexp.MustCompile(`%2e%2e%2f`),
	regexp.MustCompile(`%2e%2e%5c`),
	regexp.MustCompile(`\.\.%2f`),
	regexp.MustCompile(`\.\.%5c`),
}

// SanitizeInput performs comprehensive input sanitization
func SanitizeInput(input string) string {
	if input == "" {
		return input
	}

	// Remove control characters except tab, newline, and carriage return
	sanitized := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, input)

	// HTML escape
	sanitized = html.EscapeString(sanitized)

	// Trim whitespace
	sanitized = strings.TrimSpace(sanitized)

	return sanitized
}

// SanitizeHTML removes potentially dangerous HTML tags and attributes
func SanitizeHTML(input string) string {
	// Simple HTML sanitization - remove all tags
	re := regexp.MustCompile(`<[^>]*>`)
	sanitized := re.ReplaceAllString(input, "")
	
	// HTML decode entities
	sanitized = html.UnescapeString(sanitized)
	
	// Re-escape for safety
	sanitized = html.EscapeString(sanitized)
	
	return sanitized
}

// ValidateNoSQLInjection checks for SQL injection patterns
func ValidateNoSQLInjection(input string) bool {
	lowercaseInput := strings.ToLower(input)
	
	for _, pattern := range sqlInjectionPatterns {
		if pattern.MatchString(lowercaseInput) {
			return false
		}
	}
	
	return true
}

// ValidateNoXSS checks for XSS patterns
func ValidateNoXSS(input string) bool {
	lowercaseInput := strings.ToLower(input)
	
	for _, pattern := range xssPatterns {
		if pattern.MatchString(lowercaseInput) {
			return false
		}
	}
	
	return true
}

// ValidateNoPathTraversal checks for path traversal patterns
func ValidateNoPathTraversal(input string) bool {
	lowercaseInput := strings.ToLower(input)
	
	for _, pattern := range pathTraversalPatterns {
		if pattern.MatchString(lowercaseInput) {
			return false
		}
	}
	
	return true
}

// ValidateContentLength ensures content is within acceptable limits
func ValidateContentLength(content string, maxLength int) bool {
	return len(content) <= maxLength
}

// SanitizeFilename removes dangerous characters from filenames
func SanitizeFilename(filename string) string {
	// Remove path separators and other dangerous characters
	dangerous := regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)
	sanitized := dangerous.ReplaceAllString(filename, "_")
	
	// Remove leading/trailing dots and spaces
	sanitized = strings.Trim(sanitized, ". ")
	
	// Ensure filename is not empty
	if sanitized == "" {
		sanitized = "unnamed_file"
	}
	
	// Limit length
	if len(sanitized) > 255 {
		sanitized = sanitized[:255]
	}
	
	return sanitized
}

// ValidateSecurityHeaders checks for required security headers
func ValidateSecurityHeaders(headers map[string]string) []string {
	var missing []string
	
	requiredHeaders := map[string]string{
		"Content-Type":           "",
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "1; mode=block",
	}
	
	for header, expectedValue := range requiredHeaders {
		if value, exists := headers[header]; !exists {
			missing = append(missing, header)
		} else if expectedValue != "" && value != expectedValue {
			missing = append(missing, header+" (incorrect value)")
		}
	}
	
	return missing
}

// SanitizeEmailAddress performs email-specific sanitization
func SanitizeEmailAddress(email string) string {
	// Basic email sanitization
	email = strings.ToLower(strings.TrimSpace(email))
	
	// Remove potentially dangerous characters
	dangerous := regexp.MustCompile(`[<>'"\\]`)
	email = dangerous.ReplaceAllString(email, "")
	
	return email
}

// ValidatePasswordComplexity checks password against security requirements
func ValidatePasswordComplexity(password string) map[string]bool {
	checks := map[string]bool{
		"min_length":    len(password) >= 14,
		"has_upper":     regexp.MustCompile(`[A-Z]`).MatchString(password),
		"has_lower":     regexp.MustCompile(`[a-z]`).MatchString(password),
		"has_number":    regexp.MustCompile(`\d`).MatchString(password),
		"has_special":   regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password),
		"no_common":     !isCommonPassword(password),
		"no_sequential": !hasSequentialCharacters(password),
		"no_repeated":   !hasRepeatedCharacters(password),
	}
	
	return checks
}

// isCommonPassword checks against common password list
func isCommonPassword(password string) bool {
	commonPasswords := []string{
		"password", "123456", "password123", "admin", "qwerty",
		"letmein", "welcome", "monkey", "dragon", "pass",
	}
	
	lowercasePassword := strings.ToLower(password)
	for _, common := range commonPasswords {
		if strings.Contains(lowercasePassword, common) {
			return true
		}
	}
	
	return false
}

// hasSequentialCharacters checks for sequential characters
func hasSequentialCharacters(password string) bool {
	sequences := []string{
		"123456", "abcdef", "qwerty", "asdfgh", "zxcvbn",
		"098765", "fedcba", "ytrewq", "hgfdsa", "nbvcxz",
	}
	
	lowercasePassword := strings.ToLower(password)
	for _, seq := range sequences {
		if strings.Contains(lowercasePassword, seq) {
			return true
		}
	}
	
	return false
}

// hasRepeatedCharacters checks for too many repeated characters
func hasRepeatedCharacters(password string) bool {
	charCount := make(map[rune]int)
	
	for _, char := range password {
		charCount[char]++
		// If any character appears more than 3 times, consider it weak
		if charCount[char] > 3 {
			return true
		}
	}
	
	return false
}