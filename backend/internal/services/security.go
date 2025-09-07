package services

import (
	"encoding/json"
	"fmt"
	"time"

	"securevault/internal/database"
	"securevault/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type SecurityService struct {
	db *gorm.DB
}

type SecurityIncidentRequest struct {
	Type        models.SecurityEventType `json:"type" binding:"required"`
	Severity    models.SecuritySeverity  `json:"severity" binding:"required"`
	Title       string                   `json:"title" binding:"required"`
	Description string                   `json:"description"`
	UserID      *uuid.UUID               `json:"user_id,omitempty"`
	IPAddress   string                   `json:"ip_address" binding:"required"`
	Details     json.RawMessage          `json:"details,omitempty"`
}

type SecurityPolicy struct {
	ID       uuid.UUID `json:"id"`
	Name     string    `json:"name"`
	Category string    `json:"category"`
	Rules    string    `json:"rules"`
	Enabled  bool      `json:"enabled"`
}

func NewSecurityService() *SecurityService {
	return &SecurityService{
		db: database.GetDB(),
	}
}

// CreateSecurityIncident creates a new security incident
func (s *SecurityService) CreateSecurityIncident(req SecurityIncidentRequest) (*models.SecurityEvent, error) {
	var details models.SecurityEventDetails
	if len(req.Details) > 0 {
		if err := json.Unmarshal(req.Details, &details); err != nil {
			return nil, fmt.Errorf("invalid details format: %w", err)
		}
	}

	incident := &models.SecurityEvent{
		Type:      req.Type,
		Severity:  req.Severity,
		UserID:    req.UserID,
		IPAddress: req.IPAddress,
		Details:   details,
		Timestamp: time.Now(),
	}

	if err := s.db.Create(incident).Error; err != nil {
		return nil, fmt.Errorf("failed to create security incident: %w", err)
	}

	// Load related user if exists
	if incident.UserID != nil {
		s.db.Preload("User").First(incident, incident.ID)
	}

	return incident, nil
}

// GetSecurityIncidents retrieves security incidents with pagination
func (s *SecurityService) GetSecurityIncidents(page, limit int, filters map[string]interface{}) ([]*models.SecurityEvent, int64, error) {
	var incidents []*models.SecurityEvent
	var total int64

	query := s.db.Model(&models.SecurityEvent{}).Preload("User").Preload("Resolver")

	// Apply filters
	if severity, ok := filters["severity"].(string); ok && severity != "" {
		query = query.Where("severity = ?", severity)
	}

	if eventType, ok := filters["type"].(string); ok && eventType != "" {
		query = query.Where("type = ?", eventType)
	}

	if status, ok := filters["status"].(string); ok && status != "" {
		if status == "open" {
			query = query.Where("resolved = false")
		} else if status == "resolved" {
			query = query.Where("resolved = true")
		}
	}

	if userID, ok := filters["user_id"].(uuid.UUID); ok {
		query = query.Where("user_id = ?", userID)
	}

	// Get total count
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count incidents: %w", err)
	}

	// Get paginated results
	offset := (page - 1) * limit
	if err := query.Order("timestamp DESC").Offset(offset).Limit(limit).Find(&incidents).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to get incidents: %w", err)
	}

	return incidents, total, nil
}

// GetSecurityIncident retrieves a security incident by ID
func (s *SecurityService) GetSecurityIncident(id uuid.UUID) (*models.SecurityEvent, error) {
	var incident models.SecurityEvent
	if err := s.db.Preload("User").Preload("Resolver").First(&incident, id).Error; err != nil {
		return nil, fmt.Errorf("incident not found: %w", err)
	}
	return &incident, nil
}

// ResolveSecurityIncident marks an incident as resolved
func (s *SecurityService) ResolveSecurityIncident(id uuid.UUID, resolverID uuid.UUID) error {
	now := time.Now()
	updates := map[string]interface{}{
		"resolved":    true,
		"resolved_by": resolverID,
		"resolved_at": &now,
	}

	if err := s.db.Model(&models.SecurityEvent{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to resolve incident: %w", err)
	}

	return nil
}

// GetSecurityStats returns security statistics
func (s *SecurityService) GetSecurityStats() (map[string]interface{}, error) {
	var stats = make(map[string]interface{})

	// Total incidents
	var totalIncidents int64
	if err := s.db.Model(&models.SecurityEvent{}).Count(&totalIncidents).Error; err != nil {
		return nil, fmt.Errorf("failed to count total incidents: %w", err)
	}
	stats["total_incidents"] = totalIncidents

	// Open incidents
	var openIncidents int64
	if err := s.db.Model(&models.SecurityEvent{}).Where("resolved = false").Count(&openIncidents).Error; err != nil {
		return nil, fmt.Errorf("failed to count open incidents: %w", err)
	}
	stats["open_incidents"] = openIncidents

	// Critical incidents
	var criticalIncidents int64
	if err := s.db.Model(&models.SecurityEvent{}).Where("severity = ?", models.SeverityCritical).Count(&criticalIncidents).Error; err != nil {
		return nil, fmt.Errorf("failed to count critical incidents: %w", err)
	}
	stats["critical_incidents"] = criticalIncidents

	// Incidents by severity
	var severityStats []struct {
		Severity string `json:"severity"`
		Count    int64  `json:"count"`
	}
	if err := s.db.Model(&models.SecurityEvent{}).
		Select("severity, count(*) as count").
		Group("severity").
		Scan(&severityStats).Error; err != nil {
		return nil, fmt.Errorf("failed to get severity stats: %w", err)
	}
	stats["by_severity"] = severityStats

	// Recent incidents (last 7 days)
	sevenDaysAgo := time.Now().AddDate(0, 0, -7)
	var recentIncidents int64
	if err := s.db.Model(&models.SecurityEvent{}).
		Where("timestamp >= ?", sevenDaysAgo).
		Count(&recentIncidents).Error; err != nil {
		return nil, fmt.Errorf("failed to count recent incidents: %w", err)
	}
	stats["recent_incidents"] = recentIncidents

	return stats, nil
}

// GetSecurityPolicies retrieves all security policies
func (s *SecurityService) GetSecurityPolicies() ([]SecurityPolicy, error) {
	var policies []SecurityPolicy
	
	rows, err := s.db.Raw(`
		SELECT id, name, category, rules::text as rules, enabled 
		FROM security_policies 
		ORDER BY name
	`).Rows()
	if err != nil {
		return nil, fmt.Errorf("failed to get security policies: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var policy SecurityPolicy
		if err := rows.Scan(&policy.ID, &policy.Name, &policy.Category, &policy.Rules, &policy.Enabled); err != nil {
			return nil, fmt.Errorf("failed to scan policy: %w", err)
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

// UpdateSecurityPolicy updates a security policy
func (s *SecurityService) UpdateSecurityPolicy(id uuid.UUID, rules string, enabled bool) error {
	result := s.db.Raw("UPDATE security_policies SET rules = ?, enabled = ?, updated_at = ? WHERE id = ?",
		rules, enabled, time.Now(), id).Scan(&struct{}{})
	
	if result.Error != nil {
		return fmt.Errorf("failed to update security policy: %w", result.Error)
	}

	return nil
}

// CheckPasswordBreach checks if a password has been breached
func (s *SecurityService) CheckPasswordBreach(passwordHash string) (bool, error) {
	// This is a placeholder implementation
	// In production, you would integrate with services like HaveIBeenPwned
	// or maintain your own breach database
	
	breachedHashes := []string{
		// Common breached password hashes (SHA-1)
		"5e884898da28047151d0e56f8dc6292773603d0d", // "hello"
		"aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", // "hello"
		"7c4a8d09ca3762af61e59520943dc26494f8941b", // "123456"
	}

	for _, hash := range breachedHashes {
		if hash == passwordHash {
			return true, nil
		}
	}

	return false, nil
}

// GetPasswordStrength analyzes password strength
func (s *SecurityService) GetPasswordStrength(password string) map[string]interface{} {
	strength := map[string]interface{}{
		"score":       0,
		"feedback":    []string{},
		"suggestions": []string{},
	}

	score := 0
	var feedback []string
	var suggestions []string

	// Check length
	if len(password) < 8 {
		suggestions = append(suggestions, "Sử dụng ít nhất 8 ký tự")
	} else if len(password) >= 12 {
		score += 2
		feedback = append(feedback, "Độ dài tốt")
	} else {
		score += 1
	}

	// Check for uppercase
	hasUpper := false
	for _, char := range password {
		if char >= 'A' && char <= 'Z' {
			hasUpper = true
			break
		}
	}
	if hasUpper {
		score += 1
		feedback = append(feedback, "Có chữ hoa")
	} else {
		suggestions = append(suggestions, "Thêm chữ hoa")
	}

	// Check for lowercase
	hasLower := false
	for _, char := range password {
		if char >= 'a' && char <= 'z' {
			hasLower = true
			break
		}
	}
	if hasLower {
		score += 1
		feedback = append(feedback, "Có chữ thường")
	} else {
		suggestions = append(suggestions, "Thêm chữ thường")
	}

	// Check for numbers
	hasNumber := false
	for _, char := range password {
		if char >= '0' && char <= '9' {
			hasNumber = true
			break
		}
	}
	if hasNumber {
		score += 1
		feedback = append(feedback, "Có số")
	} else {
		suggestions = append(suggestions, "Thêm số")
	}

	// Check for special characters
	hasSpecial := false
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	for _, char := range password {
		for _, special := range specialChars {
			if char == special {
				hasSpecial = true
				break
			}
		}
		if hasSpecial {
			break
		}
	}
	if hasSpecial {
		score += 1
		feedback = append(feedback, "Có ký tự đặc biệt")
	} else {
		suggestions = append(suggestions, "Thêm ký tự đặc biệt (!@#$%^&*)")
	}

	// Calculate final score (0-4)
	if score > 4 {
		score = 4
	}

	strength["score"] = score
	strength["feedback"] = feedback
	strength["suggestions"] = suggestions

	return strength
}

// LogSecurityEvent logs a security event
func (s *SecurityService) LogSecurityEvent(eventType models.SecurityEventType, severity models.SecuritySeverity, userID *uuid.UUID, ipAddress string, details models.SecurityEventDetails) error {
	event := &models.SecurityEvent{
		Type:      eventType,
		Severity:  severity,
		UserID:    userID,
		IPAddress: ipAddress,
		Details:   details,
		Timestamp: time.Now(),
	}

	if err := s.db.Create(event).Error; err != nil {
		return fmt.Errorf("failed to log security event: %w", err)
	}

	return nil
}

// DetectAnomalousActivity detects potentially suspicious user activity
func (s *SecurityService) DetectAnomalousActivity(userID uuid.UUID, ipAddress string, userAgent string) (bool, error) {
	// Check for multiple failed login attempts
	var failedAttempts int64
	oneHourAgo := time.Now().Add(-1 * time.Hour)
	
	err := s.db.Model(&models.AuditLog{}).
		Where("user_id = ? AND action = ? AND success = false AND timestamp >= ?", 
			userID, "user_login", oneHourAgo).
		Count(&failedAttempts).Error
	
	if err != nil {
		return false, fmt.Errorf("failed to check failed attempts: %w", err)
	}

	if failedAttempts >= 5 {
		// Log security incident
		s.LogSecurityEvent(
			models.SecurityEventLoginFailure,
			models.SeverityHigh,
			&userID,
			ipAddress,
			models.SecurityEventDetails{
				AttemptsCount: int(failedAttempts),
				FailureReason: "multiple_failed_logins",
				AdditionalInfo: map[string]interface{}{
					"user_agent": userAgent,
					"time_window": "1_hour",
				},
			},
		)
		return true, nil
	}

	// Check for login from new location
	// This is a simplified check - in production you'd use geolocation services
	var previousLogins int64
	err = s.db.Model(&models.AuditLog{}).
		Where("user_id = ? AND action = ? AND ip_address = ? AND success = true", 
			userID, "user_login", ipAddress).
		Count(&previousLogins).Error
		
	if err != nil {
		return false, fmt.Errorf("failed to check previous logins: %w", err)
	}

	if previousLogins == 0 {
		// First time login from this IP
		s.LogSecurityEvent(
			models.SecurityEventSuspiciousActivity,
			models.SeverityMedium,
			&userID,
			ipAddress,
			models.SecurityEventDetails{
				FailureReason: "new_location_login",
				AdditionalInfo: map[string]interface{}{
					"user_agent": userAgent,
					"ip_address": ipAddress,
				},
			},
		)
		return true, nil
	}

	return false, nil
}