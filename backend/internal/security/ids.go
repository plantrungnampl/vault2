package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
)

// ThreatLevel represents the severity of a detected threat
type ThreatLevel int

const (
	ThreatLevelLow ThreatLevel = iota
	ThreatLevelMedium
	ThreatLevelHigh
	ThreatLevelCritical
)

func (t ThreatLevel) String() string {
	switch t {
	case ThreatLevelLow:
		return "low"
	case ThreatLevelMedium:
		return "medium"
	case ThreatLevelHigh:
		return "high"
	case ThreatLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ThreatType represents different types of threats
type ThreatType string

const (
	ThreatTypeBruteForce        ThreatType = "brute_force"
	ThreatTypeRateLimitExceeded ThreatType = "rate_limit_exceeded"
	ThreatTypeSQLInjection      ThreatType = "sql_injection"
	ThreatTypeXSS               ThreatType = "xss_attempt"
	ThreatTypeAnomaly           ThreatType = "behavioral_anomaly"
	ThreatTypeGeoAnomaly        ThreatType = "geographical_anomaly"
	ThreatTypeDeviceAnomaly     ThreatType = "device_anomaly"
	ThreatTypePrivilegeEscalation ThreatType = "privilege_escalation"
	ThreatTypeDataExfiltration  ThreatType = "data_exfiltration"
	ThreatTypeSuspiciousAPI     ThreatType = "suspicious_api_usage"
)

// SecurityEvent represents a detected security event
type SecurityEvent struct {
	ID             string                 `json:"id" gorm:"primaryKey"`
	Type           ThreatType             `json:"type"`
	Level          ThreatLevel            `json:"level"`
	UserID         *string                `json:"user_id,omitempty"`
	IPAddress      string                 `json:"ip_address"`
	UserAgent      string                 `json:"user_agent"`
	RequestURI     string                 `json:"request_uri"`
	Method         string                 `json:"method"`
	Payload        map[string]interface{} `json:"payload" gorm:"type:jsonb"`
	RiskScore      int                    `json:"risk_score"`
	CountryCode    string                 `json:"country_code"`
	City           string                 `json:"city"`
	ISP            string                 `json:"isp"`
	Blocked        bool                   `json:"blocked"`
	Response       string                 `json:"response"`
	Fingerprint    string                 `json:"fingerprint"`
	Pattern        string                 `json:"pattern"`
	Confidence     float64                `json:"confidence"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// IPReputationData holds reputation information for an IP
type IPReputationData struct {
	IP           string    `json:"ip" gorm:"primaryKey"`
	ThreatScore  int       `json:"threat_score"`
	LastSeen     time.Time `json:"last_seen"`
	TotalEvents  int       `json:"total_events"`
	BlockedUntil *time.Time `json:"blocked_until,omitempty"`
	CountryCode  string    `json:"country_code"`
	ISP          string    `json:"isp"`
	Tags         []string  `json:"tags" gorm:"type:jsonb"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// UserBehaviorProfile stores behavioral patterns for users
type UserBehaviorProfile struct {
	UserID              string    `json:"user_id" gorm:"primaryKey"`
	TypicalLoginHours   []int     `json:"typical_login_hours" gorm:"type:jsonb"`
	TypicalCountries    []string  `json:"typical_countries" gorm:"type:jsonb"`
	TypicalDevices      []string  `json:"typical_devices" gorm:"type:jsonb"`
	TypicalIPs          []string  `json:"typical_ips" gorm:"type:jsonb"`
	AverageSessionTime  int       `json:"average_session_time"`
	TypicalAPIEndpoints []string  `json:"typical_api_endpoints" gorm:"type:jsonb"`
	RiskScore           int       `json:"risk_score"`
	LastUpdated         time.Time `json:"last_updated"`
	CreatedAt           time.Time `json:"created_at"`
}

// IDSConfig holds configuration for the IDS
type IDSConfig struct {
	BruteForceThreshold     int           `json:"brute_force_threshold"`
	RateLimitWindow         time.Duration `json:"rate_limit_window"`
	RateLimitMaxRequests    int           `json:"rate_limit_max_requests"`
	AnomalyThreshold        float64       `json:"anomaly_threshold"`
	AutoBlockEnabled        bool          `json:"auto_block_enabled"`
	BlockDuration           time.Duration `json:"block_duration"`
	WhitelistedIPs          []string      `json:"whitelisted_ips"`
	BlacklistedIPs          []string      `json:"blacklisted_ips"`
	MonitoringEnabled       bool          `json:"monitoring_enabled"`
	AlertingEnabled         bool          `json:"alerting_enabled"`
	GeoLocationEnabled      bool          `json:"geo_location_enabled"`
	BehavioralAnalysisEnabled bool        `json:"behavioral_analysis_enabled"`
}

// IntrusionDetectionService handles threat detection and prevention
type IntrusionDetectionService struct {
	db             *gorm.DB
	config         *IDSConfig
	ipTracker      map[string]*IPActivity
	userTracker    map[string]*UserActivity
	patterns       []ThreatPattern
	mutex          sync.RWMutex
	auditService   interface{}
	cryptoService  *CryptoService
}

// IPActivity tracks activity for an IP address
type IPActivity struct {
	IP               string
	RequestCount     int
	FailedAttempts   int
	LastActivity     time.Time
	FirstActivity    time.Time
	UniqueEndpoints  map[string]int
	UserAgents       map[string]int
	Methods          map[string]int
	SuspiciousScore  int
}

// UserActivity tracks activity for a user
type UserActivity struct {
	UserID           string
	LoginAttempts    int
	FailedLogins     int
	LastActivity     time.Time
	IPAddresses      map[string]int
	Countries        map[string]int
	Devices          map[string]int
	APICallCount     int
	SensitiveActions int
	RiskScore        int
}

// ThreatPattern defines patterns to detect threats
type ThreatPattern struct {
	Type        ThreatType
	Pattern     *regexp.Regexp
	Description string
	Level       ThreatLevel
	Score       int
	Field       string // which field to check (uri, payload, headers, etc.)
}

// NewIntrusionDetectionService creates a new IDS instance
func NewIntrusionDetectionService(db *gorm.DB, auditService interface{}, cryptoService *CryptoService) *IntrusionDetectionService {
	config := &IDSConfig{
		BruteForceThreshold:       5,
		RateLimitWindow:           time.Minute,
		RateLimitMaxRequests:      60,
		AnomalyThreshold:          0.8,
		AutoBlockEnabled:          true,
		BlockDuration:             time.Hour,
		MonitoringEnabled:         true,
		AlertingEnabled:           true,
		GeoLocationEnabled:        true,
		BehavioralAnalysisEnabled: true,
	}

	ids := &IntrusionDetectionService{
		db:            db,
		config:        config,
		ipTracker:     make(map[string]*IPActivity),
		userTracker:   make(map[string]*UserActivity),
		auditService:  auditService,
		cryptoService: cryptoService,
	}

	// Initialize threat patterns
	ids.initializeThreatPatterns()

	// Auto-migrate database tables
	db.AutoMigrate(&SecurityEvent{}, &IPReputationData{}, &UserBehaviorProfile{})

	// Start cleanup goroutine
	go ids.startCleanupWorker()

	return ids
}

// initializeThreatPatterns sets up detection patterns
func (ids *IntrusionDetectionService) initializeThreatPatterns() {
	ids.patterns = []ThreatPattern{
		// SQL Injection patterns
		{
			Type:        ThreatTypeSQLInjection,
			Pattern:     regexp.MustCompile(`(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|insert\s+into|delete\s+from|update\s+set|exec\s*\(|script\s*>)`),
			Description: "SQL Injection attempt detected",
			Level:       ThreatLevelHigh,
			Score:       80,
			Field:       "payload",
		},
		// XSS patterns
		{
			Type:        ThreatTypeXSS,
			Pattern:     regexp.MustCompile(`(?i)(<script|javascript:|on\w+\s*=|<iframe|<object|<embed|<link|<style)`),
			Description: "Cross-site scripting attempt detected",
			Level:       ThreatLevelMedium,
			Score:       60,
			Field:       "payload",
		},
		// Suspicious API usage
		{
			Type:        ThreatTypeSuspiciousAPI,
			Pattern:     regexp.MustCompile(`(?i)(admin|root|config|backup|dump|export|debug|test|dev)`),
			Description: "Suspicious API endpoint access",
			Level:       ThreatLevelMedium,
			Score:       50,
			Field:       "uri",
		},
		// Directory traversal
		{
			Type:        ThreatTypeAnomaly,
			Pattern:     regexp.MustCompile(`(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\)`),
			Description: "Directory traversal attempt",
			Level:       ThreatLevelHigh,
			Score:       75,
			Field:       "uri",
		},
	}
}

// AnalyzeRequest analyzes an incoming request for threats
func (ids *IntrusionDetectionService) AnalyzeRequest(ctx context.Context, req *SecurityAnalysisRequest) (*SecurityAnalysisResult, error) {
	ids.mutex.Lock()
	defer ids.mutex.Unlock()

	result := &SecurityAnalysisResult{
		RequestID:      req.RequestID,
		Blocked:        false,
		RiskScore:      0,
		Threats:        []DetectedThreat{},
		Recommendations: []string{},
	}

	// Skip analysis if monitoring is disabled
	if !ids.config.MonitoringEnabled {
		return result, nil
	}

	// Check IP reputation
	if threat := ids.checkIPReputation(req.IPAddress); threat != nil {
		result.Threats = append(result.Threats, *threat)
		result.RiskScore += threat.Score
	}

	// Check rate limiting
	if threat := ids.checkRateLimit(req); threat != nil {
		result.Threats = append(result.Threats, *threat)
		result.RiskScore += threat.Score
	}

	// Check brute force attempts
	if threat := ids.checkBruteForce(req); threat != nil {
		result.Threats = append(result.Threats, *threat)
		result.RiskScore += threat.Score
	}

	// Pattern matching for various attack types
	threats := ids.checkThreatPatterns(req)
	for _, threat := range threats {
		result.Threats = append(result.Threats, threat)
		result.RiskScore += threat.Score
	}

	// Behavioral analysis
	if ids.config.BehavioralAnalysisEnabled && req.UserID != "" {
		if threat := ids.checkBehavioralAnomaly(req); threat != nil {
			result.Threats = append(result.Threats, *threat)
			result.RiskScore += threat.Score
		}
	}

	// Geographical analysis
	if ids.config.GeoLocationEnabled {
		if threat := ids.checkGeographicalAnomaly(req); threat != nil {
			result.Threats = append(result.Threats, *threat)
			result.RiskScore += threat.Score
		}
	}

	// Device fingerprinting
	if threat := ids.checkDeviceAnomaly(req); threat != nil {
		result.Threats = append(result.Threats, *threat)
		result.RiskScore += threat.Score
	}

	// Determine if request should be blocked
	result.Blocked = ids.shouldBlockRequest(result.RiskScore, result.Threats)

	// Update tracking data
	ids.updateIPActivity(req)
	if req.UserID != "" {
		ids.updateUserActivity(req)
	}

	// Log security event if threats detected
	if len(result.Threats) > 0 {
		ids.logSecurityEvent(req, result)
	}

	// Generate recommendations
	result.Recommendations = ids.generateRecommendations(result)

	return result, nil
}

// checkIPReputation checks the reputation of an IP address
func (ids *IntrusionDetectionService) checkIPReputation(ip string) *DetectedThreat {
	// Check blacklisted IPs
	for _, blackIP := range ids.config.BlacklistedIPs {
		if ip == blackIP || ids.isIPInCIDR(ip, blackIP) {
			return &DetectedThreat{
				Type:        ThreatTypeAnomaly,
				Level:       ThreatLevelCritical,
				Description: "IP address is blacklisted",
				Score:       100,
				Pattern:     "blacklist_check",
				Confidence:  1.0,
			}
		}
	}

	// Check whitelisted IPs (skip further checks)
	for _, whiteIP := range ids.config.WhitelistedIPs {
		if ip == whiteIP || ids.isIPInCIDR(ip, whiteIP) {
			return nil
		}
	}

	// Check IP reputation database
	var reputation IPReputationData
	if err := ids.db.Where("ip = ?", ip).First(&reputation).Error; err == nil {
		if reputation.ThreatScore > 70 {
			return &DetectedThreat{
				Type:        ThreatTypeAnomaly,
				Level:       ThreatLevelHigh,
				Description: fmt.Sprintf("IP has high threat score: %d", reputation.ThreatScore),
				Score:       reputation.ThreatScore,
				Pattern:     "reputation_check",
				Confidence:  0.8,
			}
		}
	}

	return nil
}

// checkRateLimit checks if IP is making too many requests
func (ids *IntrusionDetectionService) checkRateLimit(req *SecurityAnalysisRequest) *DetectedThreat {
	activity, exists := ids.ipTracker[req.IPAddress]
	if !exists {
		return nil
	}

	// Check if rate limit exceeded
	if time.Since(activity.FirstActivity) <= ids.config.RateLimitWindow &&
		activity.RequestCount > ids.config.RateLimitMaxRequests {
		return &DetectedThreat{
			Type:        ThreatTypeRateLimitExceeded,
			Level:       ThreatLevelMedium,
			Description: fmt.Sprintf("Rate limit exceeded: %d requests in %v", activity.RequestCount, ids.config.RateLimitWindow),
			Score:       60,
			Pattern:     "rate_limit",
			Confidence:  0.9,
		}
	}

	return nil
}

// checkBruteForce detects brute force attacks
func (ids *IntrusionDetectionService) checkBruteForce(req *SecurityAnalysisRequest) *DetectedThreat {
	activity, exists := ids.ipTracker[req.IPAddress]
	if !exists {
		return nil
	}

	// Check for authentication endpoints with high failure rate
	if strings.Contains(req.URI, "/auth/") && activity.FailedAttempts >= ids.config.BruteForceThreshold {
		return &DetectedThreat{
			Type:        ThreatTypeBruteForce,
			Level:       ThreatLevelHigh,
			Description: fmt.Sprintf("Brute force attack detected: %d failed attempts", activity.FailedAttempts),
			Score:       80,
			Pattern:     "brute_force",
			Confidence:  0.9,
		}
	}

	return nil
}

// checkThreatPatterns checks request against known threat patterns
func (ids *IntrusionDetectionService) checkThreatPatterns(req *SecurityAnalysisRequest) []DetectedThreat {
	var threats []DetectedThreat

	for _, pattern := range ids.patterns {
		var text string
		switch pattern.Field {
		case "uri":
			text = req.URI
		case "payload":
			if req.Body != nil {
				if bodyBytes, err := json.Marshal(req.Body); err == nil {
					text = string(bodyBytes)
				}
			}
		case "headers":
			if headersBytes, err := json.Marshal(req.Headers); err == nil {
				text = string(headersBytes)
			}
		}

		if pattern.Pattern.MatchString(text) {
			threats = append(threats, DetectedThreat{
				Type:        pattern.Type,
				Level:       pattern.Level,
				Description: pattern.Description,
				Score:       pattern.Score,
				Pattern:     pattern.Pattern.String(),
				Confidence:  0.8,
			})
		}
	}

	return threats
}

// checkBehavioralAnomaly analyzes user behavior for anomalies
func (ids *IntrusionDetectionService) checkBehavioralAnomaly(req *SecurityAnalysisRequest) *DetectedThreat {
	var profile UserBehaviorProfile
	if err := ids.db.Where("user_id = ?", req.UserID).First(&profile).Error; err != nil {
		// No profile exists yet, create one
		return nil
	}

	anomalyScore := 0.0
	
	// Check login time pattern
	currentHour := time.Now().Hour()
	if !containsInt(profile.TypicalLoginHours, currentHour) {
		anomalyScore += 0.2
	}

	// Check geographical pattern
	if req.Country != "" && !contains(profile.TypicalCountries, req.Country) {
		anomalyScore += 0.3
	}

	// Check device pattern
	deviceFingerprint := generateDeviceFingerprint(req.UserAgent, req.Headers)
	if !contains(profile.TypicalDevices, deviceFingerprint) {
		anomalyScore += 0.25
	}

	// Check IP pattern
	if !contains(profile.TypicalIPs, req.IPAddress) {
		anomalyScore += 0.25
	}

	if anomalyScore >= ids.config.AnomalyThreshold {
		return &DetectedThreat{
			Type:        ThreatTypeAnomaly,
			Level:       ThreatLevelMedium,
			Description: fmt.Sprintf("Behavioral anomaly detected: %.2f confidence", anomalyScore),
			Score:       int(anomalyScore * 100),
			Pattern:     "behavioral_analysis",
			Confidence:  anomalyScore,
		}
	}

	return nil
}

// checkGeographicalAnomaly detects unusual geographical access
func (ids *IntrusionDetectionService) checkGeographicalAnomaly(req *SecurityAnalysisRequest) *DetectedThreat {
	// This would integrate with GeoIP service in production
	// For now, we'll do basic country code checking
	if req.Country != "" {
		// Check against known high-risk countries
		highRiskCountries := []string{"CN", "RU", "KP", "IR"}
		for _, country := range highRiskCountries {
			if req.Country == country {
				return &DetectedThreat{
					Type:        ThreatTypeGeoAnomaly,
					Level:       ThreatLevelMedium,
					Description: fmt.Sprintf("Access from high-risk country: %s", req.Country),
					Score:       50,
					Pattern:     "geo_analysis",
					Confidence:  0.6,
				}
			}
		}
	}

	return nil
}

// checkDeviceAnomaly detects unusual device characteristics
func (ids *IntrusionDetectionService) checkDeviceAnomaly(req *SecurityAnalysisRequest) *DetectedThreat {
	// Check for bot-like user agents
	botPatterns := []string{
		"bot", "crawler", "spider", "scraper", "wget", "curl",
		"python-requests", "java/", "go-http-client",
	}

	userAgent := strings.ToLower(req.UserAgent)
	for _, pattern := range botPatterns {
		if strings.Contains(userAgent, pattern) {
			return &DetectedThreat{
				Type:        ThreatTypeDeviceAnomaly,
				Level:       ThreatLevelLow,
				Description: fmt.Sprintf("Bot-like user agent detected: %s", pattern),
				Score:       30,
				Pattern:     "device_analysis",
				Confidence:  0.7,
			}
		}
	}

	return nil
}

// shouldBlockRequest determines if a request should be blocked
func (ids *IntrusionDetectionService) shouldBlockRequest(riskScore int, threats []DetectedThreat) bool {
	if !ids.config.AutoBlockEnabled {
		return false
	}

	// Block if risk score is too high
	if riskScore >= 80 {
		return true
	}

	// Block if any critical threats detected
	for _, threat := range threats {
		if threat.Level == ThreatLevelCritical {
			return true
		}
	}

	return false
}

// logSecurityEvent logs a security event to the database
func (ids *IntrusionDetectionService) logSecurityEvent(req *SecurityAnalysisRequest, result *SecurityAnalysisResult) {
	event := SecurityEvent{
		ID:          generateSecurityEventID(),
		Type:        ThreatTypeAnomaly, // Default, would be determined by main threat
		Level:       ThreatLevelLow,   // Default, would be determined by highest level
		IPAddress:   req.IPAddress,
		UserAgent:   req.UserAgent,
		RequestURI:  req.URI,
		Method:      req.Method,
		RiskScore:   result.RiskScore,
		CountryCode: req.Country,
		Blocked:     result.Blocked,
		Fingerprint: generateRequestFingerprint(req),
		Confidence:  0.8,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if req.UserID != "" {
		event.UserID = &req.UserID
	}

	// Set highest threat level and primary type
	for _, threat := range result.Threats {
		if threat.Level > event.Level {
			event.Level = threat.Level
			event.Type = threat.Type
		}
	}

	// Convert threats to payload
	event.Payload = map[string]interface{}{
		"threats":         result.Threats,
		"recommendations": result.Recommendations,
		"analysis_time":   time.Now().Unix(),
	}

	ids.db.Create(&event)

	// Update IP reputation
	ids.updateIPReputation(req.IPAddress, result.RiskScore)

	// Log to audit trail
	if ids.auditService != nil {
		// auditData := map[string]interface{}{
		// 	"security_event_id": event.ID,
		// 	"risk_score":        result.RiskScore,
		// 	"blocked":           result.Blocked,
		// 	"threats":           len(result.Threats),
		// }

		// var userID string
		// if req.UserID != "" {
		// 	userID = req.UserID
		// }

		// TODO: Integrate with audit service when interface is defined
		// ids.auditService.LogActivity(userID, "security_analysis", "request", "", req.IPAddress, req.UserAgent, true, "", auditData)
	}
}

// updateIPActivity updates tracking data for an IP address
func (ids *IntrusionDetectionService) updateIPActivity(req *SecurityAnalysisRequest) {
	activity, exists := ids.ipTracker[req.IPAddress]
	if !exists {
		activity = &IPActivity{
			IP:              req.IPAddress,
			FirstActivity:   time.Now(),
			UniqueEndpoints: make(map[string]int),
			UserAgents:      make(map[string]int),
			Methods:         make(map[string]int),
		}
		ids.ipTracker[req.IPAddress] = activity
	}

	activity.RequestCount++
	activity.LastActivity = time.Now()
	activity.UniqueEndpoints[req.URI]++
	activity.UserAgents[req.UserAgent]++
	activity.Methods[req.Method]++

	// Track failed authentication attempts
	if strings.Contains(req.URI, "/auth/") && req.StatusCode >= 400 {
		activity.FailedAttempts++
	}
}

// updateUserActivity updates tracking data for a user
func (ids *IntrusionDetectionService) updateUserActivity(req *SecurityAnalysisRequest) {
	activity, exists := ids.userTracker[req.UserID]
	if !exists {
		activity = &UserActivity{
			UserID:      req.UserID,
			IPAddresses: make(map[string]int),
			Countries:   make(map[string]int),
			Devices:     make(map[string]int),
		}
		ids.userTracker[req.UserID] = activity
	}

	activity.LastActivity = time.Now()
	activity.IPAddresses[req.IPAddress]++
	activity.APICallCount++

	if req.Country != "" {
		activity.Countries[req.Country]++
	}

	deviceFingerprint := generateDeviceFingerprint(req.UserAgent, req.Headers)
	activity.Devices[deviceFingerprint]++

	// Track sensitive actions
	sensitivePaths := []string{"/admin/", "/vault/", "/auth/", "/user/"}
	for _, path := range sensitivePaths {
		if strings.Contains(req.URI, path) {
			activity.SensitiveActions++
			break
		}
	}
}

// updateIPReputation updates the reputation score for an IP
func (ids *IntrusionDetectionService) updateIPReputation(ip string, riskScore int) {
	var reputation IPReputationData
	
	if err := ids.db.Where("ip = ?", ip).First(&reputation).Error; err != nil {
		// Create new reputation entry
		reputation = IPReputationData{
			IP:          ip,
			ThreatScore: riskScore,
			TotalEvents: 1,
			LastSeen:    time.Now(),
			CreatedAt:   time.Now(),
		}
	} else {
		// Update existing reputation
		reputation.ThreatScore = (reputation.ThreatScore + riskScore) / 2 // Moving average
		reputation.TotalEvents++
		reputation.LastSeen = time.Now()
		reputation.UpdatedAt = time.Now()
	}

	ids.db.Save(&reputation)
}

// generateRecommendations generates security recommendations based on threats
func (ids *IntrusionDetectionService) generateRecommendations(result *SecurityAnalysisResult) []string {
	var recommendations []string

	if result.RiskScore > 80 {
		recommendations = append(recommendations, "Khuyến nghị chặn IP này ngay lập tức")
	}

	for _, threat := range result.Threats {
		switch threat.Type {
		case ThreatTypeBruteForce:
			recommendations = append(recommendations, "Kích hoạt CAPTCHA cho endpoint đăng nhập")
			recommendations = append(recommendations, "Tăng cường yêu cầu MFA")
		case ThreatTypeSQLInjection:
			recommendations = append(recommendations, "Kiểm tra và củng cố input validation")
			recommendations = append(recommendations, "Sử dụng parameterized queries")
		case ThreatTypeXSS:
			recommendations = append(recommendations, "Tăng cường output encoding")
			recommendations = append(recommendations, "Implement Content Security Policy")
		case ThreatTypeRateLimitExceeded:
			recommendations = append(recommendations, "Tăng cường rate limiting")
			recommendations = append(recommendations, "Implement progressive delays")
		}
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Tiếp tục giám sát hoạt động")
	}

	return recommendations
}

// Helper functions
func generateSecurityEventID() string {
	return fmt.Sprintf("sec_%d_%s", time.Now().Unix(), generateRandomString(8))
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

func generateRequestFingerprint(req *SecurityAnalysisRequest) string {
	data := fmt.Sprintf("%s-%s-%s-%s", req.IPAddress, req.UserAgent, req.Method, req.URI)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

func generateDeviceFingerprint(userAgent string, headers map[string]string) string {
	data := fmt.Sprintf("%s-%s", userAgent, headers["Accept-Language"])
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

func (ids *IntrusionDetectionService) isIPInCIDR(ip, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ipAddr := net.ParseIP(ip)
	return network.Contains(ipAddr)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsInt(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// startCleanupWorker starts a goroutine to clean up old data
func (ids *IntrusionDetectionService) startCleanupWorker() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		ids.cleanupOldData()
	}
}

// cleanupOldData removes old tracking data and events
func (ids *IntrusionDetectionService) cleanupOldData() {
	ids.mutex.Lock()
	defer ids.mutex.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour)

	// Clean IP tracking data
	for ip, activity := range ids.ipTracker {
		if activity.LastActivity.Before(cutoff) {
			delete(ids.ipTracker, ip)
		}
	}

	// Clean user tracking data
	for userID, activity := range ids.userTracker {
		if activity.LastActivity.Before(cutoff) {
			delete(ids.userTracker, userID)
		}
	}

	// Clean old security events (keep for 30 days)
	eventCutoff := time.Now().Add(-30 * 24 * time.Hour)
	ids.db.Where("created_at < ?", eventCutoff).Delete(&SecurityEvent{})
}

// GetSecurityEvents retrieves security events with pagination
func (ids *IntrusionDetectionService) GetSecurityEvents(page, limit int, filters map[string]interface{}) ([]SecurityEvent, int64, error) {
	var events []SecurityEvent
	var total int64

	query := ids.db.Model(&SecurityEvent{})

	// Apply filters
	if level, ok := filters["level"]; ok {
		query = query.Where("level = ?", level)
	}
	if threatType, ok := filters["type"]; ok {
		query = query.Where("type = ?", threatType)
	}
	if blocked, ok := filters["blocked"]; ok {
		query = query.Where("blocked = ?", blocked)
	}
	if from, ok := filters["from"]; ok {
		query = query.Where("created_at >= ?", from)
	}
	if to, ok := filters["to"]; ok {
		query = query.Where("created_at <= ?", to)
	}

	query.Count(&total)

	offset := (page - 1) * limit
	err := query.Order("created_at DESC").Offset(offset).Limit(limit).Find(&events).Error

	return events, total, err
}

// BlockIP blocks an IP address for a specified duration
func (ids *IntrusionDetectionService) BlockIP(ip string, duration time.Duration, reason string) error {
	var reputation IPReputationData
	
	if err := ids.db.Where("ip = ?", ip).First(&reputation).Error; err != nil {
		reputation = IPReputationData{
			IP:        ip,
			CreatedAt: time.Now(),
		}
	}

	blockUntil := time.Now().Add(duration)
	reputation.BlockedUntil = &blockUntil
	reputation.ThreatScore = 100
	reputation.UpdatedAt = time.Now()
	
	if reputation.Tags == nil {
		reputation.Tags = []string{}
	}
	reputation.Tags = append(reputation.Tags, fmt.Sprintf("blocked:%s", reason))

	return ids.db.Save(&reputation).Error
}

// UnblockIP removes a block from an IP address
func (ids *IntrusionDetectionService) UnblockIP(ip string) error {
	return ids.db.Model(&IPReputationData{}).Where("ip = ?", ip).Updates(map[string]interface{}{
		"blocked_until": nil,
		"updated_at":    time.Now(),
	}).Error
}

// IsIPBlocked checks if an IP address is currently blocked
func (ids *IntrusionDetectionService) IsIPBlocked(ip string) (bool, error) {
	var reputation IPReputationData
	if err := ids.db.Where("ip = ?", ip).First(&reputation).Error; err != nil {
		return false, nil // IP not in database, not blocked
	}

	if reputation.BlockedUntil != nil && reputation.BlockedUntil.After(time.Now()) {
		return true, nil
	}

	return false, nil
}