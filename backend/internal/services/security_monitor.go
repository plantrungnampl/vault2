package services

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"securevault/internal/config"
	"securevault/internal/database"
	"securevault/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Real-time Security Monitoring Service
type SecurityMonitorService struct {
	db              *gorm.DB
	config          *config.Config
	auditSvc        *AuditService
	alertChannels   map[string]chan SecurityAlert
	ruleEngine      *SecurityRuleEngine
	threatDB        *ThreatIntelligenceDB
	behaviorTracker *BehaviorTracker
	geoLocator      *GeoLocationService
	mutex           sync.RWMutex
	running         bool
	stopChan        chan struct{}
}

// Security Alert Types
type SecurityAlert struct {
	ID             uuid.UUID               `json:"id"`
	Type           SecurityAlertType       `json:"type"`
	Severity       models.SecuritySeverity `json:"severity"`
	UserID         *uuid.UUID              `json:"user_id,omitempty"`
	IPAddress      string                  `json:"ip_address"`
	UserAgent      string                  `json:"user_agent"`
	Description    string                  `json:"description"`
	Details        map[string]interface{}  `json:"details"`
	GeoLocation    *GeoLocation            `json:"geo_location,omitempty"`
	ThreatScore    float64                 `json:"threat_score"`
	Timestamp      time.Time               `json:"timestamp"`
	Acknowledged   bool                    `json:"acknowledged"`
	AcknowledgedBy *uuid.UUID              `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time              `json:"acknowledged_at,omitempty"`
	Actions        []string                `json:"actions"`
	Metadata       map[string]interface{}  `json:"metadata"`
}

type SecurityAlertType string

const (
	AlertTypeBruteForce          SecurityAlertType = "brute_force"
	AlertTypeAnomalousLogin      SecurityAlertType = "anomalous_login"
	AlertTypeGeoAnomaly          SecurityAlertType = "geo_anomaly"
	AlertTypeRateLimitExceed     SecurityAlertType = "rate_limit_exceed"
	AlertTypePasswordBreach      SecurityAlertType = "password_breach"
	AlertTypeDataExfiltration    SecurityAlertType = "data_exfiltration"
	AlertTypePrivilegeEscalation SecurityAlertType = "privilege_escalation"
	AlertTypeUnauthorizedAPI     SecurityAlertType = "unauthorized_api"
	AlertTypeMaliciousPayload    SecurityAlertType = "malicious_payload"
	AlertTypeDeviceAnomaly       SecurityAlertType = "device_anomaly"
	AlertTypeTOTPBruteForce      SecurityAlertType = "totp_brute_force"
	AlertTypeAccountEnumeration  SecurityAlertType = "account_enumeration"
)

// Geo Location Information
type GeoLocation struct {
	Country     string  `json:"country"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	Timezone    string  `json:"timezone"`
	IsTorExit   bool    `json:"is_tor_exit"`
	IsVPN       bool    `json:"is_vpn"`
	IsProxy     bool    `json:"is_proxy"`
	ThreatLevel string  `json:"threat_level"` // low, medium, high, critical
}

// Security Rule Engine
type SecurityRuleEngine struct {
	rules       []SecurityRule
	ruleCache   map[string]*SecurityRule
	evaluations map[string]*RuleEvaluation
	mutex       sync.RWMutex
}

type SecurityRule struct {
	ID         uuid.UUID               `json:"id"`
	Name       string                  `json:"name"`
	Type       SecurityAlertType       `json:"type"`
	Severity   models.SecuritySeverity `json:"severity"`
	Conditions []RuleCondition         `json:"conditions"`
	Actions    []RuleAction            `json:"actions"`
	Enabled    bool                    `json:"enabled"`
	Threshold  int                     `json:"threshold"`
	TimeWindow time.Duration           `json:"time_window"`
	Cooldown   time.Duration           `json:"cooldown"`
	CreatedAt  time.Time               `json:"created_at"`
	UpdatedAt  time.Time               `json:"updated_at"`
}

type RuleCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // eq, ne, gt, lt, contains, regex, in
	Value    interface{} `json:"value"`
	Logic    string      `json:"logic,omitempty"` // and, or
}

type RuleAction struct {
	Type       string                 `json:"type"` // alert, block, notify, quarantine
	Parameters map[string]interface{} `json:"parameters"`
}

type RuleEvaluation struct {
	RuleID        uuid.UUID `json:"rule_id"`
	Count         int       `json:"count"`
	LastTriggered time.Time `json:"last_triggered"`
	WindowStart   time.Time `json:"window_start"`
}

// Behavior Tracking
type BehaviorTracker struct {
	userBehaviors map[uuid.UUID]*UserBehaviorProfile
	ipBehaviors   map[string]*IPBehaviorProfile
	mutex         sync.RWMutex
}

type UserBehaviorProfile struct {
	UserID              uuid.UUID     `json:"user_id"`
	LoginPatterns       LoginPattern  `json:"login_patterns"`
	GeoPatterns         []GeoLocation `json:"geo_patterns"`
	DeviceFingerprints  []string      `json:"device_fingerprints"`
	AccessPatterns      AccessPattern `json:"access_patterns"`
	RiskScore           float64       `json:"risk_score"`
	LastUpdate          time.Time     `json:"last_update"`
	BaselineEstablished bool          `json:"baseline_established"`
}

type LoginPattern struct {
	TypicalHours     []int       `json:"typical_hours"`
	TypicalDays      []int       `json:"typical_days"`
	AverageFrequency float64     `json:"average_frequency"`
	LastLoginTimes   []time.Time `json:"last_login_times"`
}

type AccessPattern struct {
	CommonEndpoints  []string `json:"common_endpoints"`
	RequestVolume    float64  `json:"request_volume"`
	TypicalUserAgent string   `json:"typical_user_agent"`
}

type IPBehaviorProfile struct {
	IPAddress       string         `json:"ip_address"`
	GeoLocation     *GeoLocation   `json:"geo_location"`
	UserAgents      []string       `json:"user_agents"`
	RequestPatterns RequestPattern `json:"request_patterns"`
	ThreatScore     float64        `json:"threat_score"`
	FirstSeen       time.Time      `json:"first_seen"`
	LastSeen        time.Time      `json:"last_seen"`
	TotalRequests   int64          `json:"total_requests"`
	FailedRequests  int64          `json:"failed_requests"`
	IsKnownThreat   bool           `json:"is_known_threat"`
}

type RequestPattern struct {
	AverageRPM   float64        `json:"average_rpm"`
	PeakRPM      float64        `json:"peak_rpm"`
	RequestTypes map[string]int `json:"request_types"`
	ErrorRate    float64        `json:"error_rate"`
}

// Threat Intelligence Database
type ThreatIntelligenceDB struct {
	maliciousIPs        map[string]*ThreatInfo
	maliciousDomains    map[string]*ThreatInfo
	knownAttackPatterns []AttackPattern
	breachedPasswords   map[string]bool
	mutex               sync.RWMutex
	lastUpdate          time.Time
	updateChan          chan struct{}
}

type ThreatInfo struct {
	Source      string    `json:"source"`
	ThreatType  string    `json:"threat_type"`
	Confidence  float64   `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Description string    `json:"description"`
}

type AttackPattern struct {
	Name        string                  `json:"name"`
	Pattern     *regexp.Regexp          `json:"pattern"`
	ThreatType  string                  `json:"threat_type"`
	Severity    models.SecuritySeverity `json:"severity"`
	Description string                  `json:"description"`
}

// GeoLocation Service for IP analysis
type GeoLocationService struct {
	cache     map[string]*GeoLocation
	mutex     sync.RWMutex
	client    *http.Client
	apiKey    string
	rateLimit *time.Ticker
}

func NewSecurityMonitorService(cfg *config.Config, auditSvc *AuditService) *SecurityMonitorService {
	sms := &SecurityMonitorService{
		db:            database.GetDB(),
		config:        cfg,
		auditSvc:      auditSvc,
		alertChannels: make(map[string]chan SecurityAlert),
		stopChan:      make(chan struct{}),
	}

	// Initialize sub-services
	sms.ruleEngine = NewSecurityRuleEngine()
	sms.threatDB = NewThreatIntelligenceDB()
	sms.behaviorTracker = NewBehaviorTracker()
	sms.geoLocator = NewGeoLocationService(cfg.Security.GeoAPIKey)

	// Load default security rules
	sms.loadDefaultSecurityRules()

	// Start background processes
	go sms.runThreatIntelligenceUpdater()
	go sms.runBehaviorAnalyzer()
	go sms.runAlertProcessor()

	return sms
}

func (sms *SecurityMonitorService) Start() {
	sms.mutex.Lock()
	defer sms.mutex.Unlock()

	if sms.running {
		return
	}

	sms.running = true
	go sms.monitoringLoop()
}

func (sms *SecurityMonitorService) Stop() {
	sms.mutex.Lock()
	defer sms.mutex.Unlock()

	if !sms.running {
		return
	}

	sms.running = false
	close(sms.stopChan)
}

// Real-time Event Analysis
func (sms *SecurityMonitorService) AnalyzeSecurityEvent(event *SecurityEvent) []SecurityAlert {
	var alerts []SecurityAlert

	// Update behavior profiles
	sms.updateBehaviorProfiles(event)

	// Evaluate security rules
	triggeredRules := sms.ruleEngine.EvaluateEvent(event)
	for _, rule := range triggeredRules {
		alert := sms.createAlertFromRule(rule, event)
		alerts = append(alerts, alert)
	}

	// Check threat intelligence
	if threatInfo := sms.threatDB.CheckThreat(event.IPAddress); threatInfo != nil {
		alert := sms.createThreatAlert(event, threatInfo)
		alerts = append(alerts, alert)
	}

	// Analyze behavioral anomalies
	if anomalyScore := sms.analyzeBehavioralAnomaly(event); anomalyScore > 0.7 {
		alert := sms.createAnomalyAlert(event, anomalyScore)
		alerts = append(alerts, alert)
	}

	// Process and store alerts
	for _, alert := range alerts {
		sms.processAlert(alert)
	}

	return alerts
}

type SecurityEvent struct {
	Type      string                 `json:"type"`
	UserID    *uuid.UUID             `json:"user_id,omitempty"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Endpoint  string                 `json:"endpoint"`
	Method    string                 `json:"method"`
	Success   bool                   `json:"success"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details"`
}

// Core Detection Methods

func (sms *SecurityMonitorService) DetectBruteForce(userID *uuid.UUID, ipAddress string, timeWindow time.Duration) *SecurityAlert {
	var count int64
	query := sms.db.Model(&models.AuditLog{}).
		Where("action = ? AND success = false AND timestamp > ?", "login", time.Now().Add(-timeWindow))

	if userID != nil {
		query = query.Where("user_id = ?", *userID)
	} else {
		query = query.Where("ip_address = ?", ipAddress)
	}

	query.Count(&count)

	// Threshold: 5 failed attempts in 15 minutes
	if count >= 5 {
		return &SecurityAlert{
			ID:          uuid.New(),
			Type:        AlertTypeBruteForce,
			Severity:    models.SeverityHigh,
			UserID:      userID,
			IPAddress:   ipAddress,
			Description: fmt.Sprintf("Brute force attack detected: %d failed login attempts", count),
			Details: map[string]interface{}{
				"attempt_count": count,
				"time_window":   timeWindow.String(),
				"attack_type":   "credential_stuffing",
			},
			ThreatScore: math.Min(float64(count)/10.0, 1.0),
			Timestamp:   time.Now(),
			Actions:     []string{"block_ip", "notify_admin", "require_mfa"},
		}
	}

	return nil
}

func (sms *SecurityMonitorService) DetectGeoAnomaly(userID uuid.UUID, currentIP string) *SecurityAlert {
	// Get user's recent geo locations
	var recentLogins []models.AuditLog
	sms.db.Where("user_id = ? AND action = ? AND success = true AND timestamp > ?",
		userID, "login", time.Now().AddDate(0, 0, -30)).
		Order("timestamp DESC").Limit(10).Find(&recentLogins)

	if len(recentLogins) < 3 {
		return nil // Not enough data for baseline
	}

	currentGeo := sms.geoLocator.GetLocation(currentIP)
	if currentGeo == nil {
		return nil
	}

	// Calculate distance from typical locations
	var avgDistance float64
	for _, login := range recentLogins {
		if geo := sms.geoLocator.GetLocation(login.IPAddress); geo != nil {
			distance := sms.calculateDistance(currentGeo, geo)
			avgDistance += distance
		}
	}
	avgDistance /= float64(len(recentLogins))

	// If current location is significantly far from usual locations
	if avgDistance > 1000 { // 1000km threshold
		severity := models.SeverityMedium
		if avgDistance > 5000 {
			severity = models.SeverityHigh
		}

		return &SecurityAlert{
			ID:          uuid.New(),
			Type:        AlertTypeGeoAnomaly,
			Severity:    severity,
			UserID:      &userID,
			IPAddress:   currentIP,
			Description: fmt.Sprintf("Unusual login location detected: %.0fkm from typical locations", avgDistance),
			GeoLocation: currentGeo,
			Details: map[string]interface{}{
				"distance_km":       avgDistance,
				"typical_locations": len(recentLogins),
				"current_country":   currentGeo.Country,
				"current_city":      currentGeo.City,
			},
			ThreatScore: math.Min(avgDistance/10000.0, 1.0),
			Timestamp:   time.Now(),
			Actions:     []string{"require_additional_mfa", "notify_user", "log_detailed"},
		}
	}

	return nil
}

func (sms *SecurityMonitorService) DetectRateLimitViolation(ipAddress string, endpoint string, timeWindow time.Duration) *SecurityAlert {
	var count int64
	sms.db.Model(&models.AuditLog{}).
		Where("ip_address = ? AND resource LIKE ? AND timestamp > ?",
			ipAddress, "%"+endpoint+"%", time.Now().Add(-timeWindow)).
		Count(&count)

	// Different thresholds for different endpoints
	var threshold int64
	switch {
	case strings.Contains(endpoint, "/auth/"):
		threshold = 20 // 20 auth requests per minute
	case strings.Contains(endpoint, "/vault/"):
		threshold = 100 // 100 vault requests per minute
	default:
		threshold = 60 // 60 general requests per minute
	}

	if count > threshold {
		severity := models.SeverityMedium
		if count > threshold*2 {
			severity = models.SeverityHigh
		}

		return &SecurityAlert{
			ID:          uuid.New(),
			Type:        AlertTypeRateLimitExceed,
			Severity:    severity,
			IPAddress:   ipAddress,
			Description: fmt.Sprintf("Rate limit exceeded: %d requests to %s in %v", count, endpoint, timeWindow),
			Details: map[string]interface{}{
				"request_count": count,
				"threshold":     threshold,
				"endpoint":      endpoint,
				"time_window":   timeWindow.String(),
			},
			ThreatScore: float64(count) / float64(threshold),
			Timestamp:   time.Now(),
			Actions:     []string{"rate_limit", "temporary_block", "captcha_challenge"},
		}
	}

	return nil
}

func (sms *SecurityMonitorService) DetectMaliciousPayload(request *http.Request, body string) *SecurityAlert {
	// Check for common attack patterns
	maliciousPatterns := []AttackPattern{
		{
			Name:        "SQL Injection",
			Pattern:     regexp.MustCompile(`(?i)(union\s+select|drop\s+table|insert\s+into|update\s+set|delete\s+from|exec\s*\(|script\s*>)`),
			ThreatType:  "sqli",
			Severity:    models.SeverityHigh,
			Description: "SQL injection attempt detected",
		},
		{
			Name:        "XSS Attack",
			Pattern:     regexp.MustCompile(`(?i)(<script|javascript:|vbscript:|onload\s*=|onerror\s*=|onclick\s*=)`),
			ThreatType:  "xss",
			Severity:    models.SeverityHigh,
			Description: "Cross-site scripting attempt detected",
		},
		{
			Name:        "Command Injection",
			Pattern:     regexp.MustCompile(`(?i)(&&\s*|;\s*|\\\\|\\\\|\s*|\$\(|\` + "`" + `|nc\s+|wget\s+|curl\s+)`),
			ThreatType:  "command_injection",
			Severity:    models.SeverityCritical,
			Description: "Command injection attempt detected",
		},
		{
			Name:        "Path Traversal",
			Pattern:     regexp.MustCompile(`(\.\.\/|\.\.\\|\%2e\%2e\%2f|\%2e\%2e\%5c)`),
			ThreatType:  "path_traversal",
			Severity:    models.SeverityMedium,
			Description: "Path traversal attempt detected",
		},
	}

	// Check user agent for suspicious patterns
	userAgent := request.Header.Get("User-Agent")
	suspiciousUA := regexp.MustCompile(`(?i)(sqlmap|nmap|nikto|burp|owasp|acunetix|netsparker)`).MatchString(userAgent)

	// Analyze request content
	combinedContent := fmt.Sprintf("%s %s %s", request.URL.String(), userAgent, body)

	for _, pattern := range maliciousPatterns {
		if pattern.Pattern.MatchString(combinedContent) {
			threatScore := 0.8
			if suspiciousUA {
				threatScore = 1.0
			}

			return &SecurityAlert{
				ID:          uuid.New(),
				Type:        AlertTypeMaliciousPayload,
				Severity:    pattern.Severity,
				IPAddress:   sms.getClientIP(request),
				UserAgent:   userAgent,
				Description: pattern.Description,
				Details: map[string]interface{}{
					"attack_type":     pattern.ThreatType,
					"matched_pattern": pattern.Name,
					"endpoint":        request.URL.Path,
					"method":          request.Method,
					"suspicious_ua":   suspiciousUA,
					"payload_sample":  sms.sanitizeForLogging(combinedContent),
				},
				ThreatScore: threatScore,
				Timestamp:   time.Now(),
				Actions:     []string{"block_request", "block_ip_temporary", "alert_security_team"},
			}
		}
	}

	return nil
}

// Helper Methods

func (sms *SecurityMonitorService) updateBehaviorProfiles(event *SecurityEvent) {
	sms.behaviorTracker.mutex.Lock()
	defer sms.behaviorTracker.mutex.Unlock()

	// Update IP behavior profile
	if ipProfile, exists := sms.behaviorTracker.ipBehaviors[event.IPAddress]; exists {
		ipProfile.LastSeen = event.Timestamp
		ipProfile.TotalRequests++
		if !event.Success {
			ipProfile.FailedRequests++
		}
		// Update user agents
		found := false
		for _, ua := range ipProfile.UserAgents {
			if ua == event.UserAgent {
				found = true
				break
			}
		}
		if !found {
			ipProfile.UserAgents = append(ipProfile.UserAgents, event.UserAgent)
		}
	} else {
		geoLoc := sms.geoLocator.GetLocation(event.IPAddress)
		sms.behaviorTracker.ipBehaviors[event.IPAddress] = &IPBehaviorProfile{
			IPAddress:     event.IPAddress,
			GeoLocation:   geoLoc,
			UserAgents:    []string{event.UserAgent},
			FirstSeen:     event.Timestamp,
			LastSeen:      event.Timestamp,
			TotalRequests: 1,
		}
	}

	// Update user behavior profile if user is identified
	if event.UserID != nil {
		if userProfile, exists := sms.behaviorTracker.userBehaviors[*event.UserID]; exists {
			userProfile.LastUpdate = event.Timestamp
			// Update login patterns, access patterns, etc.
		} else {
			sms.behaviorTracker.userBehaviors[*event.UserID] = &UserBehaviorProfile{
				UserID:     *event.UserID,
				LastUpdate: event.Timestamp,
			}
		}
	}
}

func (sms *SecurityMonitorService) analyzeBehavioralAnomaly(event *SecurityEvent) float64 {
	if event.UserID == nil {
		return 0
	}

	sms.behaviorTracker.mutex.RLock()
	defer sms.behaviorTracker.mutex.RUnlock()

	profile, exists := sms.behaviorTracker.userBehaviors[*event.UserID]
	if !exists || !profile.BaselineEstablished {
		return 0 // No baseline to compare against
	}

	anomalyScore := 0.0

	// Analyze time-based patterns
	currentHour := event.Timestamp.Hour()
	currentDay := int(event.Timestamp.Weekday())

	// Check if current hour is typical
	hourScore := 1.0
	for _, hour := range profile.LoginPatterns.TypicalHours {
		if hour == currentHour {
			hourScore = 0.0
			break
		}
	}
	anomalyScore += hourScore * 0.3

	// Check if current day is typical
	dayScore := 1.0
	for _, day := range profile.LoginPatterns.TypicalDays {
		if day == currentDay {
			dayScore = 0.0
			break
		}
	}
	anomalyScore += dayScore * 0.2

	// Analyze geographical patterns
	if len(profile.GeoPatterns) > 0 {
		currentGeo := sms.geoLocator.GetLocation(event.IPAddress)
		if currentGeo != nil {
			minDistance := math.Inf(1)
			for _, geo := range profile.GeoPatterns {
				distance := sms.calculateDistance(currentGeo, &geo)
				if distance < minDistance {
					minDistance = distance
				}
			}
			// Normalize distance to 0-1 scale (1000km = 1.0)
			geoScore := math.Min(minDistance/1000.0, 1.0)
			anomalyScore += geoScore * 0.4
		}
	}

	// Check device fingerprinting
	deviceScore := 1.0
	deviceFingerprint := sms.generateDeviceFingerprint(event.UserAgent)
	for _, fp := range profile.DeviceFingerprints {
		if fp == deviceFingerprint {
			deviceScore = 0.0
			break
		}
	}
	anomalyScore += deviceScore * 0.1

	return math.Min(anomalyScore, 1.0)
}

func (sms *SecurityMonitorService) processAlert(alert SecurityAlert) {
	// Store alert in database
	alertJSON, _ := json.Marshal(alert)
	securityEvent := models.SecurityEvent{
		Type:      models.SecurityEventType(alert.Type),
		Severity:  alert.Severity,
		IPAddress: alert.IPAddress,
		Details: models.SecurityEventDetails{
			AdditionalInfo: map[string]interface{}{
				"alert_data": string(alertJSON),
			},
		},
		Timestamp: alert.Timestamp,
	}

	if alert.UserID != nil {
		securityEvent.UserID = alert.UserID
	}

	sms.db.Create(&securityEvent)

	// Send to alert channels
	for _, channel := range sms.alertChannels {
		select {
		case channel <- alert:
		case <-time.After(time.Second):
			// Channel full, skip
		}
	}

	// Execute alert actions
	sms.executeAlertActions(alert)

	// Log to audit service
	sms.auditSvc.LogSecurityEvent(alert.UserID, models.SecurityEventType(alert.Type), alert.Severity, alert.IPAddress, map[string]interface{}{
		"alert_id":     alert.ID,
		"threat_score": alert.ThreatScore,
		"actions":      alert.Actions,
	})
}

func (sms *SecurityMonitorService) executeAlertActions(alert SecurityAlert) {
	for _, action := range alert.Actions {
		switch action {
		case "block_ip":
			sms.blockIP(alert.IPAddress, 24*time.Hour)
		case "block_ip_temporary":
			sms.blockIP(alert.IPAddress, 1*time.Hour)
		case "require_mfa":
			sms.requireMFAForUser(alert.UserID)
		case "notify_admin":
			sms.notifyAdministrators(alert)
		case "notify_user":
			sms.notifyUser(alert)
		case "rate_limit":
			sms.applyRateLimit(alert.IPAddress)
		case "quarantine":
			sms.quarantineUser(alert.UserID)
		case "alert_security_team":
			sms.alertSecurityTeam(alert)
		}
	}
}

// Background Processes

func (sms *SecurityMonitorService) monitoringLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sms.runPeriodicAnalysis()
		case <-sms.stopChan:
			return
		}
	}
}

func (sms *SecurityMonitorService) runPeriodicAnalysis() {
	// Analyze recent audit logs for patterns
	var recentEvents []models.AuditLog
	sms.db.Where("timestamp > ?", time.Now().Add(-5*time.Minute)).
		Order("timestamp DESC").Limit(1000).Find(&recentEvents)

	// Convert to security events and analyze
	for _, auditLog := range recentEvents {
		event := &SecurityEvent{
			Type:      auditLog.Action,
			UserID:    &auditLog.UserID,
			IPAddress: auditLog.IPAddress,
			UserAgent: auditLog.UserAgent,
			Success:   auditLog.Success,
			Timestamp: auditLog.Timestamp,
			Details:   convertToStringMap(auditLog.Details),
		}

		// Check for various attack patterns
		if alert := sms.DetectBruteForce(event.UserID, event.IPAddress, 15*time.Minute); alert != nil {
			sms.processAlert(*alert)
		}

		if event.UserID != nil {
			if alert := sms.DetectGeoAnomaly(*event.UserID, event.IPAddress); alert != nil {
				sms.processAlert(*alert)
			}
		}

		if alert := sms.DetectRateLimitViolation(event.IPAddress, "/auth/login", 1*time.Minute); alert != nil {
			sms.processAlert(*alert)
		}
	}
}

func (sms *SecurityMonitorService) runThreatIntelligenceUpdater() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sms.updateThreatIntelligence()
		case <-sms.stopChan:
			return
		}
	}
}

func (sms *SecurityMonitorService) updateThreatIntelligence() {
	// Update malicious IP database from threat feeds
	// This would integrate with real threat intelligence APIs
	// For now, maintain a static list of known bad actors

	knownMaliciousIPs := []string{
		// Add known malicious IPs here
		// These would come from threat intel feeds in production
	}

	sms.threatDB.mutex.Lock()
	defer sms.threatDB.mutex.Unlock()

	for _, ip := range knownMaliciousIPs {
		sms.threatDB.maliciousIPs[ip] = &ThreatInfo{
			Source:      "threat_intelligence",
			ThreatType:  "malicious_ip",
			Confidence:  0.9,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			Description: "Known malicious IP from threat intelligence",
		}
	}

	sms.threatDB.lastUpdate = time.Now()
}

func (sms *SecurityMonitorService) runBehaviorAnalyzer() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sms.analyzeBehaviorBaselines()
		case <-sms.stopChan:
			return
		}
	}
}

func (sms *SecurityMonitorService) analyzeBehaviorBaselines() {
	// Update user behavior baselines based on historical data
	sms.behaviorTracker.mutex.Lock()
	defer sms.behaviorTracker.mutex.Unlock()

	for userID := range sms.behaviorTracker.userBehaviors {
		sms.updateUserBaseline(userID)
	}
}

// Utility Methods

func (sms *SecurityMonitorService) calculateDistance(geo1, geo2 *GeoLocation) float64 {
	const earthRadius = 6371 // Earth radius in kilometers

	lat1Rad := geo1.Latitude * math.Pi / 180
	lon1Rad := geo1.Longitude * math.Pi / 180
	lat2Rad := geo2.Latitude * math.Pi / 180
	lon2Rad := geo2.Longitude * math.Pi / 180

	deltaLat := lat2Rad - lat1Rad
	deltaLon := lon2Rad - lon1Rad

	a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*
			math.Sin(deltaLon/2)*math.Sin(deltaLon/2)

	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	distance := earthRadius * c

	return distance
}

func (sms *SecurityMonitorService) generateDeviceFingerprint(userAgent string) string {
	// Simple device fingerprinting based on User-Agent
	// In production, this would be more sophisticated
	return fmt.Sprintf("%x", userAgent)
}

func (sms *SecurityMonitorService) getClientIP(r *http.Request) string {
	// Get real client IP, considering proxies
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func (sms *SecurityMonitorService) sanitizeForLogging(input string) string {
	// Sanitize potentially malicious content for safe logging
	// Remove or escape dangerous characters
	sanitized := strings.ReplaceAll(input, "\n", "\\n")
	sanitized = strings.ReplaceAll(sanitized, "\r", "\\r")
	sanitized = strings.ReplaceAll(sanitized, "\t", "\\t")

	// Truncate if too long
	if len(sanitized) > 500 {
		sanitized = sanitized[:500] + "...[truncated]"
	}

	return sanitized
}

// Action Implementation Methods (simplified)

func (sms *SecurityMonitorService) blockIP(ip string, duration time.Duration) {
	// In production, this would interact with firewall/load balancer
	fmt.Printf("SECURITY: Blocking IP %s for %v\n", ip, duration)
}

func (sms *SecurityMonitorService) requireMFAForUser(userID *uuid.UUID) {
	if userID != nil {
		fmt.Printf("SECURITY: Requiring MFA for user %s\n", userID.String())
	}
}

func (sms *SecurityMonitorService) notifyAdministrators(alert SecurityAlert) {
	fmt.Printf("SECURITY ALERT: %s - %s\n", alert.Type, alert.Description)
}

func (sms *SecurityMonitorService) notifyUser(alert SecurityAlert) {
	if alert.UserID != nil {
		fmt.Printf("USER NOTIFICATION: Security alert for user %s\n", alert.UserID.String())
	}
}

func (sms *SecurityMonitorService) applyRateLimit(ip string) {
	fmt.Printf("SECURITY: Applying rate limit to IP %s\n", ip)
}

func (sms *SecurityMonitorService) quarantineUser(userID *uuid.UUID) {
	if userID != nil {
		fmt.Printf("SECURITY: Quarantining user %s\n", userID.String())
	}
}

func (sms *SecurityMonitorService) alertSecurityTeam(alert SecurityAlert) {
	fmt.Printf("SECURITY TEAM ALERT: High priority alert - %s\n", alert.Description)
}

// Constructor functions for sub-services
func NewSecurityRuleEngine() *SecurityRuleEngine {
	return &SecurityRuleEngine{
		rules:       make([]SecurityRule, 0),
		ruleCache:   make(map[string]*SecurityRule),
		evaluations: make(map[string]*RuleEvaluation),
	}
}

func NewThreatIntelligenceDB() *ThreatIntelligenceDB {
	return &ThreatIntelligenceDB{
		maliciousIPs:        make(map[string]*ThreatInfo),
		maliciousDomains:    make(map[string]*ThreatInfo),
		knownAttackPatterns: make([]AttackPattern, 0),
		breachedPasswords:   make(map[string]bool),
		updateChan:          make(chan struct{}, 1),
	}
}

func NewBehaviorTracker() *BehaviorTracker {
	return &BehaviorTracker{
		userBehaviors: make(map[uuid.UUID]*UserBehaviorProfile),
		ipBehaviors:   make(map[string]*IPBehaviorProfile),
	}
}

func NewGeoLocationService(apiKey string) *GeoLocationService {
	return &GeoLocationService{
		cache:     make(map[string]*GeoLocation),
		client:    &http.Client{Timeout: 10 * time.Second},
		apiKey:    apiKey,
		rateLimit: time.NewTicker(100 * time.Millisecond), // 10 requests per second
	}
}

// Placeholder methods that would be implemented based on specific requirements
func (sms *SecurityMonitorService) loadDefaultSecurityRules()           {}
func (sms *SecurityMonitorService) runAlertProcessor()                  {}
func (sms *SecurityMonitorService) updateUserBaseline(userID uuid.UUID) {}

func (sre *SecurityRuleEngine) EvaluateEvent(event *SecurityEvent) []SecurityRule {
	return []SecurityRule{} // Placeholder
}

func (sms *SecurityMonitorService) createAlertFromRule(rule SecurityRule, event *SecurityEvent) SecurityAlert {
	return SecurityAlert{} // Placeholder
}

func (sms *SecurityMonitorService) createThreatAlert(event *SecurityEvent, threat *ThreatInfo) SecurityAlert {
	return SecurityAlert{} // Placeholder
}

func (sms *SecurityMonitorService) createAnomalyAlert(event *SecurityEvent, score float64) SecurityAlert {
	return SecurityAlert{} // Placeholder
}

func (tidb *ThreatIntelligenceDB) CheckThreat(ip string) *ThreatInfo {
	tidb.mutex.RLock()
	defer tidb.mutex.RUnlock()

	return tidb.maliciousIPs[ip]
}

func (gls *GeoLocationService) GetLocation(ip string) *GeoLocation {
	gls.mutex.RLock()
	if cached, exists := gls.cache[ip]; exists {
		gls.mutex.RUnlock()
		return cached
	}
	gls.mutex.RUnlock()

	// In production, this would call a real geolocation API
	// For now, return a mock location
	location := &GeoLocation{
		Country:     "Vietnam",
		Region:      "Ho Chi Minh City",
		City:        "Ho Chi Minh City",
		Latitude:    10.8231,
		Longitude:   106.6297,
		ISP:         "Unknown ISP",
		Timezone:    "Asia/Ho_Chi_Minh",
		ThreatLevel: "low",
	}

	gls.mutex.Lock()
	gls.cache[ip] = location
	gls.mutex.Unlock()

	return location
}

// convertToStringMap safely converts interface{} to map[string]interface{}
func convertToStringMap(data interface{}) map[string]interface{} {
	if data == nil {
		return make(map[string]interface{})
	}

	if m, ok := data.(map[string]interface{}); ok {
		return m
	}

	// If it's not a map[string]interface{}, create a wrapper
	return map[string]interface{}{
		"data": data,
	}
}
