package services

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// IntrusionDetectionService handles security monitoring and threat detection
type IntrusionDetectionService struct {
	db               *gorm.DB
	auditService     *AuditService
	config           *IntrusionConfig
	behaviorProfiles map[uuid.UUID]*IntrusionUserProfile
	ipReputations    map[string]*IPReputation
	activeThreats    map[string]*ThreatEvent
	geoService       *IntrusionGeoService
	deviceTracker    *DeviceTracker
	mutex            sync.RWMutex
	alertChannel     chan *IntrusionAlert
}

// IntrusionConfig holds configuration for intrusion detection
type IntrusionConfig struct {
	MaxFailedLogins        int           `json:"max_failed_logins"`
	LoginWindowDuration    time.Duration `json:"login_window_duration"`
	GeoVelocityThreshold   float64       `json:"geo_velocity_threshold"` // km/h
	DeviceChangeThreshold  int           `json:"device_change_threshold"`
	SuspiciousIPThreshold  float64       `json:"suspicious_ip_threshold"`
	BehaviorScoreThreshold float64       `json:"behavior_score_threshold"`
	AutoBlockEnabled       bool          `json:"auto_block_enabled"`
	NotificationEnabled    bool          `json:"notification_enabled"`
}

// IntrusionUserProfile tracks normal user behavior patterns for intrusion detection
type IntrusionUserProfile struct {
	UserID             uuid.UUID           `json:"user_id"`
	TypicalLoginTimes  []TimeWindow        `json:"typical_login_times"`
	CommonLocations    []Location          `json:"common_locations"`
	KnownDevices       []DeviceFingerprint `json:"known_devices"`
	AverageSessionTime time.Duration       `json:"average_session_time"`
	TypicalActivities  []string            `json:"typical_activities"`
	LastUpdated        time.Time           `json:"last_updated"`
	TrustScore         float64             `json:"trust_score"`
	LearningComplete   bool                `json:"learning_complete"`
	LoginFrequency     map[int]int         `json:"login_frequency"` // Hour of day -> count
}

// TimeWindow represents a time range for behavior analysis
type TimeWindow struct {
	StartHour int     `json:"start_hour"`
	EndHour   int     `json:"end_hour"`
	Frequency float64 `json:"frequency"`
	DayOfWeek int     `json:"day_of_week"`
}

// Location represents geographic coordinates
type Location struct {
	Latitude   float64   `json:"latitude"`
	Longitude  float64   `json:"longitude"`
	Country    string    `json:"country"`
	Region     string    `json:"region"`
	City       string    `json:"city"`
	ISP        string    `json:"isp"`
	LastSeen   time.Time `json:"last_seen"`
	Frequency  int       `json:"frequency"`
	TrustLevel float64   `json:"trust_level"`
}

// DeviceFingerprint identifies unique devices
type DeviceFingerprint struct {
	ID               string            `json:"id"`
	UserAgent        string            `json:"user_agent"`
	Browser          string            `json:"browser"`
	OS               string            `json:"os"`
	ScreenResolution string            `json:"screen_resolution"`
	Timezone         string            `json:"timezone"`
	Language         string            `json:"language"`
	Plugins          []string          `json:"plugins"`
	FirstSeen        time.Time         `json:"first_seen"`
	LastSeen         time.Time         `json:"last_seen"`
	TrustLevel       float64           `json:"trust_level"`
	Properties       map[string]string `json:"properties"`
}

// IPReputation tracks IP address reputation and behavior
type IPReputation struct {
	IP              string    `json:"ip"`
	Country         string    `json:"country"`
	ISP             string    `json:"isp"`
	ReputationScore float64   `json:"reputation_score"` // 0-100
	IsKnownProxy    bool      `json:"is_known_proxy"`
	IsKnownVPN      bool      `json:"is_known_vpn"`
	IsKnownTor      bool      `json:"is_known_tor"`
	FailedLogins    int       `json:"failed_logins"`
	SuccessLogins   int       `json:"success_logins"`
	LastSeen        time.Time `json:"last_seen"`
	FirstSeen       time.Time `json:"first_seen"`
	ThreatLevel     string    `json:"threat_level"` // low, medium, high, critical
	IsBlocked       bool      `json:"is_blocked"`
	BlockedUntil    time.Time `json:"blocked_until"`
}

// ThreatEvent represents a detected security threat
type ThreatEvent struct {
	ID                string                 `json:"id"`
	UserID            uuid.UUID              `json:"user_id,omitempty"`
	Type              string                 `json:"type"`
	Severity          string                 `json:"severity"` // low, medium, high, critical
	Description       string                 `json:"description"`
	IPAddress         string                 `json:"ip_address"`
	UserAgent         string                 `json:"user_agent"`
	Location          *Location              `json:"location,omitempty"`
	DeviceFingerprint *DeviceFingerprint     `json:"device_fingerprint,omitempty"`
	RiskScore         float64                `json:"risk_score"`
	Evidence          map[string]interface{} `json:"evidence"`
	Timestamp         time.Time              `json:"timestamp"`
	Status            string                 `json:"status"` // detected, investigating, resolved, false_positive
	AutoBlocked       bool                   `json:"auto_blocked"`
	NotificationSent  bool                   `json:"notification_sent"`
}

// IntrusionAlert represents alerts sent to administrators
type IntrusionAlert struct {
	ID          string       `json:"id"`
	Type        string       `json:"type"`
	Severity    string       `json:"severity"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	UserID      uuid.UUID    `json:"user_id,omitempty"`
	ThreatEvent *ThreatEvent `json:"threat_event"`
	Timestamp   time.Time    `json:"timestamp"`
	Recipients  []string     `json:"recipients"`
}

// IntrusionGeoService provides IP geolocation services for intrusion detection
type IntrusionGeoService struct {
	// In production, integrate with MaxMind GeoIP2 or similar service
	cache map[string]*Location
	mutex sync.RWMutex
}

// DeviceTracker manages device fingerprinting
type DeviceTracker struct {
	knownDevices map[string]*DeviceFingerprint
	mutex        sync.RWMutex
}

// LoginAttempt represents a login attempt for analysis
type LoginAttempt struct {
	UserID        uuid.UUID          `json:"user_id,omitempty"`
	Email         string             `json:"email"`
	IPAddress     string             `json:"ip_address"`
	UserAgent     string             `json:"user_agent"`
	Success       bool               `json:"success"`
	FailureReason string             `json:"failure_reason,omitempty"`
	Location      *Location          `json:"location,omitempty"`
	Device        *DeviceFingerprint `json:"device,omitempty"`
	Timestamp     time.Time          `json:"timestamp"`
}

// NewIntrusionDetectionService creates a new intrusion detection service
func NewIntrusionDetectionService(db *gorm.DB, auditService *AuditService) *IntrusionDetectionService {
	config := &IntrusionConfig{
		MaxFailedLogins:        5,
		LoginWindowDuration:    15 * time.Minute,
		GeoVelocityThreshold:   500.0, // 500 km/h impossible travel
		DeviceChangeThreshold:  3,
		SuspiciousIPThreshold:  30.0,
		BehaviorScoreThreshold: 20.0,
		AutoBlockEnabled:       true,
		NotificationEnabled:    true,
	}

	geoService := &IntrusionGeoService{
		cache: make(map[string]*Location),
	}

	deviceTracker := &DeviceTracker{
		knownDevices: make(map[string]*DeviceFingerprint),
	}

	service := &IntrusionDetectionService{
		db:               db,
		auditService:     auditService,
		config:           config,
		behaviorProfiles: make(map[uuid.UUID]*IntrusionUserProfile),
		ipReputations:    make(map[string]*IPReputation),
		activeThreats:    make(map[string]*ThreatEvent),
		geoService:       geoService,
		deviceTracker:    deviceTracker,
		alertChannel:     make(chan *IntrusionAlert, 1000),
	}

	// Start background processing
	go service.threatAnalysisWorker()
	go service.alertProcessor()
	go service.cleanupWorker()

	return service
}

// AnalyzeLoginAttempt analyzes a login attempt for threats
func (ids *IntrusionDetectionService) AnalyzeLoginAttempt(attempt *LoginAttempt) (*ThreatEvent, error) {
	ids.mutex.Lock()
	defer ids.mutex.Unlock()

	var threats []*ThreatEvent

	// Get or create IP reputation
	ipRep := ids.getOrCreateIPReputation(attempt.IPAddress)

	// Update IP statistics
	if attempt.Success {
		ipRep.SuccessLogins++
	} else {
		ipRep.FailedLogins++
	}
	ipRep.LastSeen = attempt.Timestamp

	// Get user behavior profile if login succeeded
	var profile *IntrusionUserProfile
	if attempt.Success && attempt.UserID != uuid.Nil {
		profile = ids.getOrCreateUserProfile(attempt.UserID)
	}

	// 1. Brute Force Detection
	if brute := ids.detectBruteForce(attempt, ipRep); brute != nil {
		threats = append(threats, brute)
	}

	// 2. Geographic Anomaly Detection
	if attempt.Success && profile != nil {
		if geo := ids.detectGeographicAnomaly(attempt, profile); geo != nil {
			threats = append(threats, geo)
		}
	}

	// 3. Device Anomaly Detection
	if attempt.Success && profile != nil {
		if device := ids.detectDeviceAnomaly(attempt, profile); device != nil {
			threats = append(threats, device)
		}
	}

	// 4. Time-based Anomaly Detection
	if attempt.Success && profile != nil {
		if time := ids.detectTimeAnomaly(attempt, profile); time != nil {
			threats = append(threats, time)
		}
	}

	// 5. IP Reputation Check
	if ipThreat := ids.checkIPReputation(attempt, ipRep); ipThreat != nil {
		threats = append(threats, ipThreat)
	}

	// 6. Credential Stuffing Detection
	if stuffing := ids.detectCredentialStuffing(attempt); stuffing != nil {
		threats = append(threats, stuffing)
	}

	// Update behavior profiles
	if attempt.Success && attempt.UserID != uuid.Nil {
		ids.updateUserProfile(attempt, profile)
	}

	// Return highest severity threat
	var highestThreat *ThreatEvent
	for _, threat := range threats {
		if highestThreat == nil || threat.RiskScore > highestThreat.RiskScore {
			highestThreat = threat
		}
	}

	// Handle threat response
	if highestThreat != nil {
		ids.handleThreatResponse(highestThreat)
	}

	return highestThreat, nil
}

// detectBruteForce detects brute force attacks
func (ids *IntrusionDetectionService) detectBruteForce(attempt *LoginAttempt, ipRep *IPReputation) *ThreatEvent {
	if attempt.Success {
		return nil
	}

	// Check recent failed attempts from this IP
	recentFailures := ids.countRecentFailures(attempt.IPAddress, ids.config.LoginWindowDuration)

	if recentFailures >= ids.config.MaxFailedLogins {
		return &ThreatEvent{
			ID:          uuid.New().String(),
			Type:        "brute_force_attack",
			Severity:    "high",
			Description: fmt.Sprintf("Brute force attack detected: %d failed logins from IP %s", recentFailures, attempt.IPAddress),
			IPAddress:   attempt.IPAddress,
			UserAgent:   attempt.UserAgent,
			Location:    attempt.Location,
			RiskScore:   80.0 + float64(recentFailures-ids.config.MaxFailedLogins)*5.0,
			Evidence: map[string]interface{}{
				"failed_attempts": recentFailures,
				"time_window":     ids.config.LoginWindowDuration.String(),
				"emails_targeted": ids.getTargetedEmails(attempt.IPAddress),
			},
			Timestamp:   attempt.Timestamp,
			Status:      "detected",
			AutoBlocked: ids.config.AutoBlockEnabled,
		}
	}

	return nil
}

// detectGeographicAnomaly detects impossible travel or unusual locations
func (ids *IntrusionDetectionService) detectGeographicAnomaly(attempt *LoginAttempt, profile *IntrusionUserProfile) *ThreatEvent {
	if attempt.Location == nil || len(profile.CommonLocations) == 0 {
		return nil
	}

	// Check for impossible travel
	for _, location := range profile.CommonLocations {
		if location.LastSeen.After(attempt.Timestamp.Add(-1 * time.Hour)) {
			distance := ids.calculateDistance(
				attempt.Location.Latitude, attempt.Location.Longitude,
				location.Latitude, location.Longitude,
			)

			timeDiff := attempt.Timestamp.Sub(location.LastSeen).Hours()
			if timeDiff > 0 {
				velocity := distance / timeDiff

				if velocity > ids.config.GeoVelocityThreshold {
					return &ThreatEvent{
						ID:          uuid.New().String(),
						Type:        "impossible_travel",
						Severity:    "high",
						Description: fmt.Sprintf("Impossible travel detected: %.1f km in %.1f hours (%.1f km/h)", distance, timeDiff, velocity),
						UserID:      attempt.UserID,
						IPAddress:   attempt.IPAddress,
						Location:    attempt.Location,
						RiskScore:   90.0,
						Evidence: map[string]interface{}{
							"distance_km":       distance,
							"time_hours":        timeDiff,
							"velocity_kmh":      velocity,
							"previous_location": location,
						},
						Timestamp: attempt.Timestamp,
						Status:    "detected",
					}
				}
			}
		}
	}

	// Check if location is unusual for this user
	isKnownLocation := false
	minDistance := math.Inf(1)

	for _, location := range profile.CommonLocations {
		distance := ids.calculateDistance(
			attempt.Location.Latitude, attempt.Location.Longitude,
			location.Latitude, location.Longitude,
		)

		if distance < 50.0 { // Within 50km is considered same location
			isKnownLocation = true
			break
		}

		if distance < minDistance {
			minDistance = distance
		}
	}

	if !isKnownLocation && minDistance > 1000.0 { // More than 1000km from any known location
		return &ThreatEvent{
			ID:          uuid.New().String(),
			Type:        "unusual_location",
			Severity:    "medium",
			Description: fmt.Sprintf("Login from unusual location: %s, %s (%.1f km from nearest known location)", attempt.Location.City, attempt.Location.Country, minDistance),
			UserID:      attempt.UserID,
			IPAddress:   attempt.IPAddress,
			Location:    attempt.Location,
			RiskScore:   50.0 + math.Min(minDistance/100, 40.0),
			Evidence: map[string]interface{}{
				"distance_from_known": minDistance,
				"known_locations":     len(profile.CommonLocations),
			},
			Timestamp: attempt.Timestamp,
			Status:    "detected",
		}
	}

	return nil
}

// detectDeviceAnomaly detects new or suspicious devices
func (ids *IntrusionDetectionService) detectDeviceAnomaly(attempt *LoginAttempt, profile *IntrusionUserProfile) *ThreatEvent {
	if attempt.Device == nil {
		return nil
	}

	// Check if device is known
	isKnownDevice := false
	for _, device := range profile.KnownDevices {
		if ids.compareDeviceFingerprints(attempt.Device, &device) > 0.8 {
			isKnownDevice = true
			break
		}
	}

	if !isKnownDevice {
		// Count recent new device logins
		recentNewDevices := ids.countRecentNewDevices(attempt.UserID, 24*time.Hour)

		severity := "low"
		riskScore := 30.0

		if recentNewDevices >= ids.config.DeviceChangeThreshold {
			severity = "medium"
			riskScore = 60.0
		}

		return &ThreatEvent{
			ID:                uuid.New().String(),
			Type:              "new_device_login",
			Severity:          severity,
			Description:       fmt.Sprintf("Login from new device: %s on %s", attempt.Device.Browser, attempt.Device.OS),
			UserID:            attempt.UserID,
			IPAddress:         attempt.IPAddress,
			Location:          attempt.Location,
			DeviceFingerprint: attempt.Device,
			RiskScore:         riskScore,
			Evidence: map[string]interface{}{
				"device_fingerprint":  attempt.Device,
				"recent_new_devices":  recentNewDevices,
				"known_devices_count": len(profile.KnownDevices),
			},
			Timestamp: attempt.Timestamp,
			Status:    "detected",
		}
	}

	return nil
}

// detectTimeAnomaly detects unusual login times
func (ids *IntrusionDetectionService) detectTimeAnomaly(attempt *LoginAttempt, profile *IntrusionUserProfile) *ThreatEvent {
	if !profile.LearningComplete {
		return nil
	}

	hour := attempt.Timestamp.Hour()
	weekday := int(attempt.Timestamp.Weekday())

	// Check if this time is typical for the user
	frequency := profile.LoginFrequency[hour]
	totalLogins := 0
	for _, count := range profile.LoginFrequency {
		totalLogins += count
	}

	if totalLogins == 0 {
		return nil
	}

	normalizedFreq := float64(frequency) / float64(totalLogins)

	// If user rarely logs in at this time (< 5% of logins), it's suspicious
	if normalizedFreq < 0.05 && totalLogins > 50 {
		return &ThreatEvent{
			ID:          uuid.New().String(),
			Type:        "unusual_login_time",
			Severity:    "low",
			Description: fmt.Sprintf("Login at unusual time: %02d:00 on %s (only %.1f%% of historical logins)", hour, time.Weekday(weekday), normalizedFreq*100),
			UserID:      attempt.UserID,
			IPAddress:   attempt.IPAddress,
			Location:    attempt.Location,
			RiskScore:   25.0 + (0.05-normalizedFreq)*400, // Higher score for more unusual times
			Evidence: map[string]interface{}{
				"login_hour":        hour,
				"weekday":           weekday,
				"frequency_percent": normalizedFreq * 100,
				"total_logins":      totalLogins,
			},
			Timestamp: attempt.Timestamp,
			Status:    "detected",
		}
	}

	return nil
}

// checkIPReputation checks IP against threat databases
func (ids *IntrusionDetectionService) checkIPReputation(attempt *LoginAttempt, ipRep *IPReputation) *ThreatEvent {
	// Update reputation score based on behavior
	ids.updateIPReputationScore(ipRep)

	// Check for high-risk characteristics
	var riskFactors []string
	riskScore := 0.0

	if ipRep.IsKnownProxy {
		riskFactors = append(riskFactors, "known_proxy")
		riskScore += 20.0
	}

	if ipRep.IsKnownVPN {
		riskFactors = append(riskFactors, "known_vpn")
		riskScore += 15.0
	}

	if ipRep.IsKnownTor {
		riskFactors = append(riskFactors, "tor_exit_node")
		riskScore += 40.0
	}

	if ipRep.ReputationScore < ids.config.SuspiciousIPThreshold {
		riskFactors = append(riskFactors, "low_reputation")
		riskScore += (ids.config.SuspiciousIPThreshold - ipRep.ReputationScore) * 1.5
	}

	if len(riskFactors) > 0 && riskScore > 30.0 {
		severity := "medium"
		if riskScore > 60.0 {
			severity = "high"
		}

		return &ThreatEvent{
			ID:          uuid.New().String(),
			Type:        "suspicious_ip",
			Severity:    severity,
			Description: fmt.Sprintf("Login from suspicious IP: %s (%s)", attempt.IPAddress, strings.Join(riskFactors, ", ")),
			UserID:      attempt.UserID,
			IPAddress:   attempt.IPAddress,
			Location:    attempt.Location,
			RiskScore:   riskScore,
			Evidence: map[string]interface{}{
				"risk_factors":     riskFactors,
				"reputation_score": ipRep.ReputationScore,
				"failed_logins":    ipRep.FailedLogins,
				"success_logins":   ipRep.SuccessLogins,
			},
			Timestamp: attempt.Timestamp,
			Status:    "detected",
		}
	}

	return nil
}

// detectCredentialStuffing detects credential stuffing attacks
func (ids *IntrusionDetectionService) detectCredentialStuffing(attempt *LoginAttempt) *ThreatEvent {
	// Look for patterns indicating credential stuffing:
	// 1. Many different emails from same IP
	// 2. Rapid succession of login attempts
	// 3. User agents indicating automation

	targetedEmails := ids.getTargetedEmails(attempt.IPAddress)
	recentAttempts := ids.countRecentAttempts(attempt.IPAddress, 5*time.Minute)

	// Check for automation indicators in User-Agent
	suspiciousUA := ids.isSuspiciousUserAgent(attempt.UserAgent)

	if len(targetedEmails) > 10 && recentAttempts > 20 {
		riskScore := 70.0
		if suspiciousUA {
			riskScore += 20.0
		}

		return &ThreatEvent{
			ID:          uuid.New().String(),
			Type:        "credential_stuffing",
			Severity:    "high",
			Description: fmt.Sprintf("Credential stuffing attack detected: %d emails targeted, %d attempts in 5 minutes", len(targetedEmails), recentAttempts),
			IPAddress:   attempt.IPAddress,
			UserAgent:   attempt.UserAgent,
			Location:    attempt.Location,
			RiskScore:   riskScore,
			Evidence: map[string]interface{}{
				"emails_targeted": len(targetedEmails),
				"recent_attempts": recentAttempts,
				"suspicious_ua":   suspiciousUA,
				"sample_emails":   targetedEmails[:min(10, len(targetedEmails))],
			},
			Timestamp: attempt.Timestamp,
			Status:    "detected",
		}
	}

	return nil
}

// handleThreatResponse handles the response to detected threats
func (ids *IntrusionDetectionService) handleThreatResponse(threat *ThreatEvent) {
	// Store threat in database
	ids.activeThreats[threat.ID] = threat

	// Auto-block if configured and threat is severe enough
	if ids.config.AutoBlockEnabled && threat.RiskScore > 70.0 {
		ids.blockIP(threat.IPAddress, threat.RiskScore)
		threat.AutoBlocked = true
	}

	// Send alert if configured
	if ids.config.NotificationEnabled && threat.RiskScore > 50.0 {
		alert := &IntrusionAlert{
			ID:          uuid.New().String(),
			Type:        "security_threat",
			Severity:    threat.Severity,
			Title:       ids.generateAlertTitle(threat),
			Description: threat.Description,
			UserID:      threat.UserID,
			ThreatEvent: threat,
			Timestamp:   time.Now(),
			Recipients:  []string{"security@company.com", "admin@company.com"},
		}

		select {
		case ids.alertChannel <- alert:
			// Alert queued successfully
		default:
			log.Printf("Alert channel full, dropping alert: %s", alert.ID)
		}

		threat.NotificationSent = true
	}

	// Log to audit system
	ids.auditService.LogEvent(
		threat.UserID,
		fmt.Sprintf("threat_detected_%s", threat.Type),
		"security",
		threat.ID,
		false,
		map[string]interface{}{
			"threat_type":  threat.Type,
			"severity":     threat.Severity,
			"risk_score":   threat.RiskScore,
			"auto_blocked": threat.AutoBlocked,
			"ip_address":   threat.IPAddress,
			"evidence":     threat.Evidence,
		},
		threat.IPAddress,
		threat.UserAgent,
	)
}

// Helper methods

func (ids *IntrusionDetectionService) getOrCreateIPReputation(ip string) *IPReputation {
	if rep, exists := ids.ipReputations[ip]; exists {
		return rep
	}

	// Create new IP reputation
	location := ids.geoService.GetLocation(ip)

	rep := &IPReputation{
		IP:              ip,
		Country:         location.Country,
		ISP:             location.ISP,
		ReputationScore: 50.0, // Start with neutral score
		FirstSeen:       time.Now(),
		LastSeen:        time.Now(),
		ThreatLevel:     "low",
		IsBlocked:       false,
	}

	// Check against known threat databases
	ids.checkThreatDatabases(rep)

	ids.ipReputations[ip] = rep
	return rep
}

func (ids *IntrusionDetectionService) getOrCreateUserProfile(userID uuid.UUID) *IntrusionUserProfile {
	if profile, exists := ids.behaviorProfiles[userID]; exists {
		return profile
	}

	// Create new behavior profile
	profile := &IntrusionUserProfile{
		UserID:            userID,
		TypicalLoginTimes: make([]TimeWindow, 0),
		CommonLocations:   make([]Location, 0),
		KnownDevices:      make([]DeviceFingerprint, 0),
		TypicalActivities: make([]string, 0),
		LoginFrequency:    make(map[int]int),
		TrustScore:        50.0,
		LearningComplete:  false,
		LastUpdated:       time.Now(),
	}

	ids.behaviorProfiles[userID] = profile
	return profile
}

func (ids *IntrusionDetectionService) updateUserProfile(attempt *LoginAttempt, profile *IntrusionUserProfile) {
	// Update login frequency by hour
	hour := attempt.Timestamp.Hour()
	profile.LoginFrequency[hour]++

	// Update common locations
	if attempt.Location != nil {
		ids.updateCommonLocations(profile, attempt.Location)
	}

	// Update known devices
	if attempt.Device != nil {
		ids.updateKnownDevices(profile, attempt.Device)
	}

	// Update trust score based on consistency
	ids.updateTrustScore(profile, attempt)

	// Check if learning is complete (need at least 50 logins)
	totalLogins := 0
	for _, count := range profile.LoginFrequency {
		totalLogins += count
	}

	if totalLogins >= 50 && len(profile.CommonLocations) >= 2 && len(profile.KnownDevices) >= 1 {
		profile.LearningComplete = true
	}

	profile.LastUpdated = time.Now()
}

func (ids *IntrusionDetectionService) calculateDistance(lat1, lon1, lat2, lon2 float64) float64 {
	// Haversine formula for calculating distance between two points on Earth
	const R = 6371 // Earth's radius in kilometers

	lat1Rad := lat1 * math.Pi / 180
	lat2Rad := lat2 * math.Pi / 180
	deltaLat := (lat2 - lat1) * math.Pi / 180
	deltaLon := (lon2 - lon1) * math.Pi / 180

	a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*
			math.Sin(deltaLon/2)*math.Sin(deltaLon/2)

	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return R * c
}

func (ids *IntrusionDetectionService) compareDeviceFingerprints(device1, device2 *DeviceFingerprint) float64 {
	score := 0.0
	total := 0.0

	// Compare major components
	if device1.Browser == device2.Browser {
		score += 0.3
	}
	total += 0.3

	if device1.OS == device2.OS {
		score += 0.3
	}
	total += 0.3

	if device1.ScreenResolution == device2.ScreenResolution {
		score += 0.2
	}
	total += 0.2

	if device1.Timezone == device2.Timezone {
		score += 0.1
	}
	total += 0.1

	if device1.Language == device2.Language {
		score += 0.1
	}
	total += 0.1

	return score / total
}

func (ids *IntrusionDetectionService) countRecentFailures(ip string, window time.Duration) int {
	// In production, query audit logs or cache recent failures
	// For now, use IP reputation data
	if rep, exists := ids.ipReputations[ip]; exists {
		if time.Since(rep.LastSeen) <= window {
			return rep.FailedLogins
		}
	}
	return 0
}

func (ids *IntrusionDetectionService) getTargetedEmails(ip string) []string {
	// In production, query recent login attempts from this IP
	// This is a simplified implementation
	return []string{"user1@example.com", "user2@example.com", "admin@example.com"}
}

func (ids *IntrusionDetectionService) countRecentNewDevices(userID uuid.UUID, window time.Duration) int {
	// In production, query device tracking data
	// This is a simplified implementation
	return 1
}

func (ids *IntrusionDetectionService) countRecentAttempts(ip string, window time.Duration) int {
	// In production, query audit logs for recent attempts from this IP
	// This is a simplified implementation
	if rep, exists := ids.ipReputations[ip]; exists {
		return rep.FailedLogins + rep.SuccessLogins
	}
	return 0
}

func (ids *IntrusionDetectionService) isSuspiciousUserAgent(userAgent string) bool {
	// Check for automation indicators
	suspiciousPatterns := []string{
		"bot", "crawler", "spider", "curl", "wget", "python", "go-http-client",
		"java", "okhttp", "apache", "requests", "urllib", "axios",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}

	// Check for missing or minimal user agents
	if len(userAgent) < 20 || !strings.Contains(userAgentLower, "mozilla") {
		return true
	}

	return false
}

func (ids *IntrusionDetectionService) updateIPReputationScore(rep *IPReputation) {
	// Calculate reputation based on success/failure ratio and other factors
	totalAttempts := rep.FailedLogins + rep.SuccessLogins
	if totalAttempts == 0 {
		return
	}

	successRate := float64(rep.SuccessLogins) / float64(totalAttempts)

	// Base score on success rate
	rep.ReputationScore = successRate * 100

	// Penalize high failure rates
	if rep.FailedLogins > 10 {
		penalty := math.Min(float64(rep.FailedLogins-10)*2, 40)
		rep.ReputationScore -= penalty
	}

	// Bonus for long-term good behavior
	if time.Since(rep.FirstSeen) > 30*24*time.Hour && successRate > 0.8 {
		rep.ReputationScore += 10
	}

	// Ensure score stays within bounds
	rep.ReputationScore = math.Max(0, math.Min(100, rep.ReputationScore))

	// Update threat level
	if rep.ReputationScore < 20 {
		rep.ThreatLevel = "critical"
	} else if rep.ReputationScore < 40 {
		rep.ThreatLevel = "high"
	} else if rep.ReputationScore < 60 {
		rep.ThreatLevel = "medium"
	} else {
		rep.ThreatLevel = "low"
	}
}

func (ids *IntrusionDetectionService) blockIP(ip string, duration float64) {
	if rep, exists := ids.ipReputations[ip]; exists {
		rep.IsBlocked = true
		// Block duration based on risk score (hours)
		blockDuration := time.Duration(duration/10) * time.Hour
		rep.BlockedUntil = time.Now().Add(blockDuration)

		log.Printf("Blocked IP %s for %.1f hours due to risk score %.1f", ip, blockDuration.Hours(), duration)
	}
}

func (ids *IntrusionDetectionService) checkThreatDatabases(rep *IPReputation) {
	// In production, integrate with threat intelligence feeds
	// This is a simplified implementation

	// Check for known proxy/VPN patterns (basic heuristics)
	if ids.isKnownProxy(rep.IP) {
		rep.IsKnownProxy = true
		rep.ReputationScore -= 15
	}

	if ids.isKnownVPN(rep.IP) {
		rep.IsKnownVPN = true
		rep.ReputationScore -= 10
	}

	// Check Tor exit nodes (in production, use official list)
	if ids.isTorExitNode(rep.IP) {
		rep.IsKnownTor = true
		rep.ReputationScore -= 30
	}
}

func (ids *IntrusionDetectionService) isKnownProxy(ip string) bool {
	// Simplified proxy detection
	return false
}

func (ids *IntrusionDetectionService) isKnownVPN(ip string) bool {
	// Simplified VPN detection
	return false
}

func (ids *IntrusionDetectionService) isTorExitNode(ip string) bool {
	// Simplified Tor detection
	return false
}

func (ids *IntrusionDetectionService) updateCommonLocations(profile *IntrusionUserProfile, location *Location) {
	// Find if location already exists (within 50km)
	for i, commonLoc := range profile.CommonLocations {
		distance := ids.calculateDistance(
			location.Latitude, location.Longitude,
			commonLoc.Latitude, commonLoc.Longitude,
		)

		if distance < 50.0 {
			// Update existing location
			profile.CommonLocations[i].Frequency++
			profile.CommonLocations[i].LastSeen = time.Now()
			profile.CommonLocations[i].TrustLevel = math.Min(100, profile.CommonLocations[i].TrustLevel+1)
			return
		}
	}

	// Add new location
	newLocation := *location
	newLocation.Frequency = 1
	newLocation.LastSeen = time.Now()
	newLocation.TrustLevel = 10.0

	profile.CommonLocations = append(profile.CommonLocations, newLocation)
}

func (ids *IntrusionDetectionService) updateKnownDevices(profile *IntrusionUserProfile, device *DeviceFingerprint) {
	// Find if device already exists
	for i, knownDevice := range profile.KnownDevices {
		if ids.compareDeviceFingerprints(device, &knownDevice) > 0.8 {
			// Update existing device
			profile.KnownDevices[i].LastSeen = time.Now()
			profile.KnownDevices[i].TrustLevel = math.Min(100, profile.KnownDevices[i].TrustLevel+2)
			return
		}
	}

	// Add new device
	newDevice := *device
	newDevice.FirstSeen = time.Now()
	newDevice.LastSeen = time.Now()
	newDevice.TrustLevel = 10.0

	profile.KnownDevices = append(profile.KnownDevices, newDevice)
}

func (ids *IntrusionDetectionService) updateTrustScore(profile *IntrusionUserProfile, attempt *LoginAttempt) {
	// Increase trust for consistent behavior
	hour := attempt.Timestamp.Hour()
	if profile.LoginFrequency[hour] > 5 {
		profile.TrustScore = math.Min(100, profile.TrustScore+0.5)
	}

	// Increase trust for known locations
	if attempt.Location != nil {
		for _, location := range profile.CommonLocations {
			distance := ids.calculateDistance(
				attempt.Location.Latitude, attempt.Location.Longitude,
				location.Latitude, location.Longitude,
			)

			if distance < 50.0 && location.Frequency > 3 {
				profile.TrustScore = math.Min(100, profile.TrustScore+1)
				break
			}
		}
	}
}

func (ids *IntrusionDetectionService) generateAlertTitle(threat *ThreatEvent) string {
	switch threat.Type {
	case "brute_force_attack":
		return "Brute Force Attack Detected"
	case "impossible_travel":
		return "Impossible Travel Pattern Detected"
	case "credential_stuffing":
		return "Credential Stuffing Attack Detected"
	case "suspicious_ip":
		return "Login from Suspicious IP Address"
	case "new_device_login":
		return "Login from New Device"
	case "unusual_location":
		return "Login from Unusual Location"
	case "unusual_login_time":
		return "Login at Unusual Time"
	default:
		return "Security Threat Detected"
	}
}

// Background workers

func (ids *IntrusionDetectionService) threatAnalysisWorker() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ids.performPeriodicAnalysis()
		}
	}
}

func (ids *IntrusionDetectionService) alertProcessor() {
	for alert := range ids.alertChannel {
		// In production, send email/SMS/Slack notifications
		log.Printf("SECURITY ALERT [%s]: %s - %s", alert.Severity, alert.Title, alert.Description)

		// Store alert in database
		alertJSON, _ := json.Marshal(alert)
		ids.auditService.LogEvent(
			uuid.Nil,
			"security_alert_sent",
			"security",
			alert.ID,
			true,
			map[string]interface{}{
				"alert_data": string(alertJSON),
			},
			"",
			"system",
		)
	}
}

func (ids *IntrusionDetectionService) cleanupWorker() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ids.performCleanup()
		}
	}
}

func (ids *IntrusionDetectionService) performPeriodicAnalysis() {
	ids.mutex.Lock()
	defer ids.mutex.Unlock()

	// Analyze patterns across all users
	// Update behavior models
	// Check for coordinated attacks

	log.Printf("Performing periodic threat analysis - Active threats: %d, IP reputations: %d, User profiles: %d",
		len(ids.activeThreats), len(ids.ipReputations), len(ids.behaviorProfiles))
}

func (ids *IntrusionDetectionService) performCleanup() {
	ids.mutex.Lock()
	defer ids.mutex.Unlock()

	now := time.Now()

	// Clean up old threats (older than 30 days)
	for id, threat := range ids.activeThreats {
		if now.Sub(threat.Timestamp) > 30*24*time.Hour {
			delete(ids.activeThreats, id)
		}
	}

	// Clean up IP reputation data (older than 90 days)
	for ip, rep := range ids.ipReputations {
		if now.Sub(rep.LastSeen) > 90*24*time.Hour {
			delete(ids.ipReputations, ip)
		}

		// Unblock expired IP blocks
		if rep.IsBlocked && now.After(rep.BlockedUntil) {
			rep.IsBlocked = false
			log.Printf("Unblocked IP %s after expiration", ip)
		}
	}

	log.Printf("Cleanup completed - Removed old threats and IP reputations")
}

// IntrusionGeoService methods

func (gls *IntrusionGeoService) GetLocation(ip string) *Location {
	gls.mutex.RLock()
	if location, exists := gls.cache[ip]; exists {
		gls.mutex.RUnlock()
		return location
	}
	gls.mutex.RUnlock()

	// In production, integrate with MaxMind GeoIP2 or similar service
	location := &Location{
		Country:   "Unknown",
		Region:    "Unknown",
		City:      "Unknown",
		ISP:       "Unknown",
		Latitude:  0.0,
		Longitude: 0.0,
	}

	// Basic IP to location mapping (simplified)
	if net.ParseIP(ip).IsPrivate() {
		location.Country = "Private Network"
		location.ISP = "Private Network"
	} else {
		// In production, use real geolocation service
		location.Country = "United States"
		location.Region = "California"
		location.City = "San Francisco"
		location.ISP = "Example ISP"
		location.Latitude = 37.7749
		location.Longitude = -122.4194
	}

	// Cache the result
	gls.mutex.Lock()
	gls.cache[ip] = location
	gls.mutex.Unlock()

	return location
}

// Public API methods

func (ids *IntrusionDetectionService) IsIPBlocked(ip string) bool {
	ids.mutex.RLock()
	defer ids.mutex.RUnlock()

	if rep, exists := ids.ipReputations[ip]; exists {
		return rep.IsBlocked && time.Now().Before(rep.BlockedUntil)
	}
	return false
}

func (ids *IntrusionDetectionService) GetActiveThreats() []*ThreatEvent {
	ids.mutex.RLock()
	defer ids.mutex.RUnlock()

	threats := make([]*ThreatEvent, 0, len(ids.activeThreats))
	for _, threat := range ids.activeThreats {
		threats = append(threats, threat)
	}
	return threats
}

func (ids *IntrusionDetectionService) GetUserTrustScore(userID uuid.UUID) float64 {
	ids.mutex.RLock()
	defer ids.mutex.RUnlock()

	if profile, exists := ids.behaviorProfiles[userID]; exists {
		return profile.TrustScore
	}
	return 50.0 // Neutral score for new users
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
