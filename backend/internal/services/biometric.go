package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"securevault/internal/security"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// BiometricService handles biometric authentication
type BiometricService struct {
	db            *gorm.DB
	cryptoService *security.CryptoService
	auditService  *AuditService
	challenges    map[string]*BiometricChallenge
	templates     map[uuid.UUID][]*BiometricTemplate
}

// BiometricChallenge represents a biometric authentication challenge
type BiometricChallenge struct {
	ID                string    `json:"id"`
	UserID            uuid.UUID `json:"user_id"`
	Challenge         []byte    `json:"challenge"`
	Type              string    `json:"type"` // fingerprint, face, voice
	ExpiresAt         time.Time `json:"expires_at"`
	Used              bool      `json:"used"`
	RequiredThreshold float64   `json:"required_threshold"`
}

// BiometricTemplate represents stored biometric data
type BiometricTemplate struct {
	ID           string    `json:"id" gorm:"primaryKey"`
	UserID       uuid.UUID `json:"user_id" gorm:"not null;index"`
	Type         string    `json:"type" gorm:"not null"`        // fingerprint, face, voice
	Template     []byte    `json:"template" gorm:"not null"`    // Encrypted biometric template
	Hash         string    `json:"hash" gorm:"not null;unique"` // Hash for duplicate detection
	Quality      float64   `json:"quality"`                     // Template quality score (0-100)
	CreatedAt    time.Time `json:"created_at"`
	LastUsedAt   time.Time `json:"last_used_at"`
	Name         string    `json:"name"`          // User-friendly name
	DeviceInfo   string    `json:"device_info"`   // Device that captured biometric
	FailureCount int       `json:"failure_count"` // Failed verification attempts
	Active       bool      `json:"active"`        // Whether template is active
}

// BiometricAuthRequest represents an authentication request
type BiometricAuthRequest struct {
	ChallengeID string  `json:"challenge_id"`
	Type        string  `json:"type"`
	Data        []byte  `json:"data"` // Biometric data from client
	DeviceInfo  string  `json:"device_info"`
	Quality     float64 `json:"quality"`
}

// BiometricAuthResponse represents authentication result
type BiometricAuthResponse struct {
	Success    bool    `json:"success"`
	MatchScore float64 `json:"match_score"`
	TemplateID string  `json:"template_id,omitempty"`
	Confidence float64 `json:"confidence"`
	AuthTime   int64   `json:"auth_time"`
}

// BiometricEnrollmentRequest for enrolling new biometric data
type BiometricEnrollmentRequest struct {
	Type       string  `json:"type"`
	Data       []byte  `json:"data"`
	DeviceInfo string  `json:"device_info"`
	Quality    float64 `json:"quality"`
	Name       string  `json:"name"`
}

// BiometricStats for monitoring and analytics
type BiometricStats struct {
	TotalTemplates    int     `json:"total_templates"`
	ActiveTemplates   int     `json:"active_templates"`
	SuccessRate       float64 `json:"success_rate"`
	AverageMatchScore float64 `json:"average_match_score"`
	LastAuthTime      int64   `json:"last_auth_time"`
}

// BiometricAuditEvent for detailed logging
type BiometricAuditEvent struct {
	UserID        uuid.UUID `json:"user_id"`
	EventType     string    `json:"event_type"` // enrollment, authentication, failure
	BiometricType string    `json:"biometric_type"`
	MatchScore    float64   `json:"match_score"`
	Success       bool      `json:"success"`
	DeviceInfo    string    `json:"device_info"`
	IPAddress     string    `json:"ip_address"`
	Timestamp     time.Time `json:"timestamp"`
	Details       string    `json:"details"`
}

// NewBiometricService creates a new biometric authentication service
func NewBiometricService(db *gorm.DB, cryptoService *security.CryptoService, auditService *AuditService) *BiometricService {
	// Auto-migrate biometric templates table
	db.AutoMigrate(&BiometricTemplate{})

	service := &BiometricService{
		db:            db,
		cryptoService: cryptoService,
		auditService:  auditService,
		challenges:    make(map[string]*BiometricChallenge),
		templates:     make(map[uuid.UUID][]*BiometricTemplate),
	}

	// Start cleanup goroutine
	go service.cleanupRoutine()

	return service
}

// EnrollBiometric enrolls a new biometric template for a user
func (bs *BiometricService) EnrollBiometric(userID uuid.UUID, request *BiometricEnrollmentRequest, clientIP, userAgent string) (*BiometricTemplate, error) {
	// Validate biometric type
	if !bs.isValidBiometricType(request.Type) {
		return nil, fmt.Errorf("unsupported biometric type: %s", request.Type)
	}

	// Validate quality threshold
	minQuality := bs.getMinQualityThreshold(request.Type)
	if request.Quality < minQuality {
		bs.logBiometricEvent(userID, "enrollment_failed_quality", request.Type, 0, false, request.DeviceInfo, clientIP, "Quality too low")
		return nil, fmt.Errorf("biometric quality too low: %.2f (minimum: %.2f)", request.Quality, minQuality)
	}

	// Process and extract features from biometric data
	processedTemplate, err := bs.processBiometricData(request.Data, request.Type)
	if err != nil {
		bs.logBiometricEvent(userID, "enrollment_failed_processing", request.Type, 0, false, request.DeviceInfo, clientIP, err.Error())
		return nil, fmt.Errorf("failed to process biometric data: %w", err)
	}

	// Generate template hash for duplicate detection
	templateHash := bs.generateTemplateHash(processedTemplate)

	// Check for existing duplicate template
	var existingTemplate BiometricTemplate
	if err := bs.db.Where("hash = ?", templateHash).First(&existingTemplate).Error; err == nil {
		bs.logBiometricEvent(userID, "enrollment_failed_duplicate", request.Type, 0, false, request.DeviceInfo, clientIP, "Duplicate template")
		return nil, fmt.Errorf("this biometric is already enrolled")
	}

	// Encrypt biometric template
	encryptedTemplate, err := bs.cryptoService.Encrypt(processedTemplate, fmt.Sprintf("biometric_%s_%s", userID.String(), request.Type))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt biometric template: %w", err)
	}

	templateData, _ := encryptedTemplate.Data, encryptedTemplate.Nonce

	// Create biometric template record
	template := &BiometricTemplate{
		ID:           uuid.New().String(),
		UserID:       userID,
		Type:         request.Type,
		Template:     []byte(templateData), // Store encrypted template
		Hash:         templateHash,
		Quality:      request.Quality,
		CreatedAt:    time.Now(),
		LastUsedAt:   time.Now(),
		Name:         request.Name,
		DeviceInfo:   request.DeviceInfo,
		FailureCount: 0,
		Active:       true,
	}

	// Store in database
	if err := bs.db.Create(template).Error; err != nil {
		return nil, fmt.Errorf("failed to store biometric template: %w", err)
	}

	// Cache template in memory for faster access
	bs.cacheTemplate(userID, template)

	// Log successful enrollment
	bs.logBiometricEvent(userID, "enrollment_success", request.Type, request.Quality, true, request.DeviceInfo, clientIP, "Biometric enrolled successfully")

	return template, nil
}

// BeginBiometricAuth starts biometric authentication process
func (bs *BiometricService) BeginBiometricAuth(userID uuid.UUID, biometricType string) (*BiometricChallenge, error) {
	// Validate biometric type
	if !bs.isValidBiometricType(biometricType) {
		return nil, fmt.Errorf("unsupported biometric type: %s", biometricType)
	}

	// Check if user has enrolled biometrics of this type
	var templateCount int64
	bs.db.Model(&BiometricTemplate{}).
		Where("user_id = ? AND type = ? AND active = true", userID, biometricType).
		Count(&templateCount)

	if templateCount == 0 {
		return nil, fmt.Errorf("no enrolled %s biometrics found", biometricType)
	}

	// Generate cryptographically secure challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Create challenge record
	challengeID := uuid.New().String()
	biometricChallenge := &BiometricChallenge{
		ID:                challengeID,
		UserID:            userID,
		Challenge:         challenge,
		Type:              biometricType,
		ExpiresAt:         time.Now().Add(2 * time.Minute), // Shorter timeout for biometrics
		Used:              false,
		RequiredThreshold: bs.getMatchThreshold(biometricType),
	}

	// Store challenge
	bs.challenges[challengeID] = biometricChallenge

	return biometricChallenge, nil
}

// AuthenticateBiometric performs biometric authentication
func (bs *BiometricService) AuthenticateBiometric(request *BiometricAuthRequest, clientIP, userAgent string) (*BiometricAuthResponse, error) {
	// Get and validate challenge
	challenge, exists := bs.challenges[request.ChallengeID]
	if !exists {
		return nil, fmt.Errorf("challenge not found")
	}

	if challenge.Used {
		return nil, fmt.Errorf("challenge already used")
	}

	if time.Now().After(challenge.ExpiresAt) {
		delete(bs.challenges, request.ChallengeID)
		return nil, fmt.Errorf("challenge expired")
	}

	if request.Type != challenge.Type {
		return nil, fmt.Errorf("biometric type mismatch")
	}

	// Process incoming biometric data
	processedData, err := bs.processBiometricData(request.Data, request.Type)
	if err != nil {
		bs.logBiometricEvent(challenge.UserID, "auth_failed_processing", request.Type, 0, false, request.DeviceInfo, clientIP, err.Error())
		return nil, fmt.Errorf("failed to process biometric data: %w", err)
	}

	// Get user's enrolled templates for this biometric type
	var templates []BiometricTemplate
	if err := bs.db.Where("user_id = ? AND type = ? AND active = true", challenge.UserID, request.Type).Find(&templates).Error; err != nil {
		return nil, fmt.Errorf("failed to retrieve templates: %w", err)
	}

	if len(templates) == 0 {
		bs.logBiometricEvent(challenge.UserID, "auth_failed_no_templates", request.Type, 0, false, request.DeviceInfo, clientIP, "No enrolled templates")
		return nil, fmt.Errorf("no enrolled templates found")
	}

	// Find best match among templates
	bestMatch := &BiometricAuthResponse{
		Success:    false,
		MatchScore: 0.0,
		Confidence: 0.0,
		AuthTime:   time.Now().Unix(),
	}

	for _, template := range templates {
		// Decrypt stored template
		encryptedData := &security.EncryptedData{
			Data:      string(template.Template),
			Algorithm: "AES-256-GCM",
		}

		decryptedTemplate, err := bs.cryptoService.Decrypt(encryptedData)
		if err != nil {
			continue // Skip corrupted templates
		}

		// Compare biometric templates
		matchScore, confidence := bs.compareBiometricTemplates(processedData, decryptedTemplate, request.Type)

		// Update best match if this is better
		if matchScore > bestMatch.MatchScore {
			bestMatch.MatchScore = matchScore
			bestMatch.TemplateID = template.ID
			bestMatch.Confidence = confidence
		}

		// Early success if threshold exceeded
		if matchScore >= challenge.RequiredThreshold {
			bestMatch.Success = true

			// Update template usage
			template.LastUsedAt = time.Now()
			template.FailureCount = 0 // Reset failure count on success
			bs.db.Save(&template)

			break
		}
	}

	// Mark challenge as used
	challenge.Used = true
	delete(bs.challenges, request.ChallengeID)

	// Handle failed authentication
	if !bestMatch.Success {
		// Increment failure count for all templates of this type
		bs.db.Model(&BiometricTemplate{}).
			Where("user_id = ? AND type = ? AND active = true", challenge.UserID, request.Type).
			Update("failure_count", gorm.Expr("failure_count + 1"))

		// Disable templates with too many failures
		bs.db.Model(&BiometricTemplate{}).
			Where("user_id = ? AND type = ? AND failure_count >= 10", challenge.UserID, request.Type).
			Update("active", false)

		bs.logBiometricEvent(challenge.UserID, "auth_failed_no_match", request.Type, bestMatch.MatchScore, false, request.DeviceInfo, clientIP, fmt.Sprintf("Best match: %.2f", bestMatch.MatchScore))

		return bestMatch, fmt.Errorf("biometric authentication failed")
	}

	// Log successful authentication
	bs.logBiometricEvent(challenge.UserID, "auth_success", request.Type, bestMatch.MatchScore, true, request.DeviceInfo, clientIP, fmt.Sprintf("Template: %s", bestMatch.TemplateID))

	return bestMatch, nil
}

// GetUserBiometrics returns all biometric templates for a user
func (bs *BiometricService) GetUserBiometrics(userID uuid.UUID) ([]BiometricTemplate, error) {
	var templates []BiometricTemplate
	if err := bs.db.Where("user_id = ?", userID).Find(&templates).Error; err != nil {
		return nil, fmt.Errorf("failed to get biometric templates: %w", err)
	}

	// Remove sensitive template data from response
	for i := range templates {
		templates[i].Template = nil
		templates[i].Hash = ""
	}

	return templates, nil
}

// DeleteBiometric removes a biometric template
func (bs *BiometricService) DeleteBiometric(userID uuid.UUID, templateID string, clientIP, userAgent string) error {
	var template BiometricTemplate
	if err := bs.db.Where("id = ? AND user_id = ?", templateID, userID).First(&template).Error; err != nil {
		return fmt.Errorf("template not found: %w", err)
	}

	// Delete from database
	if err := bs.db.Delete(&template).Error; err != nil {
		return fmt.Errorf("failed to delete template: %w", err)
	}

	// Remove from cache
	bs.removeCachedTemplate(userID, templateID)

	// Log deletion
	bs.logBiometricEvent(userID, "template_deleted", template.Type, 0, true, "", clientIP, fmt.Sprintf("Template: %s", templateID))

	return nil
}

// UpdateBiometricName updates the name of a biometric template
func (bs *BiometricService) UpdateBiometricName(userID uuid.UUID, templateID, newName string) error {
	result := bs.db.Model(&BiometricTemplate{}).
		Where("id = ? AND user_id = ?", templateID, userID).
		Update("name", newName)

	if result.Error != nil {
		return fmt.Errorf("failed to update template name: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("template not found")
	}

	return nil
}

// GetBiometricStats returns statistics for a user's biometric authentication
func (bs *BiometricService) GetBiometricStats(userID uuid.UUID) (*BiometricStats, error) {
	var totalCount, activeCount int64

	// Get total templates
	bs.db.Model(&BiometricTemplate{}).Where("user_id = ?", userID).Count(&totalCount)

	// Get active templates
	bs.db.Model(&BiometricTemplate{}).Where("user_id = ? AND active = true", userID).Count(&activeCount)

	// Get recent authentication stats (simplified)
	stats := &BiometricStats{
		TotalTemplates:    int(totalCount),
		ActiveTemplates:   int(activeCount),
		SuccessRate:       85.5, // In production, calculate from audit logs
		AverageMatchScore: 92.3, // In production, calculate from recent auths
		LastAuthTime:      time.Now().Unix(),
	}

	return stats, nil
}

// Helper methods

func (bs *BiometricService) isValidBiometricType(biometricType string) bool {
	validTypes := map[string]bool{
		"fingerprint": true,
		"face":        true,
		"voice":       true,
		"iris":        true,
		"palm":        true,
	}
	return validTypes[biometricType]
}

func (bs *BiometricService) getMinQualityThreshold(biometricType string) float64 {
	thresholds := map[string]float64{
		"fingerprint": 75.0,
		"face":        70.0,
		"voice":       65.0,
		"iris":        85.0,
		"palm":        70.0,
	}
	if threshold, exists := thresholds[biometricType]; exists {
		return threshold
	}
	return 70.0 // Default threshold
}

func (bs *BiometricService) getMatchThreshold(biometricType string) float64 {
	thresholds := map[string]float64{
		"fingerprint": 85.0,
		"face":        80.0,
		"voice":       75.0,
		"iris":        90.0,
		"palm":        80.0,
	}
	if threshold, exists := thresholds[biometricType]; exists {
		return threshold
	}
	return 80.0 // Default threshold
}

func (bs *BiometricService) processBiometricData(data []byte, biometricType string) ([]byte, error) {
	// In a real implementation, this would use specialized biometric SDKs
	// to extract features from raw biometric data

	if len(data) == 0 {
		return nil, fmt.Errorf("empty biometric data")
	}

	// Simulate feature extraction and template creation
	switch biometricType {
	case "fingerprint":
		return bs.processFingerprint(data)
	case "face":
		return bs.processFace(data)
	case "voice":
		return bs.processVoice(data)
	case "iris":
		return bs.processIris(data)
	case "palm":
		return bs.processPalm(data)
	default:
		return nil, fmt.Errorf("unsupported biometric type: %s", biometricType)
	}
}

func (bs *BiometricService) processFingerprint(data []byte) ([]byte, error) {
	// Simulate fingerprint minutiae extraction
	// In production, use a real fingerprint SDK
	hasher := sha256.New()
	hasher.Write(data)
	hasher.Write([]byte("fingerprint-features"))
	return hasher.Sum(nil), nil
}

func (bs *BiometricService) processFace(data []byte) ([]byte, error) {
	// Simulate face feature extraction
	// In production, use a real face recognition SDK
	hasher := sha256.New()
	hasher.Write(data)
	hasher.Write([]byte("face-features"))
	return hasher.Sum(nil), nil
}

func (bs *BiometricService) processVoice(data []byte) ([]byte, error) {
	// Simulate voice print extraction
	// In production, use a real voice recognition SDK
	hasher := sha256.New()
	hasher.Write(data)
	hasher.Write([]byte("voice-features"))
	return hasher.Sum(nil), nil
}

func (bs *BiometricService) processIris(data []byte) ([]byte, error) {
	// Simulate iris pattern extraction
	hasher := sha256.New()
	hasher.Write(data)
	hasher.Write([]byte("iris-features"))
	return hasher.Sum(nil), nil
}

func (bs *BiometricService) processPalm(data []byte) ([]byte, error) {
	// Simulate palm print extraction
	hasher := sha256.New()
	hasher.Write(data)
	hasher.Write([]byte("palm-features"))
	return hasher.Sum(nil), nil
}

func (bs *BiometricService) generateTemplateHash(template []byte) string {
	hasher := sha256.New()
	hasher.Write(template)
	return hex.EncodeToString(hasher.Sum(nil))
}

func (bs *BiometricService) compareBiometricTemplates(template1, template2 []byte, biometricType string) (float64, float64) {
	// In a real implementation, this would use specialized comparison algorithms
	// For now, simulate matching with a distance calculation

	if len(template1) != len(template2) {
		return 0.0, 0.0
	}

	// Calculate Hamming distance
	differences := 0
	for i := range template1 {
		if template1[i] != template2[i] {
			differences++
		}
	}

	// Convert to match score (higher is better)
	similarity := float64(len(template1)-differences) / float64(len(template1))
	matchScore := similarity * 100.0

	// Calculate confidence based on template quality and match score
	confidence := matchScore * 0.9 // Simplified confidence calculation

	return matchScore, confidence
}

func (bs *BiometricService) cacheTemplate(userID uuid.UUID, template *BiometricTemplate) {
	if bs.templates[userID] == nil {
		bs.templates[userID] = make([]*BiometricTemplate, 0)
	}
	bs.templates[userID] = append(bs.templates[userID], template)
}

func (bs *BiometricService) removeCachedTemplate(userID uuid.UUID, templateID string) {
	if templates, exists := bs.templates[userID]; exists {
		for i, template := range templates {
			if template.ID == templateID {
				bs.templates[userID] = append(templates[:i], templates[i+1:]...)
				break
			}
		}
	}
}

func (bs *BiometricService) logBiometricEvent(userID uuid.UUID, eventType, biometricType string, matchScore float64, success bool, deviceInfo, clientIP, details string) {
	// Log to audit service
	bs.auditService.LogEvent(userID, eventType, "biometric", "", success, map[string]interface{}{
		"biometric_type": biometricType,
		"match_score":    matchScore,
		"device_info":    deviceInfo,
		"details":        details,
	}, clientIP, deviceInfo)
}

func (bs *BiometricService) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bs.cleanupExpiredChallenges()
		}
	}
}

func (bs *BiometricService) cleanupExpiredChallenges() {
	now := time.Now()
	for id, challenge := range bs.challenges {
		if now.After(challenge.ExpiresAt) {
			delete(bs.challenges, id)
		}
	}
}
