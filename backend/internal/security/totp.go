package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"time"

	"securevault/internal/config"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"
)

// MFAService handles comprehensive Multi-Factor Authentication operations
type MFAService struct {
	config      *config.Config
	cryptoSvc   *CryptoService
}

// MFAMethod represents different MFA methods
type MFAMethod string

const (
	MFAMethodTOTP      MFAMethod = "totp"
	MFAMethodFIDO2     MFAMethod = "fido2"
	MFAMethodBiometric MFAMethod = "biometric"
	MFAMethodSMS       MFAMethod = "sms"
	MFAMethodEmail     MFAMethod = "email"
	MFAMethodBackup    MFAMethod = "backup"
)

// MFAStatus represents MFA verification status
type MFAStatus string

const (
	MFAStatusPending   MFAStatus = "pending"
	MFAStatusVerified  MFAStatus = "verified"
	MFAStatusFailed    MFAStatus = "failed"
	MFAStatusExpired   MFAStatus = "expired"
	MFAStatusLocked    MFAStatus = "locked"
)

// TOTPSetup contains TOTP setup information
type TOTPSetup struct {
	Secret         string             `json:"secret"`
	QRCode         string             `json:"qr_code"`
	URL            string             `json:"url"`
	BackupCodes    []string           `json:"backup_codes"`
	RecoveryCodes  []string           `json:"recovery_codes"`
	SetupComplete  bool               `json:"setup_complete"`
	Method         MFAMethod          `json:"method"`
	CreatedAt      time.Time          `json:"created_at"`
	LastUsed       *time.Time         `json:"last_used,omitempty"`
	FailureCount   int                `json:"failure_count"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// FIDO2Setup contains FIDO2/WebAuthn setup information
type FIDO2Setup struct {
	Challenge       string            `json:"challenge"`
	UserID          string            `json:"user_id"`
	UserDisplayName string            `json:"user_display_name"`
	CredentialID    string            `json:"credential_id,omitempty"`
	PublicKey       string            `json:"public_key,omitempty"`
	AttestationData []byte            `json:"attestation_data,omitempty"`
	Counter         uint32            `json:"counter"`
	Transports      []string          `json:"transports"`
	AAGUID          string            `json:"aaguid,omitempty"`
	SetupComplete   bool              `json:"setup_complete"`
	Method          MFAMethod         `json:"method"`
	CreatedAt       time.Time         `json:"created_at"`
	LastUsed        *time.Time        `json:"last_used,omitempty"`
	FailureCount    int               `json:"failure_count"`
	DeviceInfo      map[string]string `json:"device_info,omitempty"`
}

// BiometricSetup contains biometric authentication setup
type BiometricSetup struct {
	BiometricType   string            `json:"biometric_type"` // fingerprint, face, voice, iris
	TemplateHash    string            `json:"template_hash"`
	DeviceID        string            `json:"device_id"`
	Challenge       string            `json:"challenge"`
	PublicKey       string            `json:"public_key"`
	EncryptedData   string            `json:"encrypted_data"`
	SetupComplete   bool              `json:"setup_complete"`
	Method          MFAMethod         `json:"method"`
	CreatedAt       time.Time         `json:"created_at"`
	LastUsed        *time.Time        `json:"last_used,omitempty"`
	FailureCount    int               `json:"failure_count"`
	DeviceInfo      map[string]string `json:"device_info,omitempty"`
	QualityScore    float64           `json:"quality_score"`
}

// SMSSetup contains SMS authentication setup
type SMSSetup struct {
	PhoneNumber     string            `json:"phone_number"`
	CountryCode     string            `json:"country_code"`
	PhoneHash       string            `json:"phone_hash"`
	VerificationCode string           `json:"verification_code,omitempty"`
	CodeExpiry      *time.Time        `json:"code_expiry,omitempty"`
	SetupComplete   bool              `json:"setup_complete"`
	Method          MFAMethod         `json:"method"`
	CreatedAt       time.Time         `json:"created_at"`
	LastUsed        *time.Time        `json:"last_used,omitempty"`
	FailureCount    int               `json:"failure_count"`
	Provider        string            `json:"provider"` // twilio, aws, etc
	RateLimitCount  int               `json:"rate_limit_count"`
	LastSentAt      *time.Time        `json:"last_sent_at,omitempty"`
}

// MFAChallenge represents an MFA challenge
type MFAChallenge struct {
	ID              string                 `json:"id"`
	UserID          string                 `json:"user_id"`
	Method          MFAMethod              `json:"method"`
	Challenge       string                 `json:"challenge"`
	ExpiresAt       time.Time              `json:"expires_at"`
	Status          MFAStatus              `json:"status"`
	AttemptCount    int                    `json:"attempt_count"`
	MaxAttempts     int                    `json:"max_attempts"`
	CreatedAt       time.Time              `json:"created_at"`
	VerifiedAt      *time.Time             `json:"verified_at,omitempty"`
	IPAddress       string                 `json:"ip_address"`
	UserAgent       string                 `json:"user_agent"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	SecurityContext SecurityContext        `json:"security_context"`
}

// SecurityContext provides additional security information
type SecurityContext struct {
	RiskScore       float64           `json:"risk_score"`
	GeolocationData map[string]string `json:"geolocation_data,omitempty"`
	DeviceFingerprint string          `json:"device_fingerprint"`
	ThreatLevel     string            `json:"threat_level"` // low, medium, high, critical
	RequireStepUp   bool              `json:"require_step_up"`
	SessionID       string            `json:"session_id"`
}

// MFAConfiguration holds user's MFA settings
type MFAConfiguration struct {
	UserID           string                 `json:"user_id"`
	EnabledMethods   []MFAMethod            `json:"enabled_methods"`
	PrimaryMethod    MFAMethod              `json:"primary_method"`
	BackupMethods    []MFAMethod            `json:"backup_methods"`
	RequiredMethods  int                    `json:"required_methods"` // For step-up authentication
	GracePeriod      time.Duration          `json:"grace_period"`
	LastUpdate       time.Time              `json:"last_update"`
	EnforcementLevel string                 `json:"enforcement_level"` // optional, required, strict
	TrustedDevices   []TrustedDevice        `json:"trusted_devices,omitempty"`
	Settings         map[string]interface{} `json:"settings,omitempty"`
}

// TrustedDevice represents a device that bypasses MFA temporarily
type TrustedDevice struct {
	DeviceID        string            `json:"device_id"`
	DeviceFingerprint string          `json:"device_fingerprint"`
	DeviceName      string            `json:"device_name"`
	TrustedAt       time.Time         `json:"trusted_at"`
	ExpiresAt       time.Time         `json:"expires_at"`
	LastUsed        time.Time         `json:"last_used"`
	IPAddress       string            `json:"ip_address"`
	UserAgent       string            `json:"user_agent"`
	Location        map[string]string `json:"location,omitempty"`
}

// TOTPService handles Time-based One-Time Password operations
type TOTPService struct {
	config *config.Config
}

// NewMFAService creates a new comprehensive MFA service
func NewMFAService(cfg *config.Config, cryptoSvc *CryptoService) *MFAService {
	return &MFAService{
		config:    cfg,
		cryptoSvc: cryptoSvc,
	}
}

// NewTOTPService creates a new TOTP service
func NewTOTPService(cfg *config.Config) *TOTPService {
	return &TOTPService{
		config: cfg,
	}
}

// GenerateSecret generates a new TOTP secret for a user
func (ts *TOTPService) GenerateSecret(userEmail string) (*TOTPSetup, error) {
	// Generate random secret
	secret := make([]byte, ts.config.MFA.TOTPKeySize)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	// Encode secret as base32
	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	// Generate TOTP key
	key, err := otp.NewKeyFromURL(ts.generateTOTPURL(userEmail, secretBase32))
	if err != nil {
		return nil, fmt.Errorf("failed to create TOTP key: %w", err)
	}

	// Generate QR code (base64 encoded PNG)
	qrCode, err := ts.generateQRCode(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code: %w", err)
	}

	// Generate backup codes
	backupCodes, err := ts.generateBackupCodes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	return &TOTPSetup{
		Secret:      secretBase32,
		QRCode:      qrCode,
		URL:         key.URL(),
		BackupCodes: backupCodes,
	}, nil
}

// ValidateToken validates a TOTP token
func (ts *TOTPService) ValidateToken(secret, token string) bool {
	return totp.Validate(token, secret)
}

// ValidateTokenWithWindow validates a TOTP token with time window
func (ts *TOTPService) ValidateTokenWithWindow(secret, token string, window int) bool {
	// Check current time
	if totp.Validate(token, secret) {
		return true
	}

	// Check previous and next periods within window
	for i := 1; i <= window; i++ {
		// Check previous periods
		pastTime := time.Now().Add(-time.Duration(i) * 30 * time.Second)
		if pastToken, err := totp.GenerateCode(secret, pastTime); err == nil && pastToken == token {
			return true
		}

		// Check future periods
		futureTime := time.Now().Add(time.Duration(i) * 30 * time.Second)
		if futureToken, err := totp.GenerateCode(secret, futureTime); err == nil && futureToken == token {
			return true
		}
	}

	return false
}

// generateTOTPURL generates a TOTP URL for QR code
func (ts *TOTPService) generateTOTPURL(userEmail, secret string) string {
	issuer := ts.config.MFA.TOTPIssuer
	accountName := fmt.Sprintf("%s:%s", issuer, userEmail)

	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", issuer)
	params.Set("algorithm", "SHA1")
	params.Set("digits", "6")
	params.Set("period", "30")

	return fmt.Sprintf("otpauth://totp/%s?%s", url.QueryEscape(accountName), params.Encode())
}

// generateQRCode generates a QR code for TOTP setup
func (ts *TOTPService) generateQRCode(key *otp.Key) (string, error) {
	// In a real implementation, use a QR code library like:
	// github.com/skip2/go-qrcode

	// For now, return a placeholder base64 image
	// This should be replaced with actual QR code generation
	placeholder := "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
	return placeholder, nil
}

// generateBackupCodes generates backup codes for account recovery
func (ts *TOTPService) generateBackupCodes() ([]string, error) {
	codes := make([]string, 10) // Generate 10 backup codes

	for i := 0; i < 10; i++ {
		// Generate 8-character alphanumeric code
		bytes := make([]byte, 6)
		if _, err := rand.Read(bytes); err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}

		// Convert to base32 and format
		code := base32.StdEncoding.EncodeToString(bytes)[:8]
		codes[i] = fmt.Sprintf("%s-%s", code[:4], code[4:])
	}

	return codes, nil
}

// GenerateCurrentToken generates the current TOTP token (for testing)
func (ts *TOTPService) GenerateCurrentToken(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}

// GetTimeRemaining returns seconds until next TOTP period
func (ts *TOTPService) GetTimeRemaining() int64 {
	return 30 - (time.Now().Unix() % 30)
}

// ValidateBackupCode validates a backup code
func (ts *TOTPService) ValidateBackupCode(code string, hashedCodes []string) (bool, string) {
	// In a real implementation, backup codes should be hashed
	// and this function should hash the provided code and compare

	for i, hashedCode := range hashedCodes {
		// Simplified comparison - in production, use proper hashing
		if hashedCode == code {
			return true, fmt.Sprintf("backup_code_%d", i)
		}
	}

	return false, ""
}

// HashBackupCode hashes a backup code for storage
func (ts *TOTPService) HashBackupCode(code string) (string, error) {
	// Use Argon2id for secure backup code hashing
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	
	hash := argon2.IDKey([]byte(code), salt, 1, 64*1024, 4, 32)
	hashWithSalt := append(salt, hash...)
	return base64.StdEncoding.EncodeToString(hashWithSalt), nil
}

// ========== COMPREHENSIVE MFA SERVICE IMPLEMENTATION ==========

// SetupTOTP sets up TOTP authentication for a user
func (mfa *MFAService) SetupTOTP(userID, userEmail string) (*TOTPSetup, error) {
	secret := make([]byte, 32) // 256-bit secret
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("không thể tạo mã bí mật: %w", err)
	}

	secretBase32 := base32.StdEncoding.EncodeToString(secret)
	
	// Generate Vietnamese-friendly backup codes
	backupCodes, err := mfa.generateSecureBackupCodes()
	if err != nil {
		return nil, fmt.Errorf("không thể tạo mã sao lưu: %w", err)
	}

	recoveryCodes, err := mfa.generateRecoveryCodes()
	if err != nil {
		return nil, fmt.Errorf("không thể tạo mã khôi phục: %w", err)
	}

	// Generate QR code with Vietnamese labels
	qrCode, url, err := mfa.generateTOTPQRCode(userEmail, secretBase32)
	if err != nil {
		return nil, fmt.Errorf("không thể tạo mã QR: %w", err)
	}

	return &TOTPSetup{
		Secret:        secretBase32,
		QRCode:        qrCode,
		URL:           url,
		BackupCodes:   backupCodes,
		RecoveryCodes: recoveryCodes,
		SetupComplete: false,
		Method:        MFAMethodTOTP,
		CreatedAt:     time.Now(),
		FailureCount:  0,
		Metadata: map[string]interface{}{
			"language":      "vi",
			"setup_version": "2.0",
			"issuer":        "SecureVault",
		},
	}, nil
}

// SetupFIDO2 sets up FIDO2/WebAuthn authentication
func (mfa *MFAService) SetupFIDO2(userID, userDisplayName string, deviceInfo map[string]string) (*FIDO2Setup, error) {
	// Generate cryptographic challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("không thể tạo thử thách: %w", err)
	}
	
	challengeB64 := base64.URLEncoding.EncodeToString(challenge)
	
	// Generate user handle (optional but recommended)
	userHandle := make([]byte, 32)
	if _, err := rand.Read(userHandle); err != nil {
		return nil, fmt.Errorf("không thể tạo user handle: %w", err)
	}

	return &FIDO2Setup{
		Challenge:       challengeB64,
		UserID:          userID,
		UserDisplayName: userDisplayName,
		Counter:         0,
		Transports:      []string{"usb", "nfc", "ble", "internal"},
		SetupComplete:   false,
		Method:          MFAMethodFIDO2,
		CreatedAt:       time.Now(),
		FailureCount:    0,
		DeviceInfo:      deviceInfo,
	}, nil
}

// VerifyFIDO2Registration verifies FIDO2 registration
func (mfa *MFAService) VerifyFIDO2Registration(setup *FIDO2Setup, attestationResponse map[string]interface{}) error {
	// In production, use a proper WebAuthn library like github.com/duo-labs/webauthn
	// This is a simplified verification for demonstration
	
	if clientDataJSON, ok := attestationResponse["clientDataJSON"].(string); ok {
		// Verify challenge matches
		clientData, err := base64.URLEncoding.DecodeString(clientDataJSON)
		if err != nil {
			return fmt.Errorf("dữ liệu client không hợp lệ: %w", err)
		}
		
		var clientDataObj map[string]interface{}
		if err := json.Unmarshal(clientData, &clientDataObj); err != nil {
			return fmt.Errorf("không thể phân tích dữ liệu client: %w", err)
		}
		
		if clientDataObj["challenge"] != setup.Challenge {
			return fmt.Errorf("thử thách không khớp")
		}
	}
	
	// Extract and store credential information
	if credID, ok := attestationResponse["credentialId"].(string); ok {
		setup.CredentialID = credID
	}
	
	if pubKey, ok := attestationResponse["publicKey"].(string); ok {
		setup.PublicKey = pubKey
	}
	
	setup.SetupComplete = true
	return nil
}

// SetupBiometric sets up biometric authentication
func (mfa *MFAService) SetupBiometric(userID, biometricType, deviceID string, templateData []byte, deviceInfo map[string]string) (*BiometricSetup, error) {
	// Validate biometric type
	validTypes := map[string]bool{
		"fingerprint": true,
		"face":        true,
		"voice":       true,
		"iris":        true,
	}
	
	if !validTypes[biometricType] {
		return nil, fmt.Errorf("loại sinh trắc học không được hỗ trợ: %s", biometricType)
	}

	// Generate secure challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("không thể tạo thử thách: %w", err)
	}

	// Hash biometric template (never store raw biometric data)
	templateHash := mfa.hashBiometricTemplate(templateData, deviceID)
	
	// Generate device-specific key pair
	publicKey, privateKey, err := mfa.generateBiometricKeyPair()
	if err != nil {
		return nil, fmt.Errorf("không thể tạo cặp khóa: %w", err)
	}

	// Encrypt sensitive data with device key
	encryptedData, err := mfa.encryptBiometricData(templateData, privateKey)
	if err != nil {
		return nil, fmt.Errorf("không thể mã hóa dữ liệu sinh trắc học: %w", err)
	}

	// Calculate quality score
	qualityScore := mfa.calculateBiometricQuality(templateData, biometricType)

	return &BiometricSetup{
		BiometricType: biometricType,
		TemplateHash:  templateHash,
		DeviceID:      deviceID,
		Challenge:     base64.URLEncoding.EncodeToString(challenge),
		PublicKey:     publicKey,
		EncryptedData: encryptedData,
		SetupComplete: true,
		Method:        MFAMethodBiometric,
		CreatedAt:     time.Now(),
		FailureCount:  0,
		DeviceInfo:    deviceInfo,
		QualityScore:  qualityScore,
	}, nil
}

// SetupSMS sets up SMS authentication
func (mfa *MFAService) SetupSMS(userID, phoneNumber, countryCode string) (*SMSSetup, error) {
	// Validate phone number format
	if !mfa.validatePhoneNumber(phoneNumber, countryCode) {
		return nil, fmt.Errorf("số điện thoại không hợp lệ")
	}

	// Hash phone number for privacy
	phoneHash := mfa.hashPhoneNumber(phoneNumber, countryCode)
	
	// Generate verification code
	verificationCode := mfa.generateSMSCode()
	codeExpiry := time.Now().Add(5 * time.Minute) // 5 minute expiry

	return &SMSSetup{
		PhoneNumber:     mfa.maskPhoneNumber(phoneNumber),
		CountryCode:     countryCode,
		PhoneHash:       phoneHash,
		VerificationCode: verificationCode,
		CodeExpiry:      &codeExpiry,
		SetupComplete:   false,
		Method:          MFAMethodSMS,
		CreatedAt:       time.Now(),
		FailureCount:    0,
		Provider:        "internal", // Could be Twilio, AWS SNS, etc.
		RateLimitCount:  0,
	}, nil
}

// CreateChallenge creates a new MFA challenge
func (mfa *MFAService) CreateChallenge(userID string, method MFAMethod, securityContext SecurityContext) (*MFAChallenge, error) {
	challengeID := mfa.generateChallengeID()
	
	// Generate method-specific challenge
	challenge, err := mfa.generateMethodChallenge(method)
	if err != nil {
		return nil, fmt.Errorf("không thể tạo thử thách: %w", err)
	}

	// Set expiry based on method
	expiryDuration := mfa.getChallengeExpiry(method)
	expiresAt := time.Now().Add(expiryDuration)

	// Determine max attempts based on security level
	maxAttempts := mfa.getMaxAttempts(method, securityContext.ThreatLevel)

	return &MFAChallenge{
		ID:              challengeID,
		UserID:          userID,
		Method:          method,
		Challenge:       challenge,
		ExpiresAt:       expiresAt,
		Status:          MFAStatusPending,
		AttemptCount:    0,
		MaxAttempts:     maxAttempts,
		CreatedAt:       time.Now(),
		IPAddress:       securityContext.GeolocationData["ip"],
		UserAgent:       securityContext.GeolocationData["user_agent"],
		SecurityContext: securityContext,
		Metadata: map[string]interface{}{
			"language":     "vi",
			"created_by":   "mfa_service",
			"version":      "2.0",
		},
	}, nil
}

// VerifyChallenge verifies an MFA challenge response
func (mfa *MFAService) VerifyChallenge(challengeID, userID, response string) (*MFAChallenge, error) {
	// This would typically load from database
	// For now, simulate challenge verification
	
	challenge := &MFAChallenge{
		ID:           challengeID,
		UserID:       userID,
		AttemptCount: 0,
		MaxAttempts:  3,
		Status:       MFAStatusPending,
	}

	// Increment attempt count
	challenge.AttemptCount++

	// Check if challenge is expired
	if time.Now().After(challenge.ExpiresAt) {
		challenge.Status = MFAStatusExpired
		return challenge, fmt.Errorf("thử thách đã hết hạn")
	}

	// Check if max attempts exceeded
	if challenge.AttemptCount >= challenge.MaxAttempts {
		challenge.Status = MFAStatusLocked
		return challenge, fmt.Errorf("đã vượt quá số lần thử tối đa")
	}

	// Verify response based on method
	verified, err := mfa.verifyMethodResponse(challenge.Method, challenge.Challenge, response)
	if err != nil {
		challenge.Status = MFAStatusFailed
		return challenge, fmt.Errorf("xác minh thất bại: %w", err)
	}

	if verified {
		challenge.Status = MFAStatusVerified
		now := time.Now()
		challenge.VerifiedAt = &now
	} else {
		challenge.Status = MFAStatusFailed
	}

	return challenge, nil
}

// ========== HELPER METHODS ==========

// generateSecureBackupCodes generates cryptographically secure backup codes
func (mfa *MFAService) generateSecureBackupCodes() ([]string, error) {
	codes := make([]string, 10) // Generate 10 backup codes
	
	for i := 0; i < 10; i++ {
		// Generate 8 characters using secure random
		bytes := make([]byte, 6)
		if _, err := rand.Read(bytes); err != nil {
			return nil, fmt.Errorf("không thể tạo mã sao lưu: %w", err)
		}
		
		// Convert to alphanumeric format
		code := base32.StdEncoding.EncodeToString(bytes)[:8]
		// Format as XXXX-XXXX for better readability
		codes[i] = fmt.Sprintf("%s-%s", code[:4], code[4:])
	}
	
	return codes, nil
}

// generateRecoveryCodes generates master recovery codes
func (mfa *MFAService) generateRecoveryCodes() ([]string, error) {
	codes := make([]string, 3) // Generate 3 recovery codes (more secure)
	
	for i := 0; i < 3; i++ {
		// Generate 16-character recovery code
		bytes := make([]byte, 12)
		if _, err := rand.Read(bytes); err != nil {
			return nil, fmt.Errorf("không thể tạo mã khôi phục: %w", err)
		}
		
		code := base32.StdEncoding.EncodeToString(bytes)[:16]
		// Format as XXXX-XXXX-XXXX-XXXX
		codes[i] = fmt.Sprintf("%s-%s-%s-%s", code[:4], code[4:8], code[8:12], code[12:])
	}
	
	return codes, nil
}

// generateTOTPQRCode generates QR code for TOTP setup
func (mfa *MFAService) generateTOTPQRCode(userEmail, secret string) (string, string, error) {
	issuer := "SecureVault"
	accountName := fmt.Sprintf("%s (%s)", userEmail, issuer)
	
	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", issuer)
	params.Set("algorithm", "SHA256") // Use SHA256 instead of SHA1
	params.Set("digits", "6")
	params.Set("period", "30")
	
	totpURL := fmt.Sprintf("otpauth://totp/%s?%s", url.QueryEscape(accountName), params.Encode())
	
	// In production, use github.com/skip2/go-qrcode to generate actual QR codes
	qrCodeB64 := mfa.generateQRCodeImage(totpURL)
	
	return qrCodeB64, totpURL, nil
}

// generateQRCodeImage generates base64 encoded QR code image
func (mfa *MFAService) generateQRCodeImage(data string) string {
	// Placeholder implementation - in production use proper QR code library
	return "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
}

// hashBiometricTemplate creates a secure hash of biometric template
func (mfa *MFAService) hashBiometricTemplate(templateData []byte, deviceID string) string {
	h := hmac.New(sha256.New, []byte(deviceID))
	h.Write(templateData)
	hash := h.Sum(nil)
	return base64.URLEncoding.EncodeToString(hash)
}

// generateBiometricKeyPair generates cryptographic key pair for biometric data
func (mfa *MFAService) generateBiometricKeyPair() (string, string, error) {
	// Simplified implementation - in production use proper elliptic curve cryptography
	publicKey := make([]byte, 32)
	privateKey := make([]byte, 32)
	
	if _, err := rand.Read(publicKey); err != nil {
		return "", "", err
	}
	if _, err := rand.Read(privateKey); err != nil {
		return "", "", err
	}
	
	return base64.URLEncoding.EncodeToString(publicKey),
		   base64.URLEncoding.EncodeToString(privateKey), nil
}

// encryptBiometricData encrypts biometric template data
func (mfa *MFAService) encryptBiometricData(data []byte, key string) (string, error) {
	// Use crypto service for encryption
	keyBytes, err := base64.URLEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	
	encrypted, err := mfa.cryptoSvc.Encrypt(data, string(keyBytes))
	if err != nil {
		return "", err
	}
	
	return base64.URLEncoding.EncodeToString([]byte(encrypted.Data)), nil
}

// calculateBiometricQuality calculates quality score of biometric data
func (mfa *MFAService) calculateBiometricQuality(templateData []byte, biometricType string) float64 {
	// Simplified quality calculation based on data size and entropy
	if len(templateData) < 100 {
		return 0.3 // Low quality
	}
	
	// Calculate basic entropy
	entropy := mfa.calculateEntropy(templateData)
	qualityScore := entropy / 8.0 // Normalize to 0-1
	
	// Adjust based on biometric type
	switch biometricType {
	case "fingerprint":
		qualityScore *= 0.95
	case "face":
		qualityScore *= 0.85
	case "iris":
		qualityScore *= 0.98
	case "voice":
		qualityScore *= 0.75
	}
	
	if qualityScore > 1.0 {
		qualityScore = 1.0
	}
	
	return qualityScore
}

// calculateEntropy calculates Shannon entropy of data
func (mfa *MFAService) calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}
	
	var entropy float64
	length := float64(len(data))
	
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * (math.Log2(p))
		}
	}
	
	return entropy
}

// validatePhoneNumber validates phone number format
func (mfa *MFAService) validatePhoneNumber(phoneNumber, countryCode string) bool {
	// Basic validation - in production use proper phone number validation library
	phoneRegex := regexp.MustCompile(`^[\+]?[0-9\-\s\(\)]{10,15}$`)
	return phoneRegex.MatchString(phoneNumber)
}

// hashPhoneNumber creates privacy-preserving hash of phone number
func (mfa *MFAService) hashPhoneNumber(phoneNumber, countryCode string) string {
	combined := countryCode + phoneNumber
	h := sha256.New()
	h.Write([]byte(combined))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

// maskPhoneNumber masks phone number for display
func (mfa *MFAService) maskPhoneNumber(phoneNumber string) string {
	if len(phoneNumber) < 4 {
		return "***"
	}
	
	return phoneNumber[:2] + strings.Repeat("*", len(phoneNumber)-4) + phoneNumber[len(phoneNumber)-2:]
}

// generateSMSCode generates 6-digit SMS verification code
func (mfa *MFAService) generateSMSCode() string {
	// Generate cryptographically secure 6-digit code
	max := big.NewInt(1000000)
	n, _ := rand.Int(rand.Reader, max)
	return fmt.Sprintf("%06d", n.Int64())
}

// generateChallengeID generates unique challenge ID
func (mfa *MFAService) generateChallengeID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// generateMethodChallenge generates method-specific challenge
func (mfa *MFAService) generateMethodChallenge(method MFAMethod) (string, error) {
	switch method {
	case MFAMethodTOTP:
		return "totp-challenge", nil
	case MFAMethodFIDO2:
		challenge := make([]byte, 32)
		if _, err := rand.Read(challenge); err != nil {
			return "", err
		}
		return base64.URLEncoding.EncodeToString(challenge), nil
	case MFAMethodBiometric:
		challenge := make([]byte, 32)
		if _, err := rand.Read(challenge); err != nil {
			return "", err
		}
		return base64.URLEncoding.EncodeToString(challenge), nil
	case MFAMethodSMS:
		return mfa.generateSMSCode(), nil
	default:
		return "", fmt.Errorf("phương thức MFA không được hỗ trợ: %s", method)
	}
}

// getChallengeExpiry returns expiry duration for challenge type
func (mfa *MFAService) getChallengeExpiry(method MFAMethod) time.Duration {
	switch method {
	case MFAMethodTOTP:
		return 5 * time.Minute
	case MFAMethodFIDO2:
		return 2 * time.Minute
	case MFAMethodBiometric:
		return 1 * time.Minute
	case MFAMethodSMS:
		return 5 * time.Minute
	default:
		return 5 * time.Minute
	}
}

// getMaxAttempts returns max attempts based on method and threat level
func (mfa *MFAService) getMaxAttempts(method MFAMethod, threatLevel string) int {
	baseAttempts := map[MFAMethod]int{
		MFAMethodTOTP:      5,
		MFAMethodFIDO2:     3,
		MFAMethodBiometric: 5,
		MFAMethodSMS:       3,
	}
	
	attempts := baseAttempts[method]
	
	// Reduce attempts for higher threat levels
	switch threatLevel {
	case "high":
		attempts = attempts / 2
	case "critical":
		attempts = 1
	}
	
	if attempts < 1 {
		attempts = 1
	}
	
	return attempts
}

// verifyMethodResponse verifies response based on method
func (mfa *MFAService) verifyMethodResponse(method MFAMethod, challenge, response string) (bool, error) {
	switch method {
	case MFAMethodTOTP:
		// Would verify TOTP token
		return len(response) == 6, nil
	case MFAMethodFIDO2:
		// Would verify WebAuthn assertion
		return len(response) > 10, nil
	case MFAMethodBiometric:
		// Would verify biometric signature
		return len(response) > 0, nil
	case MFAMethodSMS:
		// Would verify SMS code
		return challenge == response, nil
	default:
		return false, fmt.Errorf("phương thức không được hỗ trợ")
	}
}
