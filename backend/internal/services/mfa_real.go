package services

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"securevault/internal/config"
	"securevault/internal/database"
	"securevault/internal/models"
	"securevault/internal/security"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/argon2"
	"gorm.io/gorm"
)

// Real MFA Service with actual providers integration
type RealMFAService struct {
	db         *gorm.DB
	config     *config.Config
	cryptoSvc  *security.CryptoService
	auditSvc   *AuditService
	twilioSID  string
	twilioAuth string
	pushover   PushoverConfig
	email      MFAEmailConfig
}

type PushoverConfig struct {
	AppToken string
	UserKey  string
	Enabled  bool
}

type MFAEmailConfig struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	FromEmail    string
	Enabled      bool
}

// Real MFA Token storage
type MFAToken struct {
	ID        uuid.UUID              `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    uuid.UUID              `json:"user_id" gorm:"type:uuid;not null;index"`
	Method    string                 `json:"method" gorm:"not null"` // totp, sms, email, push
	Token     string                 `json:"token" gorm:"not null"`
	Used      bool                   `json:"used" gorm:"default:false"`
	ExpiresAt time.Time              `json:"expires_at" gorm:"not null"`
	CreatedAt time.Time              `json:"created_at"`
	UsedAt    *time.Time             `json:"used_at,omitempty"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Metadata  map[string]interface{} `json:"metadata" gorm:"type:jsonb"`
}

// User's MFA Settings
type UserMFASettings struct {
	ID            uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID        uuid.UUID  `json:"user_id" gorm:"type:uuid;not null;uniqueIndex"`
	TOTPSecret    string     `json:"totp_secret,omitempty" gorm:"encrypted"`
	TOTPEnabled   bool       `json:"totp_enabled" gorm:"default:false"`
	SMSEnabled    bool       `json:"sms_enabled" gorm:"default:false"`
	EmailEnabled  bool       `json:"email_enabled" gorm:"default:false"`
	PushEnabled   bool       `json:"push_enabled" gorm:"default:false"`
	PhoneNumber   string     `json:"phone_number,omitempty" gorm:"encrypted"`
	BackupCodes   []string   `json:"backup_codes" gorm:"type:jsonb;encrypted"`
	RecoveryCodes []string   `json:"recovery_codes" gorm:"type:jsonb;encrypted"`
	PrimaryMethod string     `json:"primary_method" gorm:"default:'totp'"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	LastUsed      *time.Time `json:"last_used,omitempty"`
	FailureCount  int        `json:"failure_count" gorm:"default:0"`
	LockedUntil   *time.Time `json:"locked_until,omitempty"`
}

// MFA Challenge for step-by-step verification
type MFAChallenge struct {
	ID           uuid.UUID              `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID       uuid.UUID              `json:"user_id" gorm:"type:uuid;not null;index"`
	SessionID    string                 `json:"session_id" gorm:"not null;index"`
	Method       string                 `json:"method" gorm:"not null"`
	Challenge    string                 `json:"challenge" gorm:"not null"`
	Response     string                 `json:"response,omitempty"`
	Status       string                 `json:"status" gorm:"default:'pending'"` // pending, verified, failed, expired
	AttemptCount int                    `json:"attempt_count" gorm:"default:0"`
	MaxAttempts  int                    `json:"max_attempts" gorm:"default:3"`
	ExpiresAt    time.Time              `json:"expires_at" gorm:"not null"`
	CreatedAt    time.Time              `json:"created_at"`
	VerifiedAt   *time.Time             `json:"verified_at,omitempty"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	Metadata     map[string]interface{} `json:"metadata" gorm:"type:jsonb"`
}

// SMS Provider response
type TwilioResponse struct {
	SID    string `json:"sid"`
	Status string `json:"status"`
	Body   string `json:"body"`
	To     string `json:"to"`
	From   string `json:"from"`
}

// Email template for MFA codes
const mfaEmailTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Mã xác thực SecureVault</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #2563eb; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background: #f9f9f9; }
        .code { font-size: 32px; font-weight: bold; text-align: center; 
               background: white; padding: 15px; margin: 20px 0; 
               border: 2px dashed #2563eb; border-radius: 5px; }
        .footer { text-align: center; color: #666; font-size: 12px; margin-top: 20px; }
        .warning { color: #dc2626; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 SecureVault</h1>
            <p>Mã xác thực đăng nhập</p>
        </div>
        <div class="content">
            <p>Xin chào,</p>
            <p>Mã xác thực MFA của bạn là:</p>
            <div class="code">{{.Code}}</div>
            <p><strong>Mã này sẽ hết hạn sau {{.ExpiryMinutes}} phút.</strong></p>
            <p class="warning">⚠️ Không chia sẻ mã này với bất kỳ ai!</p>
            <p>Nếu bạn không yêu cầu mã này, vui lòng liên hệ với bộ phận hỗ trợ ngay lập tức.</p>
        </div>
        <div class="footer">
            <p>SecureVault Security Team</p>
            <p>Thời gian: {{.Timestamp}}</p>
        </div>
    </div>
</body>
</html>
`

func NewRealMFAService(cfg *config.Config, cryptoSvc *security.CryptoService, auditSvc *AuditService) *RealMFAService {
	return &RealMFAService{
		db:         database.GetDB(),
		config:     cfg,
		cryptoSvc:  cryptoSvc,
		auditSvc:   auditSvc,
		twilioSID:  cfg.MFA.TwilioSID,
		twilioAuth: cfg.MFA.TwilioAuthToken,
		pushover: PushoverConfig{
			AppToken: cfg.MFA.PushoverAppToken,
			UserKey:  cfg.MFA.PushoverUserKey,
			Enabled:  cfg.MFA.PushoverEnabled,
		},
		email: MFAEmailConfig{
			SMTPHost:     cfg.MFA.SMTPHost,
			SMTPPort:     cfg.MFA.SMTPPort,
			SMTPUser:     cfg.MFA.SMTPUser,
			SMTPPassword: cfg.MFA.SMTPPassword,
			FromEmail:    cfg.MFA.FromEmail,
			Enabled:      cfg.MFA.EmailEnabled,
		},
	}
}

// ========== TOTP (Time-based One-Time Password) ==========

func (mfa *RealMFAService) SetupTOTP(userID uuid.UUID, issuer, accountName string) (*TOTPSetupResponse, error) {
	// Check if user already has TOTP enabled
	var settings UserMFASettings
	err := mfa.db.Where("user_id = ?", userID).First(&settings).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("failed to check existing TOTP: %w", err)
	}

	if err == gorm.ErrRecordNotFound {
		// Create new MFA settings
		settings = UserMFASettings{
			UserID: userID,
		}
	}

	// Generate new TOTP secret
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	secretBase32 := base32.StdEncoding.EncodeToString(secret)

	// Create TOTP key
	key, err := otp.NewKeyFromURL(fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA256&digits=6&period=30",
		url.QueryEscape(issuer),
		url.QueryEscape(accountName),
		secretBase32,
		url.QueryEscape(issuer),
	))
	if err != nil {
		return nil, fmt.Errorf("failed to create TOTP key: %w", err)
	}

	// Generate QR code
	qrCode, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code: %w", err)
	}

	// Generate backup codes
	backupCodes, err := mfa.generateSecureBackupCodes(10)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Generate recovery codes (more secure, fewer codes)
	recoveryCodes, err := mfa.generateSecureBackupCodes(5)
	if err != nil {
		return nil, fmt.Errorf("failed to generate recovery codes: %w", err)
	}

	// Encrypt and store the secret
	encryptedSecret, err := mfa.cryptoSvc.Encrypt([]byte(secretBase32), userID.String()+"_totp")
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	// Hash backup codes before storage
	hashedBackupCodes := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		hash, err := mfa.hashBackupCode(code)
		if err != nil {
			return nil, fmt.Errorf("failed to hash backup code: %w", err)
		}
		hashedBackupCodes[i] = hash
	}

	hashedRecoveryCodes := make([]string, len(recoveryCodes))
	for i, code := range recoveryCodes {
		hash, err := mfa.hashBackupCode(code)
		if err != nil {
			return nil, fmt.Errorf("failed to hash recovery code: %w", err)
		}
		hashedRecoveryCodes[i] = hash
	}

	// Update settings
	settings.TOTPSecret = encryptedSecret.Data
	settings.BackupCodes = hashedBackupCodes
	settings.RecoveryCodes = hashedRecoveryCodes

	// Save to database
	if err := mfa.db.Save(&settings).Error; err != nil {
		return nil, fmt.Errorf("failed to save MFA settings: %w", err)
	}

	// Audit log
	mfa.auditSvc.LogEvent(userID, "mfa_totp_setup", "mfa", settings.ID.String(), true,
		map[string]interface{}{
			"method": "totp",
			"issuer": issuer,
		}, "", "")

	return &TOTPSetupResponse{
		Secret:         secretBase32,
		QRCodePNG:      base64.StdEncoding.EncodeToString(qrCode),
		URL:            key.URL(),
		BackupCodes:    backupCodes, // Return plaintext to user (one time only)
		RecoveryCodes:  recoveryCodes,
		ManualEntryKey: formatSecretForManualEntry(secretBase32),
	}, nil
}

type TOTPSetupResponse struct {
	Secret         string   `json:"secret"`
	QRCodePNG      string   `json:"qr_code_png"`
	URL            string   `json:"url"`
	BackupCodes    []string `json:"backup_codes"`
	RecoveryCodes  []string `json:"recovery_codes"`
	ManualEntryKey string   `json:"manual_entry_key"`
}

func (mfa *RealMFAService) VerifyTOTPSetup(userID uuid.UUID, token string) error {
	var settings UserMFASettings
	if err := mfa.db.Where("user_id = ?", userID).First(&settings).Error; err != nil {
		return fmt.Errorf("MFA settings not found")
	}

	// Decrypt TOTP secret
	encData := &security.EncryptedData{Data: settings.TOTPSecret}
	secretBytes, err := mfa.cryptoSvc.Decrypt(encData)
	if err != nil {
		return fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	secret := string(secretBytes)

	// Verify TOTP token with time window
	if !mfa.validateTOTPWithWindow(secret, token, 1) {
		// Increment failure count
		settings.FailureCount++
		if settings.FailureCount >= 5 {
			lockUntil := time.Now().Add(30 * time.Minute)
			settings.LockedUntil = &lockUntil
		}
		mfa.db.Save(&settings)

		mfa.auditSvc.LogEvent(userID, "mfa_totp_verify_failed", "mfa", settings.ID.String(), false,
			map[string]interface{}{"failure_count": settings.FailureCount}, "", "")

		return fmt.Errorf("invalid TOTP code")
	}

	// Enable TOTP and reset failure count
	settings.TOTPEnabled = true
	settings.FailureCount = 0
	settings.LockedUntil = nil
	now := time.Now()
	settings.LastUsed = &now

	if err := mfa.db.Save(&settings).Error; err != nil {
		return fmt.Errorf("failed to enable TOTP: %w", err)
	}

	mfa.auditSvc.LogEvent(userID, "mfa_totp_enabled", "mfa", settings.ID.String(), true,
		map[string]interface{}{"method": "totp"}, "", "")

	return nil
}

// ========== SMS MFA ==========

func (mfa *RealMFAService) SetupSMS(userID uuid.UUID, phoneNumber string) error {
	// Validate phone number format
	if !mfa.validatePhoneNumber(phoneNumber) {
		return fmt.Errorf("invalid phone number format")
	}

	var settings UserMFASettings
	err := mfa.db.Where("user_id = ?", userID).First(&settings).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return fmt.Errorf("failed to get MFA settings: %w", err)
	}

	if err == gorm.ErrRecordNotFound {
		settings = UserMFASettings{UserID: userID}
	}

	// Encrypt phone number
	encryptedPhone, err := mfa.cryptoSvc.Encrypt([]byte(phoneNumber), userID.String()+"_phone")
	if err != nil {
		return fmt.Errorf("failed to encrypt phone number: %w", err)
	}

	settings.PhoneNumber = encryptedPhone.Data

	if err := mfa.db.Save(&settings).Error; err != nil {
		return fmt.Errorf("failed to save phone number: %w", err)
	}

	// Send verification SMS
	code, err := mfa.generateSMSCode()
	if err != nil {
		return fmt.Errorf("failed to generate SMS code: %w", err)
	}

	if err := mfa.sendSMS(phoneNumber, fmt.Sprintf("Mã xác thực SecureVault: %s. Mã có hiệu lực trong 5 phút.", code)); err != nil {
		return fmt.Errorf("failed to send SMS: %w", err)
	}

	// Store verification token
	token := MFAToken{
		UserID:    userID,
		Method:    "sms",
		Token:     mfa.hashToken(code),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Metadata:  map[string]interface{}{"phone": phoneNumber},
	}

	if err := mfa.db.Create(&token).Error; err != nil {
		return fmt.Errorf("failed to store SMS token: %w", err)
	}

	mfa.auditSvc.LogEvent(userID, "mfa_sms_setup", "mfa", settings.ID.String(), true,
		map[string]interface{}{
			"method":       "sms",
			"phone_masked": mfa.maskPhoneNumber(phoneNumber),
		}, "", "")

	return nil
}

func (mfa *RealMFAService) VerifySMSSetup(userID uuid.UUID, code string) error {
	// Find pending SMS token
	var token MFAToken
	err := mfa.db.Where("user_id = ? AND method = 'sms' AND used = false AND expires_at > ?",
		userID, time.Now()).Order("created_at DESC").First(&token).Error
	if err != nil {
		return fmt.Errorf("no valid SMS verification found")
	}

	// Verify code
	if !mfa.verifyHashedToken(code, token.Token) {
		return fmt.Errorf("invalid SMS code")
	}

	// Mark token as used
	now := time.Now()
	token.Used = true
	token.UsedAt = &now
	mfa.db.Save(&token)

	// Enable SMS MFA
	var settings UserMFASettings
	if err := mfa.db.Where("user_id = ?", userID).First(&settings).Error; err != nil {
		return fmt.Errorf("MFA settings not found")
	}

	settings.SMSEnabled = true
	settings.LastUsed = &now

	if err := mfa.db.Save(&settings).Error; err != nil {
		return fmt.Errorf("failed to enable SMS MFA: %w", err)
	}

	mfa.auditSvc.LogEvent(userID, "mfa_sms_enabled", "mfa", settings.ID.String(), true,
		map[string]interface{}{"method": "sms"}, "", "")

	return nil
}

// ========== Email MFA ==========

func (mfa *RealMFAService) SendEmailMFA(userID uuid.UUID, email string) error {
	code, err := mfa.generateSMSCode() // Same 6-digit format
	if err != nil {
		return fmt.Errorf("failed to generate email code: %w", err)
	}

	// Send email with code
	if err := mfa.sendMFAEmail(email, code, 5); err != nil {
		return fmt.Errorf("failed to send MFA email: %w", err)
	}

	// Store verification token
	token := MFAToken{
		UserID:    userID,
		Method:    "email",
		Token:     mfa.hashToken(code),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Metadata:  map[string]interface{}{"email": email},
	}

	if err := mfa.db.Create(&token).Error; err != nil {
		return fmt.Errorf("failed to store email token: %w", err)
	}

	mfa.auditSvc.LogEvent(userID, "mfa_email_sent", "mfa", token.ID.String(), true,
		map[string]interface{}{
			"method":       "email",
			"email_masked": mfa.maskEmail(email),
		}, "", "")

	return nil
}

// ========== Push Notification MFA ==========

func (mfa *RealMFAService) SendPushMFA(userID uuid.UUID, deviceToken, message string) error {
	if !mfa.pushover.Enabled {
		return fmt.Errorf("push notifications not configured")
	}

	// Generate push challenge
	challenge := make([]byte, 32)
	rand.Read(challenge)
	challengeStr := base64.URLEncoding.EncodeToString(challenge)

	// Send push notification
	if err := mfa.sendPushoverNotification(message + " Challenge: " + challengeStr[:8]); err != nil {
		return fmt.Errorf("failed to send push notification: %w", err)
	}

	// Store challenge
	token := MFAToken{
		UserID:    userID,
		Method:    "push",
		Token:     mfa.hashToken(challengeStr),
		ExpiresAt: time.Now().Add(2 * time.Minute), // Shorter expiry for push
		Metadata:  map[string]interface{}{"device_token": deviceToken},
	}

	if err := mfa.db.Create(&token).Error; err != nil {
		return fmt.Errorf("failed to store push token: %w", err)
	}

	return nil
}

// ========== MFA Verification During Login ==========

func (mfa *RealMFAService) CreateMFAChallenge(userID uuid.UUID, sessionID, method, ipAddress, userAgent string) (*MFAChallenge, error) {
	// Check if user has the requested MFA method enabled
	var settings UserMFASettings
	if err := mfa.db.Where("user_id = ?", userID).First(&settings).Error; err != nil {
		return nil, fmt.Errorf("user MFA settings not found")
	}

	// Check if user is locked
	if settings.LockedUntil != nil && time.Now().Before(*settings.LockedUntil) {
		return nil, fmt.Errorf("MFA locked until %v", settings.LockedUntil.Format("15:04:05"))
	}

	// Verify method is enabled
	switch method {
	case "totp":
		if !settings.TOTPEnabled {
			return nil, fmt.Errorf("TOTP not enabled for user")
		}
	case "sms":
		if !settings.SMSEnabled {
			return nil, fmt.Errorf("SMS not enabled for user")
		}
	case "email":
		if !settings.EmailEnabled {
			return nil, fmt.Errorf("Email MFA not enabled for user")
		}
	case "push":
		if !settings.PushEnabled {
			return nil, fmt.Errorf("Push notifications not enabled for user")
		}
	default:
		return nil, fmt.Errorf("unsupported MFA method: %s", method)
	}

	// Generate challenge based on method
	var challenge string

	switch method {
	case "totp":
		challenge = "totp_challenge"
	case "sms":
		// Get user's phone number and send SMS
		encData := &security.EncryptedData{Data: settings.PhoneNumber}
		phoneBytes, err := mfa.cryptoSvc.Decrypt(encData)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt phone number")
		}
		phone := string(phoneBytes)

		code, err := mfa.generateSMSCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate SMS code")
		}

		if err := mfa.sendSMS(phone, fmt.Sprintf("Mã đăng nhập SecureVault: %s", code)); err != nil {
			return nil, fmt.Errorf("failed to send SMS: %w", err)
		}

		challenge = mfa.hashToken(code)
	case "email":
		// Get user email from user record and send email
		var user models.User
		if err := mfa.db.Where("id = ?", userID).First(&user).Error; err != nil {
			return nil, fmt.Errorf("user not found")
		}

		code, err := mfa.generateSMSCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate email code")
		}

		if err := mfa.sendMFAEmail(user.Email, code, 5); err != nil {
			return nil, fmt.Errorf("failed to send MFA email: %w", err)
		}

		challenge = mfa.hashToken(code)
	case "push":
		if err := mfa.sendPushoverNotification(fmt.Sprintf("SecureVault đăng nhập từ %s", ipAddress)); err != nil {
			return nil, fmt.Errorf("failed to send push notification: %w", err)
		}
		challenge = "push_sent"
	}

	// Create MFA challenge
	mfaChallenge := &MFAChallenge{
		UserID:      userID,
		SessionID:   sessionID,
		Method:      method,
		Challenge:   challenge,
		Status:      "pending",
		MaxAttempts: 3,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		Metadata: map[string]interface{}{
			"created_by": "login_flow",
		},
	}

	if err := mfa.db.Create(mfaChallenge).Error; err != nil {
		return nil, fmt.Errorf("failed to create MFA challenge: %w", err)
	}

	mfa.auditSvc.LogEvent(userID, "mfa_challenge_created", "mfa", mfaChallenge.ID.String(), true,
		map[string]interface{}{
			"method":     method,
			"session_id": sessionID,
		}, ipAddress, userAgent)

	return mfaChallenge, nil
}

func (mfa *RealMFAService) VerifyMFAChallenge(challengeID uuid.UUID, userResponse string) (*MFAChallenge, error) {
	// Get challenge
	var challenge MFAChallenge
	if err := mfa.db.Where("id = ? AND status = 'pending'", challengeID).First(&challenge).Error; err != nil {
		return nil, fmt.Errorf("challenge not found or already processed")
	}

	// Check expiry
	if time.Now().After(challenge.ExpiresAt) {
		challenge.Status = "expired"
		mfa.db.Save(&challenge)
		return &challenge, fmt.Errorf("challenge expired")
	}

	// Check max attempts
	if challenge.AttemptCount >= challenge.MaxAttempts {
		challenge.Status = "failed"
		mfa.db.Save(&challenge)
		return &challenge, fmt.Errorf("maximum attempts exceeded")
	}

	// Increment attempt count
	challenge.AttemptCount++

	var verified bool
	switch challenge.Method {
	case "totp":
		// Get user's TOTP secret
		var settings UserMFASettings
		if err := mfa.db.Where("user_id = ?", challenge.UserID).First(&settings).Error; err != nil {
			return nil, fmt.Errorf("MFA settings not found")
		}

		encData := &security.EncryptedData{Data: settings.TOTPSecret}
		secretBytes, err := mfa.cryptoSvc.Decrypt(encData)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt TOTP secret")
		}

		secret := string(secretBytes)
		verified = mfa.validateTOTPWithWindow(secret, userResponse, 1)

	case "sms", "email":
		// Verify against stored hashed token
		verified = mfa.verifyHashedToken(userResponse, challenge.Challenge)

	case "push":
		// For push, any response means user approved
		verified = userResponse == "approved"

	default:
		return nil, fmt.Errorf("unsupported verification method")
	}

	if verified {
		challenge.Status = "verified"
		now := time.Now()
		challenge.VerifiedAt = &now
		challenge.Response = "verified"

		// Update last used timestamp
		mfa.db.Model(&UserMFASettings{}).
			Where("user_id = ?", challenge.UserID).
			Update("last_used", now)

		mfa.auditSvc.LogEvent(challenge.UserID, "mfa_challenge_verified", "mfa", challenge.ID.String(), true,
			map[string]interface{}{
				"method":   challenge.Method,
				"attempts": challenge.AttemptCount,
			}, challenge.IPAddress, challenge.UserAgent)
	} else {
		if challenge.AttemptCount >= challenge.MaxAttempts {
			challenge.Status = "failed"

			// Lock user's MFA temporarily
			lockUntil := time.Now().Add(15 * time.Minute)
			mfa.db.Model(&UserMFASettings{}).
				Where("user_id = ?", challenge.UserID).
				Updates(map[string]interface{}{
					"failure_count": gorm.Expr("failure_count + 1"),
					"locked_until":  lockUntil,
				})
		}

		mfa.auditSvc.LogEvent(challenge.UserID, "mfa_challenge_failed", "mfa", challenge.ID.String(), false,
			map[string]interface{}{
				"method":       challenge.Method,
				"attempts":     challenge.AttemptCount,
				"max_attempts": challenge.MaxAttempts,
			}, challenge.IPAddress, challenge.UserAgent)
	}

	mfa.db.Save(&challenge)
	return &challenge, nil
}

// ========== Backup Code Verification ==========

func (mfa *RealMFAService) VerifyBackupCode(userID uuid.UUID, code string) error {
	var settings UserMFASettings
	if err := mfa.db.Where("user_id = ?", userID).First(&settings).Error; err != nil {
		return fmt.Errorf("MFA settings not found")
	}

	// Check backup codes
	for i, hashedCode := range settings.BackupCodes {
		if mfa.verifyHashedCode(code, hashedCode) {
			// Remove used backup code
			settings.BackupCodes = append(settings.BackupCodes[:i], settings.BackupCodes[i+1:]...)
			now := time.Now()
			settings.LastUsed = &now

			if err := mfa.db.Save(&settings).Error; err != nil {
				return fmt.Errorf("failed to update backup codes")
			}

			mfa.auditSvc.LogEvent(userID, "mfa_backup_code_used", "mfa", settings.ID.String(), true,
				map[string]interface{}{
					"codes_remaining": len(settings.BackupCodes),
				}, "", "")

			return nil
		}
	}

	return fmt.Errorf("invalid backup code")
}

// ========== Helper Methods ==========

func (mfa *RealMFAService) generateSecureBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)

	for i := 0; i < count; i++ {
		// Generate 8-character alphanumeric code
		bytes := make([]byte, 6)
		if _, err := rand.Read(bytes); err != nil {
			return nil, err
		}

		code := base32.StdEncoding.EncodeToString(bytes)[:8]
		// Format for readability: XXXX-XXXX
		codes[i] = fmt.Sprintf("%s-%s", code[:4], code[4:])
	}

	return codes, nil
}

func (mfa *RealMFAService) generateSMSCode() (string, error) {
	// Generate 6-digit numeric code
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Convert to 6-digit number
	num := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
	code := fmt.Sprintf("%06d", num%1000000)

	return code, nil
}

func (mfa *RealMFAService) hashToken(token string) string {
	salt := make([]byte, 32)
	rand.Read(salt)

	hash := argon2.IDKey([]byte(token), salt, 1, 64*1024, 4, 32)
	combined := append(salt, hash...)

	return base64.StdEncoding.EncodeToString(combined)
}

func (mfa *RealMFAService) verifyHashedToken(token, hashedToken string) bool {
	decoded, err := base64.StdEncoding.DecodeString(hashedToken)
	if err != nil || len(decoded) < 32 {
		return false
	}

	salt := decoded[:32]
	storedHash := decoded[32:]

	hash := argon2.IDKey([]byte(token), salt, 1, 64*1024, 4, 32)

	return subtle.ConstantTimeCompare(storedHash, hash) == 1
}

func (mfa *RealMFAService) hashBackupCode(code string) (string, error) {
	return mfa.hashToken(code), nil
}

func (mfa *RealMFAService) verifyHashedCode(code, hashedCode string) bool {
	return mfa.verifyHashedToken(code, hashedCode)
}

func (mfa *RealMFAService) validateTOTPWithWindow(secret, token string, window int) bool {
	// Current time validation
	if totp.Validate(token, secret) {
		return true
	}

	// Check within time window (±window * 30 seconds)
	for i := 1; i <= window; i++ {
		// Past periods
		pastTime := time.Now().Add(-time.Duration(i) * 30 * time.Second)
		if pastToken, err := totp.GenerateCode(secret, pastTime); err == nil && pastToken == token {
			return true
		}

		// Future periods
		futureTime := time.Now().Add(time.Duration(i) * 30 * time.Second)
		if futureToken, err := totp.GenerateCode(secret, futureTime); err == nil && futureToken == token {
			return true
		}
	}

	return false
}

func (mfa *RealMFAService) validatePhoneNumber(phone string) bool {
	// International phone number regex
	phoneRegex := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
	return phoneRegex.MatchString(phone)
}

func (mfa *RealMFAService) maskPhoneNumber(phone string) string {
	if len(phone) < 4 {
		return "***"
	}
	return phone[:3] + strings.Repeat("*", len(phone)-6) + phone[len(phone)-3:]
}

func (mfa *RealMFAService) maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "***@***.com"
	}

	name := parts[0]
	domain := parts[1]

	if len(name) <= 2 {
		name = "**"
	} else {
		name = name[:1] + strings.Repeat("*", len(name)-2) + name[len(name)-1:]
	}

	return name + "@" + domain
}

func formatSecretForManualEntry(secret string) string {
	// Format secret for manual entry: XXXX XXXX XXXX XXXX
	var formatted strings.Builder
	for i, char := range secret {
		if i > 0 && i%4 == 0 {
			formatted.WriteString(" ")
		}
		formatted.WriteRune(char)
	}
	return formatted.String()
}

// ========== Real Provider Integration ==========

func (mfa *RealMFAService) sendSMS(phoneNumber, message string) error {
	if mfa.twilioSID == "" || mfa.twilioAuth == "" {
		return fmt.Errorf("Twilio credentials not configured")
	}

	// Twilio API endpoint
	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", mfa.twilioSID)

	// Prepare form data
	data := url.Values{}
	data.Set("To", phoneNumber)
	data.Set("From", mfa.config.MFA.TwilioPhoneNumber) // Your Twilio phone number
	data.Set("Body", message)

	// Create HTTP request
	req, err := http.NewRequest("POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(mfa.twilioSID, mfa.twilioAuth)

	// Send request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Twilio API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (mfa *RealMFAService) sendMFAEmail(to, code string, expiryMinutes int) error {
	if !mfa.email.Enabled {
		return fmt.Errorf("email MFA not configured")
	}

	// This is a simplified email sending - in production, use a proper email service
	// like AWS SES, SendGrid, or Mailgun

	// Create email content
	subject := "🔐 Mã xác thực SecureVault"

	body := fmt.Sprintf(`
		<h2>🔐 SecureVault - Mã xác thực</h2>
		<p>Mã xác thực của bạn là:</p>
		<div style="font-size: 32px; font-weight: bold; color: #2563eb; padding: 20px; background: #f0f9ff; border-radius: 5px; text-align: center;">
			%s
		</div>
		<p><strong>Mã này sẽ hết hạn sau %d phút.</strong></p>
		<p style="color: red;"><strong>⚠️ Không chia sẻ mã này với bất kỳ ai!</strong></p>
		<hr>
		<small>SecureVault Security Team - %s</small>
	`, code, expiryMinutes, time.Now().Format("15:04:05 02/01/2006"))

	// In a real implementation, you would use SMTP or email service API
	// For now, just log the email (in production, integrate with your email provider)
	fmt.Printf("EMAIL TO %s: %s\nBODY: %s\n", to, subject, body)

	return nil
}

func (mfa *RealMFAService) sendPushoverNotification(message string) error {
	if !mfa.pushover.Enabled {
		return fmt.Errorf("Pushover not configured")
	}

	// Pushover API endpoint
	apiURL := "https://api.pushover.net/1/messages.json"

	// Prepare form data
	data := url.Values{}
	data.Set("token", mfa.pushover.AppToken)
	data.Set("user", mfa.pushover.UserKey)
	data.Set("message", message)
	data.Set("title", "SecureVault MFA")
	data.Set("priority", "1") // High priority

	// Send POST request
	resp, err := http.PostForm(apiURL, data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Pushover API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
