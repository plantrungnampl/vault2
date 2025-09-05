package security

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"securevault/internal/config"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTPService handles Time-based One-Time Password operations
type TOTPService struct {
	config *config.Config
}

// TOTPSetup contains TOTP setup information
type TOTPSetup struct {
	Secret      string   `json:"secret"`
	QRCode      string   `json:"qr_code"`
	URL         string   `json:"url"`
	BackupCodes []string `json:"backup_codes"`
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
	// Use the crypto service to hash backup codes
	// This is a simplified version - in production, use proper salt and hashing
	return base64.StdEncoding.EncodeToString([]byte(code)), nil
}
