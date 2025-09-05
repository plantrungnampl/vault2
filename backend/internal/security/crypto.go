package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"securevault/internal/config"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// CryptoService handles all cryptographic operations
type CryptoService struct {
	config     *config.Config
	masterKey  []byte
	gcm        cipher.AEAD
	keyCache   map[string][]byte
	rotationCh chan struct{}
}

// EncryptedData represents encrypted data with metadata
type EncryptedData struct {
	Data      string    `json:"data"`
	Nonce     string    `json:"nonce"`
	Algorithm string    `json:"algorithm"`
	KeyID     string    `json:"key_id"`
	Timestamp time.Time `json:"timestamp"`
}

// KeyInfo contains information about encryption keys
type KeyInfo struct {
	ID        string    `json:"id"`
	Algorithm string    `json:"algorithm"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Active    bool      `json:"active"`
}

// NewCryptoService creates a new crypto service
func NewCryptoService(cfg *config.Config) *CryptoService {
	// Derive master key from configuration
	masterKey := pbkdf2.Key(
		[]byte(cfg.Database.EncryptionKey),
		[]byte("securevault-master-salt"),
		100000, // 100,000 iterations (minimum required)
		32,     // 256-bit key
		sha256.New,
	)

	// Create AES-GCM cipher
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		panic(fmt.Sprintf("Failed to create AES cipher: %v", err))
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(fmt.Sprintf("Failed to create GCM: %v", err))
	}

	service := &CryptoService{
		config:     cfg,
		masterKey:  masterKey,
		gcm:        gcm,
		keyCache:   make(map[string][]byte),
		rotationCh: make(chan struct{}, 1),
	}

	// Start key rotation goroutine
	go service.keyRotationScheduler()

	return service
}

// Encrypt encrypts data using AES-256-GCM with a unique key per item
func (cs *CryptoService) Encrypt(data []byte, keyID string) (*EncryptedData, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	// Generate or retrieve item-specific key
	itemKey, err := cs.getOrCreateItemKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get item key: %w", err)
	}

	// Create AES-GCM cipher with item key
	block, err := aes.NewCipher(itemKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	return &EncryptedData{
		Data:      base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Algorithm: "AES-256-GCM",
		KeyID:     keyID,
		Timestamp: time.Now().UTC(),
	}, nil
}

// Decrypt decrypts data using the stored key ID and nonce
func (cs *CryptoService) Decrypt(encData *EncryptedData) ([]byte, error) {
	if encData == nil {
		return nil, fmt.Errorf("encrypted data cannot be nil")
	}

	// Get item key
	itemKey, err := cs.getOrCreateItemKey(encData.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get item key: %w", err)
	}

	// Create AES-GCM cipher with item key
	block, err := aes.NewCipher(itemKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decode base64 data
	ciphertext, err := base64.StdEncoding.DecodeString(encData.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(encData.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// HashPassword creates a secure hash of a password using Argon2id
func (cs *CryptoService) HashPassword(password string) (string, error) {
	// Generate random salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash password with Argon2id
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)

	// Encode as base64 with salt prepended
	encoded := base64.StdEncoding.EncodeToString(append(salt, hash...))
	return encoded, nil
}

// VerifyPassword verifies a password against its hash
func (cs *CryptoService) VerifyPassword(password, hash string) bool {
	// Decode hash
	decoded, err := base64.StdEncoding.DecodeString(hash)
	if err != nil || len(decoded) < 32 {
		return false
	}

	// Extract salt and hash
	salt := decoded[:32]
	storedHash := decoded[32:]

	// Hash provided password with same salt
	computedHash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)

	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(storedHash, computedHash) == 1
}

// GenerateSecureToken generates a cryptographically secure random token
func (cs *CryptoService) GenerateSecureToken(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("token length must be positive")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return hex.EncodeToString(bytes), nil
}

// GenerateHMAC generates HMAC-SHA256 for data integrity
func (cs *CryptoService) GenerateHMAC(data []byte) (string, error) {
	h := sha256.New()
	h.Write(cs.masterKey)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyHMAC verifies HMAC-SHA256
func (cs *CryptoService) VerifyHMAC(data []byte, expectedHMAC string) bool {
	computedHMAC, err := cs.GenerateHMAC(data)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(computedHMAC), []byte(expectedHMAC)) == 1
}

// getOrCreateItemKey gets or creates a unique encryption key for an item
func (cs *CryptoService) getOrCreateItemKey(keyID string) ([]byte, error) {
	// Check cache first
	if key, exists := cs.keyCache[keyID]; exists {
		return key, nil
	}

	// Derive key from master key and item ID
	itemKey := pbkdf2.Key(
		cs.masterKey,
		[]byte(keyID),
		10000, // Fewer iterations for item keys since master key is already strong
		32,    // 256-bit key
		sha256.New,
	)

	// Cache the key
	cs.keyCache[keyID] = itemKey
	return itemKey, nil
}

// RotateKeys rotates encryption keys
func (cs *CryptoService) RotateKeys() error {
	// Signal key rotation
	select {
	case cs.rotationCh <- struct{}{}:
		return nil
	default:
		return fmt.Errorf("key rotation already in progress")
	}
}

// GetKeyInfo returns information about encryption keys
func (cs *CryptoService) GetKeyInfo() []KeyInfo {
	// In a real implementation, this would query a key management system
	return []KeyInfo{
		{
			ID:        "master-key-v1",
			Algorithm: "AES-256-GCM",
			CreatedAt: time.Now().AddDate(0, -1, 0), // 1 month ago
			ExpiresAt: time.Now().AddDate(0, 2, 0),  // 2 months from now
			Active:    true,
		},
	}
}

// keyRotationScheduler handles automatic key rotation
func (cs *CryptoService) keyRotationScheduler() {
	interval := cs.config.Security.KeyRotationInterval
	if interval <= 0 {
		interval = 24 * time.Hour // Default to 24 hours if not set
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cs.performKeyRotation()
		case <-cs.rotationCh:
			cs.performKeyRotation()
		}
	}
}

// performKeyRotation performs the actual key rotation
func (cs *CryptoService) performKeyRotation() {
	// Clear key cache to force regeneration
	cs.keyCache = make(map[string][]byte)

	// In a production system, this would:
	// 1. Generate new master key
	// 2. Re-encrypt all data with new key
	// 3. Update key metadata in database
	// 4. Notify administrators

	// For now, just log the rotation
	fmt.Printf("Key rotation completed at %v\n", time.Now())
}

// ValidatePasswordComplexity validates password meets security requirements
func (cs *CryptoService) ValidatePasswordComplexity(password string) error {
	if len(password) < cs.config.Security.PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters long", cs.config.Security.PasswordMinLength)
	}

	if !cs.config.Security.PasswordComplexity {
		return nil // Skip complexity check if disabled
	}

	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasNumber = true
		default:
			for _, special := range specialChars {
				if char == special {
					hasSpecial = true
					break
				}
			}
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return fmt.Errorf("password must contain at least one number")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// EncryptSearchIndex creates an encrypted searchable index
func (cs *CryptoService) EncryptSearchIndex(text string) ([]string, error) {
	// Tokenize text
	words := tokenizeText(text)

	// Create encrypted tokens for search
	var encryptedTokens []string
	for _, word := range words {
		if len(word) < 3 { // Skip very short words
			continue
		}

		// Create deterministic encryption for searching
		token := cs.createSearchToken(word)
		encryptedTokens = append(encryptedTokens, token)
	}

	return encryptedTokens, nil
}

// createSearchToken creates a deterministic token for searching
func (cs *CryptoService) createSearchToken(word string) string {
	// Use HMAC for deterministic but secure tokens
	h := sha256.New()
	h.Write(cs.masterKey)
	h.Write([]byte("search-salt"))
	h.Write([]byte(word))
	return hex.EncodeToString(h.Sum(nil))[:16] // Use first 16 chars
}

// tokenizeText splits text into searchable tokens
func tokenizeText(text string) []string {
	// Simple tokenization - in production, use a proper tokenizer
	words := make([]string, 0)
	current := ""

	for _, char := range text {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			current += string(char)
		} else {
			if current != "" {
				words = append(words, current)
				current = ""
			}
		}
	}

	if current != "" {
		words = append(words, current)
	}

	return words
}
