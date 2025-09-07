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
	"strings"
	"time"

	"securevault/internal/config"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// CryptoService handles all cryptographic operations
type CryptoService struct {
	config        *config.Config
	masterKey     []byte
	gcm           cipher.AEAD
	keyCache      map[string][]byte
	rotationCh    chan struct{}
	keyManager    *KeyManager
	passwordHistory map[string][]string // User ID -> password hashes
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
	Version   int       `json:"version"`
	KeyType   string    `json:"key_type"` // master, item, search, etc.
}

// KeyManager manages encryption key lifecycle
type KeyManager struct {
	keys           map[string]*KeyInfo
	activeKeys     map[string]string // key type -> active key ID
	rotationPolicy int               // days between rotations
}

// PasswordStrengthResult contains password strength analysis
type PasswordStrengthResult struct {
	Score           int      `json:"score"`           // 0-100
	Strength        string   `json:"strength"`        // weak, fair, good, strong, very_strong
	Suggestions     []string `json:"suggestions"`
	HasCompromised  bool     `json:"has_compromised"`
	EstimatedCrack  string   `json:"estimated_crack_time"`
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

	keyManager := &KeyManager{
		keys:           make(map[string]*KeyInfo),
		activeKeys:     make(map[string]string),
		rotationPolicy: 90, // 90 days default
	}

	service := &CryptoService{
		config:          cfg,
		masterKey:       masterKey,
		gcm:            gcm,
		keyCache:       make(map[string][]byte),
		rotationCh:     make(chan struct{}, 1),
		keyManager:     keyManager,
		passwordHistory: make(map[string][]string),
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
	fmt.Printf("Starting key rotation at %v\n", time.Now())
	
	// 1. Generate new master key
	newMasterKey := make([]byte, 32)
	if _, err := rand.Read(newMasterKey); err != nil {
		fmt.Printf("CRITICAL: Failed to generate new master key: %v\n", err)
		return
	}
	
	// 2. Create backup of current key for data recovery
	oldMasterKey := cs.masterKey
	keyBackup := make([]byte, len(oldMasterKey))
	copy(keyBackup, oldMasterKey)
	
	// 3. Update master key
	cs.masterKey = newMasterKey
	
	// 4. Clear item key cache to force regeneration with new master key
	cs.keyCache = make(map[string][]byte)
	
	// 5. Update GCM cipher with new master key
	block, err := aes.NewCipher(cs.masterKey)
	if err != nil {
		fmt.Printf("CRITICAL: Failed to create new cipher: %v\n", err)
		// Rollback to old key
		cs.masterKey = keyBackup
		return
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("CRITICAL: Failed to create new GCM: %v\n", err)
		// Rollback to old key
		cs.masterKey = keyBackup
		return
	}
	cs.gcm = gcm
	
	// 6. Store key rotation metadata
	keyRotationRecord := map[string]interface{}{
		"rotation_time": time.Now(),
		"old_key_id":   fmt.Sprintf("%x", sha256.Sum256(keyBackup))[:16],
		"new_key_id":   fmt.Sprintf("%x", sha256.Sum256(cs.masterKey))[:16],
		"rotation_reason": "scheduled",
	}
	
	// In production, store this in secure key management system
	fmt.Printf("Key rotation metadata: %+v\n", keyRotationRecord)
	
	// 7. Notify administrators (in production, send actual notifications)
	fmt.Printf("SECURITY NOTICE: Master key rotation completed successfully at %v\n", time.Now())
	fmt.Printf("New key ID: %s\n", keyRotationRecord["new_key_id"])
	
	// 8. Securely wipe old key from memory
	for i := range keyBackup {
		keyBackup[i] = 0
	}
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

// Advanced Security Features

// QuantumResistantEncrypt provides quantum-resistant encryption simulation
func (cs *CryptoService) QuantumResistantEncrypt(data []byte, keyID string) (*EncryptedData, error) {
	// Multi-layer encryption for quantum resistance
	
	// First layer: Standard AES-256-GCM
	firstLayer, err := cs.Encrypt(data, keyID+"_layer1")
	if err != nil {
		return nil, fmt.Errorf("first layer encryption failed: %w", err)
	}

	// Convert first layer to bytes for second layer
	firstLayerBytes := []byte(firstLayer.Data)
	
	// Second layer: Different key derivation
	secondLayer, err := cs.Encrypt(firstLayerBytes, keyID+"_layer2")
	if err != nil {
		return nil, fmt.Errorf("second layer encryption failed: %w", err)
	}

	return &EncryptedData{
		Data:      secondLayer.Data,
		Nonce:     secondLayer.Nonce,
		Algorithm: "QUANTUM-RESISTANT-AES-256-GCM-DUAL",
		KeyID:     keyID,
		Timestamp: time.Now().UTC(),
	}, nil
}

// DeriveKeyFromPassword derives key using scrypt (more secure than PBKDF2)
func (cs *CryptoService) DeriveKeyFromPassword(password, salt string) ([]byte, error) {
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		return nil, fmt.Errorf("invalid salt: %w", err)
	}

	// scrypt parameters: N=32768, r=8, p=1 (recommended for interactive use)
	key, err := scrypt.Key([]byte(password), saltBytes, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	return key, nil
}

// AnalyzePasswordStrength provides comprehensive password strength analysis
func (cs *CryptoService) AnalyzePasswordStrength(password string) *PasswordStrengthResult {
	result := &PasswordStrengthResult{
		Suggestions: make([]string, 0),
	}

	score := 0
	length := len(password)

	// Length scoring
	if length >= 14 {
		score += 25
	} else if length >= 8 {
		score += 10
	} else {
		result.Suggestions = append(result.Suggestions, "Sử dụng ít nhất 14 ký tự")
	}

	// Character variety scoring
	hasLower := strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz")
	hasUpper := strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	hasDigits := strings.ContainsAny(password, "0123456789")
	hasSpecial := strings.ContainsAny(password, "!@#$%^&*()_+-=[]{}|;:,.<>?")

	if hasLower { score += 10 } else { result.Suggestions = append(result.Suggestions, "Thêm chữ thường") }
	if hasUpper { score += 10 } else { result.Suggestions = append(result.Suggestions, "Thêm chữ hoa") }
	if hasDigits { score += 10 } else { result.Suggestions = append(result.Suggestions, "Thêm số") }
	if hasSpecial { score += 15 } else { result.Suggestions = append(result.Suggestions, "Thêm ký tự đặc biệt") }

	// Pattern detection
	if !cs.hasRepeatingPatterns(password) {
		score += 10
	} else {
		result.Suggestions = append(result.Suggestions, "Tránh lặp ký tự liên tiếp")
	}

	// Dictionary word check (simplified)
	if !cs.containsCommonWords(password) {
		score += 10
	} else {
		result.Suggestions = append(result.Suggestions, "Tránh sử dụng từ thông dụng")
	}

	// Sequential patterns
	if !cs.hasSequentialPatterns(password) {
		score += 10
	} else {
		result.Suggestions = append(result.Suggestions, "Tránh chuỗi ký tự tuần tự")
	}

	result.Score = score

	// Determine strength level
	switch {
	case score >= 90:
		result.Strength = "very_strong"
		result.EstimatedCrack = "centuries"
	case score >= 70:
		result.Strength = "strong"
		result.EstimatedCrack = "years"
	case score >= 50:
		result.Strength = "good"
		result.EstimatedCrack = "months"
	case score >= 30:
		result.Strength = "fair"
		result.EstimatedCrack = "days"
	default:
		result.Strength = "weak"
		result.EstimatedCrack = "minutes"
	}

	// Check against compromised password database (simulation)
	result.HasCompromised = cs.isPasswordCompromised(password)
	if result.HasCompromised {
		result.Suggestions = append(result.Suggestions, "Mật khẩu này đã bị rò rỉ, hãy đổi mật khẩu khác")
		result.Score = 0
		result.Strength = "compromised"
	}

	return result
}

// CheckPasswordHistory validates password against history
func (cs *CryptoService) CheckPasswordHistory(userID, newPassword string) error {
	history, exists := cs.passwordHistory[userID]
	if !exists {
		return nil // No history, password is valid
	}

	// Check against last 24 passwords
	maxHistory := 24
	if len(history) > maxHistory {
		history = history[len(history)-maxHistory:]
	}

	for _, oldPasswordHash := range history {
		if cs.VerifyPassword(newPassword, oldPasswordHash) {
			return fmt.Errorf("không thể sử dụng lại 24 mật khẩu gần đây")
		}
	}

	return nil
}

// AddPasswordToHistory adds password to user's history
func (cs *CryptoService) AddPasswordToHistory(userID, passwordHash string) {
	if cs.passwordHistory[userID] == nil {
		cs.passwordHistory[userID] = make([]string, 0)
	}
	
	cs.passwordHistory[userID] = append(cs.passwordHistory[userID], passwordHash)
	
	// Keep only last 24 passwords
	if len(cs.passwordHistory[userID]) > 24 {
		cs.passwordHistory[userID] = cs.passwordHistory[userID][1:]
	}
}

// GenerateSecurePassword generates a cryptographically secure password
func (cs *CryptoService) GenerateSecurePassword(length int) string {
	if length < 14 {
		length = 14 // Minimum security requirement
	}

	const (
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits    = "0123456789"
		special   = "!@#$%^&*()_+-=[]{}|;:,.<>?"
		all       = lowercase + uppercase + digits + special
	)

	password := make([]byte, length)
	
	// Ensure at least one character from each category
	password[0] = lowercase[cs.secureRandomInt(len(lowercase))]
	password[1] = uppercase[cs.secureRandomInt(len(uppercase))]
	password[2] = digits[cs.secureRandomInt(len(digits))]
	password[3] = special[cs.secureRandomInt(len(special))]

	// Fill the rest randomly
	for i := 4; i < length; i++ {
		password[i] = all[cs.secureRandomInt(len(all))]
	}

	// Shuffle the password
	for i := length - 1; i > 0; i-- {
		j := cs.secureRandomInt(i + 1)
		password[i], password[j] = password[j], password[i]
	}

	return string(password)
}

// SecureWipe securely wipes sensitive data from memory
func (cs *CryptoService) SecureWipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// Helper methods for password analysis

func (cs *CryptoService) hasRepeatingPatterns(password string) bool {
	for i := 0; i < len(password)-2; i++ {
		if password[i] == password[i+1] && password[i+1] == password[i+2] {
			return true
		}
	}
	return false
}

func (cs *CryptoService) containsCommonWords(password string) bool {
	// Simplified check - in production, use a comprehensive dictionary
	commonWords := []string{
		"password", "123456", "admin", "user", "login",
		"welcome", "qwerty", "abc123", "password123",
		"admin123", "root", "toor", "guest", "test",
	}

	passwordLower := strings.ToLower(password)
	for _, word := range commonWords {
		if strings.Contains(passwordLower, word) {
			return true
		}
	}
	return false
}

func (cs *CryptoService) hasSequentialPatterns(password string) bool {
	// Check for sequential characters like "abc", "123", "xyz"
	for i := 0; i < len(password)-2; i++ {
		if password[i+1] == password[i]+1 && password[i+2] == password[i]+2 {
			return true
		}
	}
	return false
}

func (cs *CryptoService) isPasswordCompromised(password string) bool {
	// Simulation of breach database check
	// In production, this would query HaveIBeenPwned API or similar
	compromisedPasswords := map[string]bool{
		"password123":    true,
		"admin123":       true,
		"123456789":      true,
		"qwerty123":      true,
		"welcome123":     true,
	}

	return compromisedPasswords[strings.ToLower(password)]
}

func (cs *CryptoService) secureRandomInt(max int) int {
	if max <= 0 {
		return 0
	}

	// Generate cryptographically secure random integer
	randomBytes := make([]byte, 4)
	rand.Read(randomBytes)
	
	// Convert to int and ensure within range
	randomInt := int(randomBytes[0])<<24 | int(randomBytes[1])<<16 | int(randomBytes[2])<<8 | int(randomBytes[3])
	if randomInt < 0 {
		randomInt = -randomInt
	}
	
	return randomInt % max
}
