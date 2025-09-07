package services

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// WebAuthnService handles FIDO2/WebAuthn authentication
type WebAuthnService struct {
	db           *gorm.DB
	relyingParty *RelyingParty
	challenges   map[string]*Challenge // In production, use Redis
}

// RelyingParty configuration for WebAuthn
type RelyingParty struct {
	ID          string
	Name        string
	DisplayName string
	Origin      string
	Icon        string
}

// Challenge represents a WebAuthn challenge
type Challenge struct {
	ID        string    `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	Challenge []byte    `json:"challenge"`
	Type      string    `json:"type"` // registration, authentication
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

// CredentialCreationOptions for WebAuthn registration
type CredentialCreationOptions struct {
	Challenge              []byte                    `json:"challenge"`
	RelyingParty           *RelyingParty             `json:"rp"`
	User                   *UserInfo                 `json:"user"`
	PubKeyCredParams       []PubKeyCredParam         `json:"pubKeyCredParams"`
	AuthenticatorSelection *AuthenticatorSelection   `json:"authenticatorSelection,omitempty"`
	Timeout                int                       `json:"timeout"`
	Attestation            string                    `json:"attestation"`
	ExcludeCredentials     []PublicKeyCredDescriptor `json:"excludeCredentials,omitempty"`
	Extensions             map[string]interface{}    `json:"extensions,omitempty"`
}

// CredentialRequestOptions for WebAuthn authentication
type CredentialRequestOptions struct {
	Challenge        []byte                    `json:"challenge"`
	Timeout          int                       `json:"timeout"`
	RelyingPartyID   string                    `json:"rpId"`
	AllowCredentials []PublicKeyCredDescriptor `json:"allowCredentials,omitempty"`
	UserVerification string                    `json:"userVerification"`
	Extensions       map[string]interface{}    `json:"extensions,omitempty"`
}

// UserInfo for WebAuthn
type UserInfo struct {
	ID          []byte `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// PubKeyCredParam defines supported cryptographic parameters
type PubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

// AuthenticatorSelection defines authenticator requirements
type AuthenticatorSelection struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	RequireResidentKey      bool   `json:"requireResidentKey"`
	ResidentKey             string `json:"residentKey"`
	UserVerification        string `json:"userVerification"`
}

// PublicKeyCredDescriptor describes a credential
type PublicKeyCredDescriptor struct {
	Type       string   `json:"type"`
	ID         []byte   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

// AttestationResponse from authenticator during registration
type AttestationResponse struct {
	ClientDataJSON    []byte `json:"clientDataJSON"`
	AttestationObject []byte `json:"attestationObject"`
}

// AssertionResponse from authenticator during authentication
type AssertionResponse struct {
	ClientDataJSON    []byte `json:"clientDataJSON"`
	AuthenticatorData []byte `json:"authenticatorData"`
	Signature         []byte `json:"signature"`
	UserHandle        []byte `json:"userHandle,omitempty"`
}

// WebAuthnCredential represents a stored credential
type WebAuthnCredential struct {
	ID              string    `json:"id" gorm:"primaryKey"`
	UserID          uuid.UUID `json:"user_id" gorm:"not null;index"`
	CredentialID    []byte    `json:"credential_id" gorm:"not null;unique"`
	PublicKey       []byte    `json:"public_key" gorm:"not null"`
	AttestationType string    `json:"attestation_type"`
	Transport       []string  `json:"transport" gorm:"type:text[]"`
	Flags           uint8     `json:"flags"`
	SignCount       uint32    `json:"sign_count"`
	CreatedAt       time.Time `json:"created_at"`
	LastUsedAt      time.Time `json:"last_used_at"`
	Name            string    `json:"name"`
	AAGUID          []byte    `json:"aaguid"`
}

// ClientData represents the client data JSON
type ClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}

// NewWebAuthnService creates a new WebAuthn service
func NewWebAuthnService(db *gorm.DB, config *RelyingParty) *WebAuthnService {
	// Auto-migrate WebAuthn credentials table
	db.AutoMigrate(&WebAuthnCredential{})

	return &WebAuthnService{
		db:           db,
		relyingParty: config,
		challenges:   make(map[string]*Challenge),
	}
}

// BeginRegistration starts WebAuthn credential registration
func (ws *WebAuthnService) BeginRegistration(userID uuid.UUID, userName, displayName string) (*CredentialCreationOptions, string, error) {
	// Generate cryptographically secure challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, "", fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Create challenge record
	challengeID := uuid.New().String()
	challengeRecord := &Challenge{
		ID:        challengeID,
		UserID:    userID,
		Challenge: challenge,
		Type:      "registration",
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Used:      false,
	}

	// Store challenge (in production, use Redis with expiration)
	ws.challenges[challengeID] = challengeRecord

	// Get existing credentials to exclude
	var existingCreds []WebAuthnCredential
	ws.db.Where("user_id = ?", userID).Find(&existingCreds)

	excludeCredentials := make([]PublicKeyCredDescriptor, 0)
	for _, cred := range existingCreds {
		excludeCredentials = append(excludeCredentials, PublicKeyCredDescriptor{
			Type:       "public-key",
			ID:         cred.CredentialID,
			Transports: cred.Transport,
		})
	}

	// User ID as bytes
	userIDBytes, _ := userID.MarshalBinary()

	options := &CredentialCreationOptions{
		Challenge:    challenge,
		RelyingParty: ws.relyingParty,
		User: &UserInfo{
			ID:          userIDBytes,
			Name:        userName,
			DisplayName: displayName,
		},
		PubKeyCredParams: []PubKeyCredParam{
			{Type: "public-key", Alg: -7},   // ES256
			{Type: "public-key", Alg: -35},  // ES384
			{Type: "public-key", Alg: -36},  // ES512
			{Type: "public-key", Alg: -257}, // RS256
		},
		AuthenticatorSelection: &AuthenticatorSelection{
			RequireResidentKey: false,
			ResidentKey:        "preferred",
			UserVerification:   "preferred",
		},
		Timeout:            60000, // 60 seconds
		Attestation:        "direct",
		ExcludeCredentials: excludeCredentials,
	}

	return options, challengeID, nil
}

// FinishRegistration completes WebAuthn credential registration
func (ws *WebAuthnService) FinishRegistration(challengeID string, credentialID []byte, publicKey []byte, attestationResponse *AttestationResponse, transport []string) error {
	// Get and validate challenge
	challenge, exists := ws.challenges[challengeID]
	if !exists {
		return fmt.Errorf("challenge not found")
	}

	if challenge.Used {
		return fmt.Errorf("challenge already used")
	}

	if time.Now().After(challenge.ExpiresAt) {
		delete(ws.challenges, challengeID)
		return fmt.Errorf("challenge expired")
	}

	if challenge.Type != "registration" {
		return fmt.Errorf("invalid challenge type")
	}

	// Verify client data
	if err := ws.verifyClientData(attestationResponse.ClientDataJSON, challenge.Challenge, "webauthn.create"); err != nil {
		return fmt.Errorf("client data verification failed: %w", err)
	}

	// Parse and verify attestation object
	attestationObject, err := ws.parseAttestationObject(attestationResponse.AttestationObject)
	if err != nil {
		return fmt.Errorf("failed to parse attestation object: %w", err)
	}

	// Verify attestation
	if err := ws.verifyAttestation(attestationObject); err != nil {
		return fmt.Errorf("attestation verification failed: %w", err)
	}

	// Store credential
	credential := &WebAuthnCredential{
		ID:              uuid.New().String(),
		UserID:          challenge.UserID,
		CredentialID:    credentialID,
		PublicKey:       publicKey,
		AttestationType: "direct",
		Transport:       transport,
		Flags:           attestationObject["flags"].(uint8),
		SignCount:       0,
		CreatedAt:       time.Now(),
		LastUsedAt:      time.Now(),
		Name:            fmt.Sprintf("Security Key %s", time.Now().Format("Jan 02, 2006")),
		AAGUID:          attestationObject["aaguid"].([]byte),
	}

	if err := ws.db.Create(credential).Error; err != nil {
		return fmt.Errorf("failed to store credential: %w", err)
	}

	// Mark challenge as used
	challenge.Used = true

	// Clean up challenge
	delete(ws.challenges, challengeID)

	return nil
}

// BeginAuthentication starts WebAuthn authentication
func (ws *WebAuthnService) BeginAuthentication(userID uuid.UUID) (*CredentialRequestOptions, string, error) {
	// Generate challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, "", fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Create challenge record
	challengeID := uuid.New().String()
	challengeRecord := &Challenge{
		ID:        challengeID,
		UserID:    userID,
		Challenge: challenge,
		Type:      "authentication",
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Used:      false,
	}

	ws.challenges[challengeID] = challengeRecord

	// Get user's credentials
	var credentials []WebAuthnCredential
	ws.db.Where("user_id = ?", userID).Find(&credentials)

	if len(credentials) == 0 {
		return nil, "", fmt.Errorf("no credentials found for user")
	}

	// Build allowed credentials list
	allowCredentials := make([]PublicKeyCredDescriptor, 0)
	for _, cred := range credentials {
		allowCredentials = append(allowCredentials, PublicKeyCredDescriptor{
			Type:       "public-key",
			ID:         cred.CredentialID,
			Transports: cred.Transport,
		})
	}

	options := &CredentialRequestOptions{
		Challenge:        challenge,
		Timeout:          60000, // 60 seconds
		RelyingPartyID:   ws.relyingParty.ID,
		AllowCredentials: allowCredentials,
		UserVerification: "preferred",
	}

	return options, challengeID, nil
}

// FinishAuthentication completes WebAuthn authentication
func (ws *WebAuthnService) FinishAuthentication(challengeID string, credentialID []byte, assertionResponse *AssertionResponse) (*WebAuthnCredential, error) {
	// Get and validate challenge
	challenge, exists := ws.challenges[challengeID]
	if !exists {
		return nil, fmt.Errorf("challenge not found")
	}

	if challenge.Used {
		return nil, fmt.Errorf("challenge already used")
	}

	if time.Now().After(challenge.ExpiresAt) {
		delete(ws.challenges, challengeID)
		return nil, fmt.Errorf("challenge expired")
	}

	if challenge.Type != "authentication" {
		return nil, fmt.Errorf("invalid challenge type")
	}

	// Get credential
	var credential WebAuthnCredential
	if err := ws.db.Where("credential_id = ? AND user_id = ?", credentialID, challenge.UserID).First(&credential).Error; err != nil {
		return nil, fmt.Errorf("credential not found: %w", err)
	}

	// Verify client data
	if err := ws.verifyClientData(assertionResponse.ClientDataJSON, challenge.Challenge, "webauthn.get"); err != nil {
		return nil, fmt.Errorf("client data verification failed: %w", err)
	}

	// Verify signature
	if err := ws.verifyAssertion(&credential, assertionResponse); err != nil {
		return nil, fmt.Errorf("assertion verification failed: %w", err)
	}

	// Update credential usage
	credential.LastUsedAt = time.Now()
	credential.SignCount++
	ws.db.Save(&credential)

	// Mark challenge as used
	challenge.Used = true
	delete(ws.challenges, challengeID)

	return &credential, nil
}

// GetUserCredentials returns all WebAuthn credentials for a user
func (ws *WebAuthnService) GetUserCredentials(userID uuid.UUID) ([]WebAuthnCredential, error) {
	var credentials []WebAuthnCredential
	if err := ws.db.Where("user_id = ?", userID).Find(&credentials).Error; err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}
	return credentials, nil
}

// DeleteCredential removes a WebAuthn credential
func (ws *WebAuthnService) DeleteCredential(userID uuid.UUID, credentialID string) error {
	result := ws.db.Where("id = ? AND user_id = ?", credentialID, userID).Delete(&WebAuthnCredential{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete credential: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("credential not found")
	}
	return nil
}

// UpdateCredentialName updates the name of a credential
func (ws *WebAuthnService) UpdateCredentialName(userID uuid.UUID, credentialID, newName string) error {
	result := ws.db.Model(&WebAuthnCredential{}).
		Where("id = ? AND user_id = ?", credentialID, userID).
		Update("name", newName)

	if result.Error != nil {
		return fmt.Errorf("failed to update credential name: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("credential not found")
	}
	return nil
}

// Helper methods for verification

func (ws *WebAuthnService) verifyClientData(clientDataJSON, expectedChallenge []byte, expectedType string) error {
	var clientData ClientData
	if err := json.Unmarshal(clientDataJSON, &clientData); err != nil {
		return fmt.Errorf("failed to parse client data: %w", err)
	}

	// Verify type
	if clientData.Type != expectedType {
		return fmt.Errorf("invalid client data type: expected %s, got %s", expectedType, clientData.Type)
	}

	// Verify challenge
	challengeB64 := base64.RawURLEncoding.EncodeToString(expectedChallenge)
	if clientData.Challenge != challengeB64 {
		return fmt.Errorf("challenge mismatch")
	}

	// Verify origin
	if clientData.Origin != ws.relyingParty.Origin {
		return fmt.Errorf("origin mismatch: expected %s, got %s", ws.relyingParty.Origin, clientData.Origin)
	}

	return nil
}

func (ws *WebAuthnService) parseAttestationObject(attestationObject []byte) (map[string]interface{}, error) {
	// In a real implementation, this would use CBOR to parse the attestation object
	// For now, return a mock structure
	return map[string]interface{}{
		"fmt":      "none",
		"attStmt":  map[string]interface{}{},
		"authData": attestationObject, // Simplified
		"flags":    uint8(0x41),       // User present + User verified
		"aaguid":   make([]byte, 16),
	}, nil
}

func (ws *WebAuthnService) verifyAttestation(attestationObject map[string]interface{}) error {
	// In a real implementation, this would verify the attestation statement
	// based on the format (fmt) field
	format := attestationObject["fmt"].(string)

	switch format {
	case "none":
		// No attestation to verify
		return nil
	case "packed", "tpm", "android-key", "android-safetynet", "fido-u2f", "apple":
		// In production, implement proper attestation verification
		return nil
	default:
		return fmt.Errorf("unsupported attestation format: %s", format)
	}
}

func (ws *WebAuthnService) verifyAssertion(credential *WebAuthnCredential, assertion *AssertionResponse) error {
	// In a real implementation, this would:
	// 1. Parse the authenticator data
	// 2. Verify the signature using the stored public key
	// 3. Check the sign count to prevent replay attacks

	// For now, perform basic validation
	if len(assertion.Signature) == 0 {
		return fmt.Errorf("empty signature")
	}

	if len(assertion.AuthenticatorData) < 37 {
		return fmt.Errorf("invalid authenticator data length")
	}

	// In production, implement proper cryptographic signature verification
	return nil
}

// CleanupExpiredChallenges removes expired challenges
func (ws *WebAuthnService) CleanupExpiredChallenges() {
	now := time.Now()
	for id, challenge := range ws.challenges {
		if now.After(challenge.ExpiresAt) {
			delete(ws.challenges, id)
		}
	}
}

// GetCredentialCount returns the number of registered credentials for a user
func (ws *WebAuthnService) GetCredentialCount(userID uuid.UUID) (int64, error) {
	var count int64
	if err := ws.db.Model(&WebAuthnCredential{}).Where("user_id = ?", userID).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("failed to count credentials: %w", err)
	}
	return count, nil
}
