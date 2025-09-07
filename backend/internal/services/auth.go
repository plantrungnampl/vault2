package services

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"securevault/internal/config"
	"securevault/internal/database"
	"securevault/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthService struct {
	db          *gorm.DB
	config      *config.Config
	userService *UserService
}

type JWTClaims struct {
	UserID      uuid.UUID         `json:"user_id"`
	Email       string            `json:"email"`
	Role        models.UserRole   `json:"role"`
	Status      models.UserStatus `json:"status"`
	SessionID   uuid.UUID         `json:"session_id"`
	MFAVerified bool              `json:"mfa_verified"`
	jwt.RegisteredClaims
}

// GetUserID implements the Claims interface
func (c *JWTClaims) GetUserID() uuid.UUID {
	return c.UserID
}

// GetRole implements the Claims interface
func (c *JWTClaims) GetRole() string {
	return string(c.Role)
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	ExpiresIn    int64        `json:"expires_in"`
	User         *models.User `json:"user"`
}

type RegisterRequest struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=14"`
	FirstName string `json:"firstName" binding:"required"`
	LastName  string `json:"lastName" binding:"required"`
}

func NewAuthService(cfg *config.Config) *AuthService {
	return &AuthService{
		db:          database.GetDB(),
		config:      cfg,
		userService: NewUserService(),
	}
}

// Register creates a new user account
func (s *AuthService) Register(req RegisterRequest) (*models.User, error) {
	// Validate password strength
	if err := s.validatePasswordStrength(req.Password); err != nil {
		return nil, err
	}

	// Create user
	user, err := s.userService.CreateUser(req.Email, req.Password, req.FirstName, req.LastName)
	if err != nil {
		return nil, err
	}

	// Log audit event
	s.logAuditEvent(user.ID, "user_registration", "user", user.ID.String(), "", true, nil)

	return user, nil
}

// Login authenticates user and creates session
func (s *AuthService) Login(req LoginRequest, ipAddress, userAgent string) (*LoginResponse, error) {
	// Get user by email
	user, err := s.userService.GetUserByEmail(req.Email)
	if err != nil {
		s.logSecurityEvent(models.SecurityEventInvalidCredentials, models.SeverityMedium, nil, ipAddress, models.SecurityEventDetails{
			FailureReason: "user_not_found",
			AdditionalInfo: map[string]interface{}{
				"email": req.Email,
			},
		})
		return nil, errors.New("invalid credentials")
	}

	// Check if account is locked
	locked, err := s.userService.IsAccountLocked(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check account lock status: %v", err)
	}
	if locked {
		s.logSecurityEvent(models.SecurityEventAccountLockout, models.SeverityHigh, &user.ID, ipAddress, models.SecurityEventDetails{
			FailureReason: "account_locked",
			AdditionalInfo: map[string]interface{}{
				"user_id": user.ID,
			},
		})
		return nil, errors.New("account is locked")
	}

	// Verify password
	if !s.userService.VerifyPassword(user, req.Password) {
		// Record failed login attempt
		s.userService.RecordLoginAttempt(user.ID, false, ipAddress)
		s.logSecurityEvent(models.SecurityEventInvalidCredentials, models.SeverityMedium, &user.ID, ipAddress, models.SecurityEventDetails{
			FailureReason: "invalid_password",
			AdditionalInfo: map[string]interface{}{
				"user_id": user.ID,
			},
		})
		return nil, errors.New("invalid credentials")
	}

	// Check if user is active
	if user.Status != models.StatusActive {
		s.logSecurityEvent(models.SecurityEventUnauthorizedAccess, models.SeverityMedium, &user.ID, ipAddress, models.SecurityEventDetails{
			FailureReason: "inactive_account",
			AdditionalInfo: map[string]interface{}{
				"user_id": user.ID,
				"status":  user.Status,
			},
		})
		return nil, errors.New("account is not active")
	}

	// Create session
	session, err := s.createSession(user, ipAddress, userAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}

	// Generate tokens
	accessToken, err := s.generateAccessToken(user, session.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %v", err)
	}

	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %v", err)
	}

	// Update session with refresh token
	hashedRefreshToken, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err := s.db.Model(session).Update("refresh_token", string(hashedRefreshToken)).Error; err != nil {
		return nil, fmt.Errorf("failed to update session: %v", err)
	}

	// Record successful login
	s.userService.RecordLoginAttempt(user.ID, true, ipAddress)

	// Log audit event
	s.logAuditEvent(user.ID, "user_login", "session", session.ID.String(), ipAddress, true, nil)

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.config.Security.JWTExpiry.Seconds()),
		User:         user,
	}, nil
}

// RefreshToken refreshes access token using refresh token
func (s *AuthService) RefreshToken(refreshToken string) (*LoginResponse, error) {
	// Find session by refresh token hash
	sessions := []models.Session{}
	if err := s.db.Preload("User").Find(&sessions).Error; err != nil {
		return nil, fmt.Errorf("failed to query sessions: %v", err)
	}

	var validSession *models.Session
	for _, sess := range sessions {
		if err := bcrypt.CompareHashAndPassword([]byte(sess.RefreshToken), []byte(refreshToken)); err == nil {
			validSession = &sess
			break
		}
	}

	if validSession == nil {
		return nil, errors.New("invalid refresh token")
	}

	// Check if session is expired
	if validSession.ExpiresAt.Before(time.Now()) {
		s.db.Delete(validSession)
		return nil, errors.New("session expired")
	}

	// Generate new access token
	accessToken, err := s.generateAccessToken(&validSession.User, validSession.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %v", err)
	}

	// Update session activity
	s.db.Model(validSession).Update("last_activity", time.Now())

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.config.Security.JWTExpiry.Seconds()),
		User:         &validSession.User,
	}, nil
}

// Logout invalidates session
func (s *AuthService) Logout(sessionID uuid.UUID) error {
	// Delete session
	if err := s.db.Delete(&models.Session{}, sessionID).Error; err != nil {
		return fmt.Errorf("failed to delete session: %v", err)
	}

	// Log audit event
	s.logAuditEvent(uuid.Nil, "user_logout", "session", sessionID.String(), "", true, nil)

	return nil
}

// ValidateToken validates JWT token and returns user info
func (s *AuthService) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.Security.JWTSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		// Verify session still exists
		var session models.Session
		if err := s.db.Where("id = ?", claims.SessionID).First(&session).Error; err != nil {
			return nil, errors.New("session not found")
		}

		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// createSession creates a new user session
func (s *AuthService) createSession(user *models.User, ipAddress, userAgent string) (*models.Session, error) {
	// Generate session token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(tokenBytes)

	// Hash token for storage
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	deviceInfo := s.parseDeviceInfo(userAgent)
	deviceInfoJSON, err := json.Marshal(deviceInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal device info: %v", err)
	}

	session := &models.Session{
		ID:           uuid.New(),
		UserID:       user.ID,
		TokenHash:    string(hashedToken),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		DeviceInfo:   deviceInfoJSON,
		ExpiresAt:    time.Now().Add(s.config.Security.RefreshTokenExpiry),
		LastActivity: time.Now(),
	}

	if err := s.db.Create(session).Error; err != nil {
		return nil, err
	}

	return session, nil
}

// generateAccessToken generates JWT access token
func (s *AuthService) generateAccessToken(user *models.User, sessionID uuid.UUID) (string, error) {
	claims := JWTClaims{
		UserID:    user.ID,
		Email:     user.Email,
		Role:      user.Role,
		Status:    user.Status,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.config.Security.JWTExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "securevault",
			Subject:   user.ID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.Security.JWTSecret))
}

// generateRefreshToken generates random refresh token
func (s *AuthService) generateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// parseDeviceInfo parses user agent to extract device information
func (s *AuthService) parseDeviceInfo(userAgent string) models.DeviceInfo {
	// Simple parsing - in production, use a library like go-device-detector
	return models.DeviceInfo{
		Browser:     "Unknown",
		OS:          "Unknown",
		DeviceType:  "Unknown",
		Fingerprint: "",
	}
}

// validatePasswordStrength validates password meets security requirements
func (s *AuthService) validatePasswordStrength(password string) error {
	if len(password) < s.config.Security.PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters long", s.config.Security.PasswordMinLength)
	}

	if s.config.Security.PasswordComplexity {
		// Add more complexity checks here
		// For now, just check length
	}

	return nil
}

// logAuditEvent logs an audit event
func (s *AuthService) logAuditEvent(userID uuid.UUID, action, resource, resourceID, ipAddress string, success bool, details interface{}) {
	auditLog := &models.AuditLog{
		UserID:     userID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		IPAddress:  ipAddress,
		Success:    success,
		Details:    details,
		Timestamp:  time.Now(),
	}

	s.db.Create(auditLog)
}

// logSecurityEvent logs a security event
func (s *AuthService) logSecurityEvent(eventType models.SecurityEventType, severity models.SecuritySeverity, userID *uuid.UUID, ipAddress string, details models.SecurityEventDetails) {
	event := &models.SecurityEvent{
		Type:      eventType,
		Severity:  severity,
		UserID:    userID,
		IPAddress: ipAddress,
		Details:   details,
		Timestamp: time.Now(),
	}

	s.db.Create(event)
}
