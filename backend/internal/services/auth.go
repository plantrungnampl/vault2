package services

import (
	"database/sql"
	"fmt"
	"time"

	"securevault/internal/config"
	"securevault/internal/database"
	"securevault/internal/redis"
	"securevault/internal/security"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AuthService handles authentication operations
type AuthService struct {
	db            *sql.DB
	redis         *redis.Client
	cryptoService *security.CryptoService
	config        *config.Config
}

// NewAuthService creates a new authentication service
func NewAuthService(db *sql.DB, redisClient *redis.Client, cryptoService *security.CryptoService, cfg *config.Config) *AuthService {
	return &AuthService{
		db:            db,
		redis:         redisClient,
		cryptoService: cryptoService,
		config:        cfg,
	}
}

// RegisterRequest represents a user registration request
type RegisterRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=14"`
	FirstName string `json:"first_name" validate:"required,min=1,max=100"`
	LastName  string `json:"last_name" validate:"required,min=1,max=100"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email      string     `json:"email" validate:"required,email"`
	Password   string     `json:"password" validate:"required"`
	MFAToken   string     `json:"mfa_token,omitempty"`
	DeviceInfo DeviceInfo `json:"device_info"`
}

// DeviceInfo represents device information
type DeviceInfo struct {
	Browser     string `json:"browser"`
	OS          string `json:"os"`
	DeviceType  string `json:"device_type"`
	Fingerprint string `json:"fingerprint"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	User         *database.User `json:"user"`
	AccessToken  string         `json:"access_token"`
	RefreshToken string         `json:"refresh_token"`
	ExpiresIn    int64          `json:"expires_in"`
	MFARequired  bool           `json:"mfa_required,omitempty"`
	MFAMethods   []string       `json:"mfa_methods,omitempty"`
}

// JWTClaims represents JWT token claims
type JWTClaims struct {
	UserID      uuid.UUID         `json:"user_id"`
	Email       string            `json:"email"`
	Role        database.UserRole `json:"role"`
	SessionID   uuid.UUID         `json:"session_id"`
	MFAVerified bool              `json:"mfa_verified"`
	Permissions map[string]bool   `json:"permissions"`
	jwt.RegisteredClaims
}

// Register creates a new user account
func (as *AuthService) Register(req *RegisterRequest, ipAddress, userAgent string) (*AuthResponse, error) {
	// Validate password complexity
	if err := as.cryptoService.ValidatePasswordComplexity(req.Password); err != nil {
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	// Check if user already exists
	var existingUserID uuid.UUID
	err := as.db.QueryRow("SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL", req.Email).Scan(&existingUserID)
	if err == nil {
		return nil, fmt.Errorf("user with email %s already exists", req.Email)
	} else if err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	// Hash password
	passwordHash, err := as.cryptoService.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Generate email verification token
	verificationToken, err := as.cryptoService.GenerateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Create user
	userID := uuid.New()
	user := &database.User{
		ID:                     userID,
		Email:                  req.Email,
		PasswordHash:           passwordHash,
		FirstName:              req.FirstName,
		LastName:               req.LastName,
		Role:                   database.RoleBasicUser,
		Status:                 database.StatusPending,
		EmailVerificationToken: verificationToken,
		Preferences: database.UserPreferences{
			Language: "en",
			Theme:    "light",
			Timezone: "UTC",
			Notifications: database.NotificationSettings{
				Email:    true,
				SMS:      false,
				Push:     true,
				Security: true,
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Insert user into database
	_, err = as.db.Exec(`
		INSERT INTO users (
			id, email, password_hash, first_name, last_name, role, status,
			email_verification_token, preferences, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		user.ID, user.Email, user.PasswordHash, user.FirstName, user.LastName,
		user.Role, user.Status, user.EmailVerificationToken, user.Preferences,
		user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// TODO: Send verification email

	// Create session and generate tokens
	session, err := as.createSession(user, ipAddress, userAgent, DeviceInfo{})
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	accessToken, err := as.generateAccessToken(user, session.ID, false)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := as.generateRefreshToken(user.ID, session.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(as.config.Security.JWTExpiry.Seconds()),
		MFARequired:  false,
	}, nil
}

// Login authenticates a user
func (as *AuthService) Login(req *LoginRequest, ipAddress, userAgent string) (*AuthResponse, error) {
	// Get user by email
	user, err := as.getUserByEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if account is locked
	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		return nil, fmt.Errorf("account is locked until %v", user.LockedUntil)
	}

	// Verify password
	if !as.cryptoService.VerifyPassword(req.Password, user.PasswordHash) {
		// Increment login attempts
		as.incrementLoginAttempts(user.ID)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Reset login attempts on successful password verification
	as.resetLoginAttempts(user.ID)

	// Check if MFA is required
	if user.MFAEnabled && req.MFAToken == "" {
		return &AuthResponse{
			MFARequired: true,
			MFAMethods:  as.getMFAMethods(user.ID),
		}, nil
	}

	// Verify MFA if provided
	mfaVerified := false
	if user.MFAEnabled && req.MFAToken != "" {
		if !as.verifyMFA(user.ID, req.MFAToken) {
			return nil, fmt.Errorf("invalid MFA token")
		}
		mfaVerified = true
	}

	// Update last login
	as.updateLastLogin(user.ID, ipAddress)

	// Create session
	session, err := as.createSession(user, ipAddress, userAgent, req.DeviceInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Generate tokens
	accessToken, err := as.generateAccessToken(user, session.ID, mfaVerified)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := as.generateRefreshToken(user.ID, session.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(as.config.Security.JWTExpiry.Seconds()),
		MFARequired:  false,
	}, nil
}

// RefreshToken generates new access and refresh tokens
func (as *AuthService) RefreshToken(refreshToken string) (*AuthResponse, error) {
	// Validate refresh token
	sessionID, userID, err := as.validateRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Get user
	user, err := as.getUserByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check if session is still valid
	session, err := as.getSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	if session.RevokedAt != nil {
		return nil, fmt.Errorf("session has been revoked")
	}

	// Generate new tokens
	accessToken, err := as.generateAccessToken(user, session.ID, true) // Assume MFA is verified for refresh
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	newRefreshToken, err := as.generateRefreshToken(user.ID, session.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Update session with new refresh token
	as.updateSessionRefreshToken(session.ID, newRefreshToken)

	return &AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(as.config.Security.JWTExpiry.Seconds()),
	}, nil
}

// Logout revokes a user session
func (as *AuthService) Logout(sessionID uuid.UUID) error {
	// Revoke session
	_, err := as.db.Exec("UPDATE sessions SET revoked_at = NOW() WHERE id = $1", sessionID)
	if err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	// Remove from Redis cache
	as.redis.Del(fmt.Sprintf("session:%s", sessionID))

	return nil
}

// ValidateToken validates a JWT token and returns claims
func (as *AuthService) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(as.config.Security.JWTSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Check if session is still valid
	session, err := as.getSession(claims.SessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found")
	}

	if session.RevokedAt != nil {
		return nil, fmt.Errorf("session has been revoked")
	}

	if session.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("session has expired")
	}

	return claims, nil
}

// Helper methods

func (as *AuthService) getUserByEmail(email string) (*database.User, error) {
	var user database.User
	err := as.db.QueryRow(`
		SELECT id, email, password_hash, first_name, last_name, role, status,
		       mfa_enabled, mfa_secret, login_attempts, locked_until, last_login_at,
		       last_login_ip, two_factor_enabled, preferences, created_at, updated_at
		FROM users 
		WHERE email = $1 AND deleted_at IS NULL`,
		email,
	).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
		&user.Role, &user.Status, &user.MFAEnabled, &user.MFASecret, &user.LoginAttempts,
		&user.LockedUntil, &user.LastLoginAt, &user.LastLoginIP, &user.TwoFactorEnabled,
		&user.Preferences, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (as *AuthService) getUserByID(userID uuid.UUID) (*database.User, error) {
	var user database.User
	err := as.db.QueryRow(`
		SELECT id, email, password_hash, first_name, last_name, role, status,
		       mfa_enabled, mfa_secret, login_attempts, locked_until, last_login_at,
		       last_login_ip, two_factor_enabled, preferences, created_at, updated_at
		FROM users 
		WHERE id = $1 AND deleted_at IS NULL`,
		userID,
	).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
		&user.Role, &user.Status, &user.MFAEnabled, &user.MFASecret, &user.LoginAttempts,
		&user.LockedUntil, &user.LastLoginAt, &user.LastLoginIP, &user.TwoFactorEnabled,
		&user.Preferences, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (as *AuthService) incrementLoginAttempts(userID uuid.UUID) {
	attempts := 0
	as.db.QueryRow("SELECT login_attempts FROM users WHERE id = $1", userID).Scan(&attempts)
	attempts++

	var query string
	var args []interface{}

	if attempts >= as.config.Security.MaxLoginAttempts {
		// Lock account
		lockUntil := time.Now().Add(as.config.Security.AccountLockoutTime)
		query = "UPDATE users SET login_attempts = $1, locked_until = $2 WHERE id = $3"
		args = []interface{}{attempts, lockUntil, userID}
	} else {
		query = "UPDATE users SET login_attempts = $1 WHERE id = $2"
		args = []interface{}{attempts, userID}
	}

	as.db.Exec(query, args...)
}

func (as *AuthService) resetLoginAttempts(userID uuid.UUID) {
	as.db.Exec("UPDATE users SET login_attempts = 0, locked_until = NULL WHERE id = $1", userID)
}

func (as *AuthService) updateLastLogin(userID uuid.UUID, ipAddress string) {
	as.db.Exec("UPDATE users SET last_login_at = NOW(), last_login_ip = $1 WHERE id = $2", ipAddress, userID)
}

func (as *AuthService) createSession(user *database.User, ipAddress, userAgent string, deviceInfo DeviceInfo) (*database.Session, error) {
	sessionID := uuid.New()
	expiresAt := time.Now().Add(as.config.Security.RefreshTokenExpiry)

	// Generate secure tokens
	tokenHash, err := as.cryptoService.GenerateSecureToken(32)
	if err != nil {
		return nil, err
	}

	refreshToken, err := as.cryptoService.GenerateSecureToken(32)
	if err != nil {
		return nil, err
	}

	session := &database.Session{
		ID:           sessionID,
		UserID:       user.ID,
		TokenHash:    tokenHash,
		RefreshToken: refreshToken,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		DeviceInfo: database.DeviceInfo{
			Browser:     deviceInfo.Browser,
			OS:          deviceInfo.OS,
			DeviceType:  deviceInfo.DeviceType,
			Fingerprint: deviceInfo.Fingerprint,
		},
		LastActivity: time.Now(),
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
	}

	_, err = as.db.Exec(`
		INSERT INTO sessions (
			id, user_id, token_hash, refresh_token, ip_address, user_agent,
			device_info, last_activity, expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		session.ID, session.UserID, session.TokenHash, session.RefreshToken,
		session.IPAddress, session.UserAgent, session.DeviceInfo,
		session.LastActivity, session.ExpiresAt, session.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (as *AuthService) generateAccessToken(user *database.User, sessionID uuid.UUID, mfaVerified bool) (string, error) {
	claims := &JWTClaims{
		UserID:      user.ID,
		Email:       user.Email,
		Role:        user.Role,
		SessionID:   sessionID,
		MFAVerified: mfaVerified,
		Permissions: as.getUserPermissions(user.Role),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(as.config.Security.JWTExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "securevault",
			Subject:   user.ID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(as.config.Security.JWTSecret))
}

func (as *AuthService) generateRefreshToken(userID, sessionID uuid.UUID) (string, error) {
	claims := &JWTClaims{
		UserID:    userID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(as.config.Security.RefreshTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "securevault",
			Subject:   userID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(as.config.Security.JWTSecret))
}

func (as *AuthService) validateRefreshToken(tokenString string) (uuid.UUID, uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(as.config.Security.JWTSecret), nil
	})

	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid token claims")
	}

	return claims.SessionID, claims.UserID, nil
}

func (as *AuthService) getSession(sessionID uuid.UUID) (*database.Session, error) {
	var session database.Session
	err := as.db.QueryRow(`
		SELECT id, user_id, token_hash, refresh_token, ip_address, user_agent,
		       device_info, last_activity, expires_at, created_at, revoked_at
		FROM sessions WHERE id = $1`,
		sessionID,
	).Scan(
		&session.ID, &session.UserID, &session.TokenHash, &session.RefreshToken,
		&session.IPAddress, &session.UserAgent, &session.DeviceInfo,
		&session.LastActivity, &session.ExpiresAt, &session.CreatedAt, &session.RevokedAt,
	)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (as *AuthService) updateSessionRefreshToken(sessionID uuid.UUID, refreshToken string) {
	as.db.Exec("UPDATE sessions SET refresh_token = $1 WHERE id = $2", refreshToken, sessionID)
}

func (as *AuthService) getMFAMethods(userID uuid.UUID) []string {
	// This would query the MFA credentials table
	// For now, return static methods
	return []string{"totp", "webauthn"}
}

func (as *AuthService) verifyMFA(userID uuid.UUID, token string) bool {
	// This would verify the MFA token
	// For now, return true for development
	return true
}

func (as *AuthService) getUserPermissions(role database.UserRole) map[string]bool {
	permissions := make(map[string]bool)

	switch role {
	case database.RoleBasicUser:
		permissions["vault:read"] = true
		permissions["vault:create"] = true
		permissions["vault:update"] = true
		permissions["vault:delete"] = true
		permissions["vault:share"] = false
	case database.RolePremiumUser:
		permissions["vault:read"] = true
		permissions["vault:create"] = true
		permissions["vault:update"] = true
		permissions["vault:delete"] = true
		permissions["vault:share"] = true
		permissions["api:access"] = true
	case database.RoleTeamMember:
		permissions["vault:read"] = true
		permissions["vault:create"] = true
		permissions["vault:update"] = true
		permissions["vault:delete"] = true
		permissions["vault:share"] = true
		permissions["team:access"] = true
	case database.RoleVaultAdmin:
		permissions["admin:users"] = true
		permissions["admin:vault"] = true
		permissions["admin:audit"] = true
	case database.RoleSecurityAdmin:
		permissions["admin:security"] = true
		permissions["admin:keys"] = true
		permissions["admin:incidents"] = true
		permissions["admin:audit"] = true
	case database.RoleSuperAdmin:
		permissions["admin:*"] = true
	}

	return permissions
}
