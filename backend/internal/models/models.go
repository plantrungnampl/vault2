package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system
type User struct {
	ID                     uuid.UUID       `json:"id" db:"id"`
	Email                  string          `json:"email" db:"email"`
	PasswordHash           string          `json:"-" db:"password_hash"`
	FirstName              string          `json:"first_name" db:"first_name"`
	LastName               string          `json:"last_name" db:"last_name"`
	Role                   UserRole        `json:"role" db:"role"`
	Status                 UserStatus      `json:"status" db:"status"`
	MFAEnabled             bool            `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret              string          `json:"-" db:"mfa_secret"`
	TwoFactorEnabled       bool            `json:"two_factor_enabled" db:"two_factor_enabled"`
	EmailVerified          bool            `json:"email_verified" db:"email_verified"`
	EmailVerificationToken string          `json:"-" db:"email_verification_token"`
	PasswordResetToken     string          `json:"-" db:"password_reset_token"`
	PasswordResetExpiry    *time.Time      `json:"-" db:"password_reset_expiry"`
	LoginAttempts          int             `json:"-" db:"login_attempts"`
	LockedUntil            *time.Time      `json:"-" db:"locked_until"`
	LastLoginAt            *time.Time      `json:"last_login_at" db:"last_login_at"`
	LastLoginIP            string          `json:"last_login_ip" db:"last_login_ip"`
	Preferences            UserPreferences `json:"preferences" db:"preferences"`
	CreatedAt              time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time       `json:"updated_at" db:"updated_at"`
	DeletedAt              *time.Time      `json:"-" db:"deleted_at"`
}

// UserRole represents user roles
type UserRole string

const (
	RoleBasicUser     UserRole = "basic_user"
	RolePremiumUser   UserRole = "premium_user"
	RoleTeamMember    UserRole = "team_member"
	RoleVaultAdmin    UserRole = "vault_admin"
	RoleSecurityAdmin UserRole = "security_admin"
	RoleSuperAdmin    UserRole = "super_admin"
)

// UserStatus represents user status
type UserStatus string

const (
	StatusActive    UserStatus = "active"
	StatusPending   UserStatus = "pending"
	StatusSuspended UserStatus = "suspended"
	StatusDeactive  UserStatus = "deactive"
)

// UserPreferences represents user preferences
type UserPreferences struct {
	Language      string               `json:"language"`
	Theme         string               `json:"theme"`
	Timezone      string               `json:"timezone"`
	Notifications NotificationSettings `json:"notifications"`
}

// NotificationSettings represents notification preferences
type NotificationSettings struct {
	Email    bool `json:"email"`
	SMS      bool `json:"sms"`
	Push     bool `json:"push"`
	Security bool `json:"security"`
}

// Session represents a user session
type Session struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	UserID       uuid.UUID  `json:"user_id" db:"user_id"`
	TokenHash    string     `json:"-" db:"token_hash"`
	RefreshToken string     `json:"-" db:"refresh_token"`
	IPAddress    string     `json:"ip_address" db:"ip_address"`
	UserAgent    string     `json:"user_agent" db:"user_agent"`
	DeviceInfo   DeviceInfo `json:"device_info" db:"device_info"`
	LastActivity time.Time  `json:"last_activity" db:"last_activity"`
	ExpiresAt    time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
}

// DeviceInfo represents device information
type DeviceInfo struct {
	Browser     string `json:"browser"`
	OS          string `json:"os"`
	DeviceType  string `json:"device_type"`
	Fingerprint string `json:"fingerprint"`
}

// VaultItem represents a vault item
type VaultItem struct {
	ID          string                 `json:"id" db:"id"`
	UserID      string                 `json:"user_id" db:"user_id"`
	Name        string                 `json:"name" db:"name"`
	Type        string                 `json:"type" db:"type"`
	Data        map[string]interface{} `json:"data" db:"data"`
	Notes       string                 `json:"notes" db:"notes"`
	FolderID    *string                `json:"folder_id" db:"folder_id"`
	Tags        []string               `json:"tags" db:"tags"`
	Favorite    bool                   `json:"favorite" db:"favorite"`
	Reprompt    bool                   `json:"reprompt" db:"reprompt"`
	SharedWith  []string               `json:"shared_with" db:"shared_with"`
	Permissions map[string]string      `json:"permissions" db:"permissions"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt   *time.Time             `json:"-" db:"deleted_at"`
}

// VaultFolder represents a vault folder
type VaultFolder struct {
	ID        string     `json:"id" db:"id"`
	UserID    string     `json:"user_id" db:"user_id"`
	Name      string     `json:"name" db:"name"`
	Color     string     `json:"color" db:"color"`
	Icon      string     `json:"icon" db:"icon"`
	ParentID  *string    `json:"parent_id" db:"parent_id"`
	ItemCount int        `json:"item_count" db:"item_count"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"-" db:"deleted_at"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID         uuid.UUID   `json:"id" db:"id"`
	UserID     uuid.UUID   `json:"user_id" db:"user_id"`
	Action     string      `json:"action" db:"action"`
	Resource   string      `json:"resource" db:"resource"`
	ResourceID string      `json:"resource_id" db:"resource_id"`
	IPAddress  string      `json:"ip_address" db:"ip_address"`
	UserAgent  string      `json:"user_agent" db:"user_agent"`
	Success    bool        `json:"success" db:"success"`
	ErrorCode  string      `json:"error_code" db:"error_code"`
	Details    interface{} `json:"details" db:"details"`
	Timestamp  time.Time   `json:"timestamp" db:"timestamp"`
}

// SecurityEvent represents a security event
type SecurityEvent struct {
	ID         uuid.UUID            `json:"id" db:"id"`
	Type       SecurityEventType    `json:"type" db:"type"`
	Severity   SecuritySeverity     `json:"severity" db:"severity"`
	UserID     *uuid.UUID           `json:"user_id,omitempty" db:"user_id"`
	IPAddress  string               `json:"ip_address" db:"ip_address"`
	Details    SecurityEventDetails `json:"details" db:"details"`
	Resolved   bool                 `json:"resolved" db:"resolved"`
	ResolvedBy *uuid.UUID           `json:"resolved_by,omitempty" db:"resolved_by"`
	ResolvedAt *time.Time           `json:"resolved_at,omitempty" db:"resolved_at"`
	Timestamp  time.Time            `json:"timestamp" db:"timestamp"`
}

// SecurityEventType represents types of security events
type SecurityEventType string

const (
	SecurityEventLoginFailure        SecurityEventType = "login_failure"
	SecurityEventAccountLockout      SecurityEventType = "account_lockout"
	SecurityEventPasswordBreach      SecurityEventType = "password_breach"
	SecurityEventSuspiciousActivity  SecurityEventType = "suspicious_activity"
	SecurityEventUnauthorizedAccess  SecurityEventType = "unauthorized_access"
	SecurityEventDataExfiltration    SecurityEventType = "data_exfiltration"
	SecurityEventMFABypass           SecurityEventType = "mfa_bypass"
	SecurityEventPrivilegeEscalation SecurityEventType = "privilege_escalation"
)

// SecuritySeverity represents severity levels
type SecuritySeverity string

const (
	SeverityLow      SecuritySeverity = "low"
	SeverityMedium   SecuritySeverity = "medium"
	SeverityHigh     SecuritySeverity = "high"
	SeverityCritical SecuritySeverity = "critical"
)

// SecurityEventDetails represents details of security events
type SecurityEventDetails struct {
	AttemptsCount     int                    `json:"attempts_count,omitempty"`
	FailureReason     string                 `json:"failure_reason,omitempty"`
	GeolocationData   map[string]interface{} `json:"geolocation_data,omitempty"`
	DeviceFingerprint string                 `json:"device_fingerprint,omitempty"`
	AnomalyScore      float64                `json:"anomaly_score,omitempty"`
	AdditionalInfo    map[string]interface{} `json:"additional_info,omitempty"`
}

// MFACredential represents MFA credentials
type MFACredential struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	UserID      uuid.UUID  `json:"user_id" db:"user_id"`
	Type        MFAType    `json:"type" db:"type"`
	Name        string     `json:"name" db:"name"`
	Secret      string     `json:"-" db:"secret"`
	BackupCodes []string   `json:"-" db:"backup_codes"`
	Verified    bool       `json:"verified" db:"verified"`
	Primary     bool       `json:"primary" db:"primary"`
	LastUsed    *time.Time `json:"last_used" db:"last_used"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
}

// MFAType represents MFA credential types
type MFAType string

const (
	MFATypeTOTP     MFAType = "totp"
	MFATypeWebAuthn MFAType = "webauthn"
	MFATypeSMS      MFAType = "sms"
	MFATypeEmail    MFAType = "email"
)

// VaultShare represents shared vault items
type VaultShare struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	VaultItemID  string     `json:"vault_item_id" db:"vault_item_id"`
	OwnerUserID  string     `json:"owner_user_id" db:"owner_user_id"`
	SharedUserID string     `json:"shared_user_id" db:"shared_user_id"`
	Permissions  string     `json:"permissions" db:"permissions"`
	ExpiresAt    *time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	RevokedAt    *time.Time `json:"revoked_at" db:"revoked_at"`
}

// PasswordPolicy represents password policy settings
type PasswordPolicy struct {
	ID                    uuid.UUID `json:"id" db:"id"`
	MinLength             int       `json:"min_length" db:"min_length"`
	RequireUppercase      bool      `json:"require_uppercase" db:"require_uppercase"`
	RequireLowercase      bool      `json:"require_lowercase" db:"require_lowercase"`
	RequireNumbers        bool      `json:"require_numbers" db:"require_numbers"`
	RequireSpecialChars   bool      `json:"require_special_chars" db:"require_special_chars"`
	DisallowRepeatedChars bool      `json:"disallow_repeated_chars" db:"disallow_repeated_chars"`
	DisallowCommonWords   bool      `json:"disallow_common_words" db:"disallow_common_words"`
	PasswordHistoryCount  int       `json:"password_history_count" db:"password_history_count"`
	MaxAge                int       `json:"max_age" db:"max_age"`
	UpdatedAt             time.Time `json:"updated_at" db:"updated_at"`
}

// ComplianceReport represents compliance report data
type ComplianceReport struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	Type        string                 `json:"type" db:"type"`
	DateRange   DateRange              `json:"date_range" db:"date_range"`
	Data        map[string]interface{} `json:"data" db:"data"`
	GeneratedBy uuid.UUID              `json:"generated_by" db:"generated_by"`
	GeneratedAt time.Time              `json:"generated_at" db:"generated_at"`
}

// DateRange represents a date range
type DateRange struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
}

// EncryptionKey represents encryption keys
type EncryptionKey struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	KeyType   string     `json:"key_type" db:"key_type"`
	KeyData   string     `json:"-" db:"key_data"`
	Version   int        `json:"version" db:"version"`
	Active    bool       `json:"active" db:"active"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	RotatedAt *time.Time `json:"rotated_at" db:"rotated_at"`
}
