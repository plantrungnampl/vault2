package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID                     uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Email                  string         `json:"email" gorm:"uniqueIndex;not null"`
	PasswordHash           string         `json:"-" gorm:"column:password_hash;not null"`
	FirstName              string         `json:"first_name" gorm:"not null"`
	LastName               string         `json:"last_name" gorm:"not null"`
	Role                   UserRole       `json:"role" gorm:"default:'basic_user'"`
	Status                 UserStatus     `json:"status" gorm:"default:'pending'"`
	MFAEnabled             bool           `json:"mfa_enabled" gorm:"default:false"`
	MFASecret              string         `json:"-" gorm:"column:mfa_secret"`
	TwoFactorEnabled       bool           `json:"two_factor_enabled" gorm:"default:false"`
	EmailVerified          bool           `json:"email_verified" gorm:"default:false"`
	EmailVerificationToken string         `json:"-" gorm:"column:email_verification_token"`
	PasswordResetToken     string         `json:"-" gorm:"column:password_reset_token"`
	PasswordResetExpiry    *time.Time     `json:"-" gorm:"column:password_reset_expiry"`
	LoginAttempts          int            `json:"-" gorm:"default:0"`
	LockedUntil            *time.Time     `json:"-" gorm:"column:locked_until"`
	LastLoginAt            *time.Time     `json:"last_login_at" gorm:"column:last_login_at"`
	LastLoginIP            string         `json:"last_login_ip" gorm:"column:last_login_ip"`
	Preferences            datatypes.JSON `json:"preferences" gorm:"type:jsonb"`
	CreatedAt              time.Time      `json:"created_at"`
	UpdatedAt              time.Time      `json:"updated_at"`
	DeletedAt              gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	Sessions       []Session       `json:"sessions,omitempty" gorm:"foreignKey:UserID"`
	VaultItems     []VaultItem     `json:"vault_items,omitempty" gorm:"foreignKey:UserID"`
	VaultFolders   []VaultFolder   `json:"vault_folders,omitempty" gorm:"foreignKey:UserID"`
	AuditLogs      []AuditLog      `json:"audit_logs,omitempty" gorm:"foreignKey:UserID"`
	MFACredentials []MFACredential `json:"mfa_credentials,omitempty" gorm:"foreignKey:UserID"`
}

// MarshalJSON custom JSON marshaling for User to handle preferences
func (u User) MarshalJSON() ([]byte, error) {
	type Alias User
	var prefs UserPreferences
	if len(u.Preferences) > 0 {
		if err := json.Unmarshal(u.Preferences, &prefs); err != nil {
			return nil, err
		}
	}

	return json.Marshal(&struct {
		Alias
		Preferences UserPreferences `json:"preferences"`
	}{
		Alias:       (Alias)(u),
		Preferences: prefs,
	})
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
	ID           uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID       uuid.UUID      `json:"user_id" gorm:"type:uuid;not null;index"`
	TokenHash    string         `json:"-" gorm:"column:token_hash;not null;uniqueIndex"`
	RefreshToken string         `json:"-" gorm:"column:refresh_token;uniqueIndex"`
	IPAddress    string         `json:"ip_address" gorm:"column:ip_address"`
	UserAgent    string         `json:"user_agent" gorm:"column:user_agent"`
	DeviceInfo   datatypes.JSON `json:"device_info" gorm:"type:jsonb"`
	LastActivity time.Time      `json:"last_activity" gorm:"column:last_activity"`
	ExpiresAt    time.Time      `json:"expires_at" gorm:"column:expires_at;not null"`
	CreatedAt    time.Time      `json:"created_at"`
	RevokedAt    *time.Time     `json:"revoked_at,omitempty" gorm:"column:revoked_at"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	User User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// MarshalJSON custom JSON marshaling for Session to handle device_info
func (s Session) MarshalJSON() ([]byte, error) {
	type Alias Session
	var deviceInfo DeviceInfo
	if len(s.DeviceInfo) > 0 {
		if err := json.Unmarshal(s.DeviceInfo, &deviceInfo); err != nil {
			return nil, err
		}
	}

	return json.Marshal(&struct {
		Alias
		DeviceInfo DeviceInfo `json:"device_info"`
	}{
		Alias:      (Alias)(s),
		DeviceInfo: deviceInfo,
	})
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
	ID          uuid.UUID              `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID      uuid.UUID              `json:"user_id" gorm:"type:uuid;not null;index"`
	Name        string                 `json:"name" gorm:"not null"`
	Type        string                 `json:"type" gorm:"not null;index"`
	Data        map[string]interface{} `json:"data" gorm:"type:jsonb"`
	Notes       string                 `json:"notes"`
	FolderID    *uuid.UUID             `json:"folder_id" gorm:"type:uuid;index"`
	Tags        []string               `json:"tags" gorm:"type:text[]"`
	Favorite    bool                   `json:"favorite" gorm:"default:false"`
	Reprompt    bool                   `json:"reprompt" gorm:"default:false"`
	SharedWith  []string               `json:"shared_with" gorm:"type:text[]"`
	Permissions map[string]string      `json:"permissions" gorm:"type:jsonb"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	DeletedAt   gorm.DeletedAt         `json:"-" gorm:"index"`

	// Relationships
	User   User        `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Folder VaultFolder `json:"folder,omitempty" gorm:"foreignKey:FolderID"`
}

// VaultFolder represents a vault folder
type VaultFolder struct {
	ID        uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    uuid.UUID      `json:"user_id" gorm:"type:uuid;not null;index"`
	Name      string         `json:"name" gorm:"not null"`
	Color     string         `json:"color"`
	Icon      string         `json:"icon"`
	ParentID  *uuid.UUID     `json:"parent_id" gorm:"type:uuid;index"`
	ItemCount int            `json:"item_count" gorm:"default:0"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	User       User          `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Parent     *VaultFolder  `json:"parent,omitempty" gorm:"foreignKey:ParentID"`
	Subfolders []VaultFolder `json:"subfolders,omitempty" gorm:"foreignKey:ParentID"`
	Items      []VaultItem   `json:"items,omitempty" gorm:"foreignKey:FolderID"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID         uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID     uuid.UUID      `json:"user_id" gorm:"type:uuid;not null;index"`
	Action     string         `json:"action" gorm:"not null;index"`
	Resource   string         `json:"resource" gorm:"not null"`
	ResourceID string         `json:"resource_id"`
	IPAddress  string         `json:"ip_address" gorm:"index"`
	UserAgent  string         `json:"user_agent"`
	Success    bool           `json:"success" gorm:"default:true"`
	ErrorCode  string         `json:"error_code"`
	Details    interface{}    `json:"details" gorm:"type:jsonb"`
	Timestamp  time.Time      `json:"timestamp" gorm:"index;default:CURRENT_TIMESTAMP"`
	DeletedAt  gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	User User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// SecurityEvent represents a security event
type SecurityEvent struct {
	ID         uuid.UUID            `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Type       SecurityEventType    `json:"type" gorm:"not null;index"`
	Severity   SecuritySeverity     `json:"severity" gorm:"not null;index"`
	UserID     *uuid.UUID           `json:"user_id,omitempty" gorm:"type:uuid;index"`
	IPAddress  string               `json:"ip_address" gorm:"index"`
	Details    SecurityEventDetails `json:"details" gorm:"type:jsonb"`
	Resolved   bool                 `json:"resolved" gorm:"default:false"`
	ResolvedBy *uuid.UUID           `json:"resolved_by,omitempty" gorm:"type:uuid"`
	ResolvedAt *time.Time           `json:"resolved_at,omitempty"`
	Timestamp  time.Time            `json:"timestamp" gorm:"index;default:CURRENT_TIMESTAMP"`
	DeletedAt  gorm.DeletedAt       `json:"-" gorm:"index"`

	// Relationships
	User     *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Resolver *User `json:"resolver,omitempty" gorm:"foreignKey:ResolvedBy"`
}

// SecurityEventType represents types of security events
type SecurityEventType string

const (
	SecurityEventInvalidCredentials  SecurityEventType = "invalid_credentials"
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
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID      uuid.UUID      `json:"user_id" gorm:"type:uuid;not null;index"`
	Type        MFAType        `json:"type" gorm:"not null"`
	Name        string         `json:"name" gorm:"not null"`
	Secret      string         `json:"-" gorm:"column:secret"`
	BackupCodes []string       `json:"-" gorm:"type:text[]"`
	Verified    bool           `json:"verified" gorm:"default:false"`
	Primary     bool           `json:"primary" gorm:"default:false"`
	LastUsed    *time.Time     `json:"last_used"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	User User `json:"user,omitempty" gorm:"foreignKey:UserID"`
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
	ID                    uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	MinLength             int            `json:"min_length" gorm:"default:14"`
	RequireUppercase      bool           `json:"require_uppercase" gorm:"default:true"`
	RequireLowercase      bool           `json:"require_lowercase" gorm:"default:true"`
	RequireNumbers        bool           `json:"require_numbers" gorm:"default:true"`
	RequireSpecialChars   bool           `json:"require_special_chars" gorm:"default:true"`
	DisallowRepeatedChars bool           `json:"disallow_repeated_chars" gorm:"default:true"`
	DisallowCommonWords   bool           `json:"disallow_common_words" gorm:"default:true"`
	PasswordHistoryCount  int            `json:"password_history_count" gorm:"default:24"`
	MaxAge                int            `json:"max_age" gorm:"default:90"`
	UpdatedAt             time.Time      `json:"updated_at"`
	DeletedAt             gorm.DeletedAt `json:"-" gorm:"index"`
}

// ComplianceReport represents compliance report data
type ComplianceReport struct {
	ID          uuid.UUID              `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Type        string                 `json:"type" gorm:"not null"`
	DateRange   DateRange              `json:"date_range" gorm:"type:jsonb"`
	Data        map[string]interface{} `json:"data" gorm:"type:jsonb"`
	GeneratedBy uuid.UUID              `json:"generated_by" gorm:"type:uuid;not null"`
	GeneratedAt time.Time              `json:"generated_at" gorm:"default:CURRENT_TIMESTAMP"`
	DeletedAt   gorm.DeletedAt         `json:"-" gorm:"index"`

	// Relationships
	GeneratedByUser User `json:"generated_by_user,omitempty" gorm:"foreignKey:GeneratedBy"`
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

// ========== ADVANCED RBAC SYSTEM ==========

// Permission represents a specific permission in the system
type Permission struct {
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name        string         `json:"name" gorm:"uniqueIndex;not null"`
	Resource    string         `json:"resource" gorm:"not null;index"`
	Action      string         `json:"action" gorm:"not null;index"`
	Description string         `json:"description"`
	Category    string         `json:"category" gorm:"index"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	RolePermissions []RolePermission `json:"role_permissions,omitempty" gorm:"foreignKey:PermissionID"`
}

// Role represents a role with specific permissions
type Role struct {
	ID               uuid.UUID        `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name             UserRole         `json:"name" gorm:"uniqueIndex;not null"`
	DisplayName      string           `json:"display_name" gorm:"not null"`
	Description      string           `json:"description"`
	Level            int              `json:"level" gorm:"not null"` // Hierarchy level (1-6)
	IsSystemRole     bool             `json:"is_system_role" gorm:"default:true"`
	MaxItems         int              `json:"max_items" gorm:"default:-1"` // -1 = unlimited
	MaxSharedItems   int              `json:"max_shared_items" gorm:"default:0"`
	MaxTeamMembers   int              `json:"max_team_members" gorm:"default:0"`
	StorageLimit     int64            `json:"storage_limit" gorm:"default:-1"` // bytes, -1 = unlimited
	SessionTimeout   int              `json:"session_timeout" gorm:"default:3600"` // seconds
	MFARequired      bool             `json:"mfa_required" gorm:"default:false"`
	PasswordPolicy   datatypes.JSON   `json:"password_policy" gorm:"type:jsonb"`
	IPWhitelist      []string         `json:"ip_whitelist" gorm:"type:text[]"`
	TimeRestrictions datatypes.JSON   `json:"time_restrictions" gorm:"type:jsonb"`
	CreatedAt        time.Time        `json:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
	DeletedAt        gorm.DeletedAt   `json:"-" gorm:"index"`

	// Relationships
	Users           []User           `json:"users,omitempty" gorm:"foreignKey:Role;references:Name"`
	RolePermissions []RolePermission `json:"role_permissions,omitempty" gorm:"foreignKey:RoleID"`
}

// RolePermission represents the many-to-many relationship between roles and permissions
type RolePermission struct {
	ID           uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	RoleID       uuid.UUID      `json:"role_id" gorm:"type:uuid;not null;index"`
	PermissionID uuid.UUID      `json:"permission_id" gorm:"type:uuid;not null;index"`
	Conditions   datatypes.JSON `json:"conditions" gorm:"type:jsonb"` // JSON conditions for dynamic permissions
	GrantedBy    uuid.UUID      `json:"granted_by" gorm:"type:uuid"`
	GrantedAt    time.Time      `json:"granted_at" gorm:"default:CURRENT_TIMESTAMP"`
	ExpiresAt    *time.Time     `json:"expires_at,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	Role       Role       `json:"role,omitempty" gorm:"foreignKey:RoleID"`
	Permission Permission `json:"permission,omitempty" gorm:"foreignKey:PermissionID"`
	GrantedByUser *User   `json:"granted_by_user,omitempty" gorm:"foreignKey:GrantedBy"`
}

// UserPermissionOverride represents user-specific permission overrides
type UserPermissionOverride struct {
	ID           uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID       uuid.UUID      `json:"user_id" gorm:"type:uuid;not null;index"`
	PermissionID uuid.UUID      `json:"permission_id" gorm:"type:uuid;not null;index"`
	Granted      bool           `json:"granted"` // true = grant, false = revoke
	Reason       string         `json:"reason"`
	Conditions   datatypes.JSON `json:"conditions" gorm:"type:jsonb"`
	GrantedBy    uuid.UUID      `json:"granted_by" gorm:"type:uuid;not null"`
	GrantedAt    time.Time      `json:"granted_at" gorm:"default:CURRENT_TIMESTAMP"`
	ExpiresAt    *time.Time     `json:"expires_at,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	User       User       `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Permission Permission `json:"permission,omitempty" gorm:"foreignKey:PermissionID"`
	GrantedByUser User    `json:"granted_by_user,omitempty" gorm:"foreignKey:GrantedBy"`
}

// ResourceAccess represents access control for specific resources
type ResourceAccess struct {
	ID         uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID     uuid.UUID      `json:"user_id" gorm:"type:uuid;not null;index"`
	ResourceType string       `json:"resource_type" gorm:"not null;index"`
	ResourceID uuid.UUID      `json:"resource_id" gorm:"type:uuid;not null;index"`
	AccessLevel AccessLevel   `json:"access_level" gorm:"not null"`
	Permissions []string      `json:"permissions" gorm:"type:text[]"`
	GrantedBy   uuid.UUID     `json:"granted_by" gorm:"type:uuid"`
	GrantedAt   time.Time     `json:"granted_at" gorm:"default:CURRENT_TIMESTAMP"`
	ExpiresAt   *time.Time    `json:"expires_at,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	User User `json:"user,omitempty" gorm:"foreignKey:UserID"`
	GrantedByUser *User `json:"granted_by_user,omitempty" gorm:"foreignKey:GrantedBy"`
}

// AccessLevel represents different levels of access
type AccessLevel string

const (
	AccessLevelNone   AccessLevel = "none"
	AccessLevelRead   AccessLevel = "read"
	AccessLevelWrite  AccessLevel = "write"
	AccessLevelModify AccessLevel = "modify"
	AccessLevelDelete AccessLevel = "delete"
	AccessLevelAdmin  AccessLevel = "admin"
	AccessLevelOwner  AccessLevel = "owner"
)

// PermissionContext represents context for permission evaluation
type PermissionContext struct {
	UserID       uuid.UUID              `json:"user_id"`
	Role         UserRole               `json:"role"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	Resource     string                 `json:"resource"`
	ResourceID   *uuid.UUID             `json:"resource_id,omitempty"`
	Action       string                 `json:"action"`
	Time         time.Time              `json:"time"`
	SessionID    string                 `json:"session_id"`
	DeviceInfo   map[string]interface{} `json:"device_info"`
	GeolocationData map[string]interface{} `json:"geolocation_data"`
	SecurityLevel SecurityLevel        `json:"security_level"`
	MFAVerified  bool                   `json:"mfa_verified"`
	RiskScore    float64                `json:"risk_score"`
}

// SecurityLevel represents security levels for permission evaluation
type SecurityLevel string

const (
	SecurityLevelLow      SecurityLevel = "low"
	SecurityLevelStandard SecurityLevel = "standard"
	SecurityLevelHigh     SecurityLevel = "high"
	SecurityLevelCritical SecurityLevel = "critical"
)

// PermissionCondition represents dynamic permission conditions
type PermissionCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // eq, ne, gt, lt, gte, lte, in, not_in, contains, regex
	Value    interface{} `json:"value"`
	LogicalOp string     `json:"logical_op,omitempty"` // and, or (for chaining conditions)
}

// TimeRestriction represents time-based access restrictions
type TimeRestriction struct {
	DaysOfWeek    []int  `json:"days_of_week"`    // 0=Sunday, 1=Monday, etc.
	StartTime     string `json:"start_time"`      // HH:MM format
	EndTime       string `json:"end_time"`        // HH:MM format
	Timezone      string `json:"timezone"`
	DateRanges    []DateRange `json:"date_ranges,omitempty"`
	Exceptions    []string    `json:"exceptions,omitempty"` // Exception dates (YYYY-MM-DD)
}

// RoleHierarchy represents the role hierarchy for inheritance
type RoleHierarchy struct {
	ID        uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	ParentRole UserRole      `json:"parent_role" gorm:"not null;index"`
	ChildRole  UserRole      `json:"child_role" gorm:"not null;index"`
	CreatedAt time.Time      `json:"created_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// PermissionTemplate represents pre-defined permission templates
type PermissionTemplate struct {
	ID          uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name        string         `json:"name" gorm:"uniqueIndex;not null"`
	Description string         `json:"description"`
	Category    string         `json:"category" gorm:"index"`
	Permissions []uuid.UUID    `json:"permissions" gorm:"type:uuid[]"`
	IsActive    bool           `json:"is_active" gorm:"default:true"`
	CreatedBy   uuid.UUID      `json:"created_by" gorm:"type:uuid"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	CreatedByUser User `json:"created_by_user,omitempty" gorm:"foreignKey:CreatedBy"`
}

// ========== PREDEFINED PERMISSIONS ==========

// Standard permissions for the SecureVault system
var SystemPermissions = []Permission{
	// Vault Management
	{Name: "vault.items.create", Resource: "vault_items", Action: "create", Description: "Tạo mục vault mới", Category: "vault"},
	{Name: "vault.items.read", Resource: "vault_items", Action: "read", Description: "Xem mục vault", Category: "vault"},
	{Name: "vault.items.update", Resource: "vault_items", Action: "update", Description: "Cập nhật mục vault", Category: "vault"},
	{Name: "vault.items.delete", Resource: "vault_items", Action: "delete", Description: "Xóa mục vault", Category: "vault"},
	{Name: "vault.items.share", Resource: "vault_items", Action: "share", Description: "Chia sẻ mục vault", Category: "vault"},
	{Name: "vault.items.export", Resource: "vault_items", Action: "export", Description: "Xuất dữ liệu vault", Category: "vault"},
	{Name: "vault.items.import", Resource: "vault_items", Action: "import", Description: "Nhập dữ liệu vault", Category: "vault"},
	
	// Folder Management
	{Name: "vault.folders.create", Resource: "vault_folders", Action: "create", Description: "Tạo thư mục vault", Category: "vault"},
	{Name: "vault.folders.read", Resource: "vault_folders", Action: "read", Description: "Xem thư mục vault", Category: "vault"},
	{Name: "vault.folders.update", Resource: "vault_folders", Action: "update", Description: "Cập nhật thư mục vault", Category: "vault"},
	{Name: "vault.folders.delete", Resource: "vault_folders", Action: "delete", Description: "Xóa thư mục vault", Category: "vault"},
	
	// User Management
	{Name: "users.create", Resource: "users", Action: "create", Description: "Tạo người dùng mới", Category: "admin"},
	{Name: "users.read", Resource: "users", Action: "read", Description: "Xem thông tin người dùng", Category: "admin"},
	{Name: "users.update", Resource: "users", Action: "update", Description: "Cập nhật người dùng", Category: "admin"},
	{Name: "users.delete", Resource: "users", Action: "delete", Description: "Xóa người dùng", Category: "admin"},
	{Name: "users.suspend", Resource: "users", Action: "suspend", Description: "Tạm ngưng tài khoản", Category: "admin"},
	{Name: "users.activate", Resource: "users", Action: "activate", Description: "Kích hoạt tài khoản", Category: "admin"},
	{Name: "users.reset_password", Resource: "users", Action: "reset_password", Description: "Đặt lại mật khẩu", Category: "admin"},
	{Name: "users.manage_roles", Resource: "users", Action: "manage_roles", Description: "Quản lý vai trò người dùng", Category: "admin"},
	{Name: "users.view_sessions", Resource: "users", Action: "view_sessions", Description: "Xem phiên đăng nhập", Category: "admin"},
	{Name: "users.terminate_sessions", Resource: "users", Action: "terminate_sessions", Description: "Kết thúc phiên đăng nhập", Category: "admin"},
	
	// Security Management
	{Name: "security.incidents.read", Resource: "security_events", Action: "read", Description: "Xem sự cố bảo mật", Category: "security"},
	{Name: "security.incidents.resolve", Resource: "security_events", Action: "resolve", Description: "Giải quyết sự cố bảo mật", Category: "security"},
	{Name: "security.audit_logs.read", Resource: "audit_logs", Action: "read", Description: "Xem nhật ký audit", Category: "security"},
	{Name: "security.audit_logs.export", Resource: "audit_logs", Action: "export", Description: "Xuất nhật ký audit", Category: "security"},
	{Name: "security.policies.read", Resource: "policies", Action: "read", Description: "Xem chính sách bảo mật", Category: "security"},
	{Name: "security.policies.update", Resource: "policies", Action: "update", Description: "Cập nhật chính sách bảo mật", Category: "security"},
	{Name: "security.mfa.manage", Resource: "mfa", Action: "manage", Description: "Quản lý MFA", Category: "security"},
	{Name: "security.keys.rotate", Resource: "encryption_keys", Action: "rotate", Description: "Xoay vòng khóa mã hóa", Category: "security"},
	
	// System Administration
	{Name: "system.health.read", Resource: "system", Action: "health_check", Description: "Kiểm tra sức khỏe hệ thống", Category: "system"},
	{Name: "system.config.read", Resource: "system", Action: "config_read", Description: "Xem cấu hình hệ thống", Category: "system"},
	{Name: "system.config.update", Resource: "system", Action: "config_update", Description: "Cập nhật cấu hình hệ thống", Category: "system"},
	{Name: "system.backup.create", Resource: "system", Action: "backup_create", Description: "Tạo sao lưu hệ thống", Category: "system"},
	{Name: "system.backup.restore", Resource: "system", Action: "backup_restore", Description: "Khôi phục từ sao lưu", Category: "system"},
	{Name: "system.maintenance.manage", Resource: "system", Action: "maintenance", Description: "Quản lý bảo trì hệ thống", Category: "system"},
	
	// Reporting
	{Name: "reports.compliance.generate", Resource: "reports", Action: "generate", Description: "Tạo báo cáo tuân thủ", Category: "reports"},
	{Name: "reports.usage.view", Resource: "reports", Action: "view", Description: "Xem báo cáo sử dụng", Category: "reports"},
	{Name: "reports.security.view", Resource: "reports", Action: "security_view", Description: "Xem báo cáo bảo mật", Category: "reports"},
	
	// Team Management
	{Name: "teams.create", Resource: "teams", Action: "create", Description: "Tạo nhóm", Category: "team"},
	{Name: "teams.read", Resource: "teams", Action: "read", Description: "Xem nhóm", Category: "team"},
	{Name: "teams.update", Resource: "teams", Action: "update", Description: "Cập nhật nhóm", Category: "team"},
	{Name: "teams.delete", Resource: "teams", Action: "delete", Description: "Xóa nhóm", Category: "team"},
	{Name: "teams.manage_members", Resource: "teams", Action: "manage_members", Description: "Quản lý thành viên nhóm", Category: "team"},
}

// Role definitions with hierarchical levels and permissions
var SystemRoles = []Role{
	{
		Name:             RoleBasicUser,
		DisplayName:      "Người dùng cơ bản",
		Description:      "Quyền truy cập cơ bản cho vault cá nhân",
		Level:            1,
		IsSystemRole:     true,
		MaxItems:         50,
		MaxSharedItems:   5,
		MaxTeamMembers:   0,
		StorageLimit:     1024 * 1024 * 100, // 100MB
		SessionTimeout:   3600,              // 1 hour
		MFARequired:      false,
	},
	{
		Name:             RolePremiumUser,
		DisplayName:      "Người dùng cao cấp",
		Description:      "Quyền truy cập mở rộng với tính năng premium",
		Level:            2,
		IsSystemRole:     true,
		MaxItems:         500,
		MaxSharedItems:   50,
		MaxTeamMembers:   5,
		StorageLimit:     1024 * 1024 * 1024, // 1GB
		SessionTimeout:   7200,               // 2 hours
		MFARequired:      false,
	},
	{
		Name:             RoleTeamMember,
		DisplayName:      "Thành viên nhóm",
		Description:      "Quyền truy cập cho thành viên trong nhóm",
		Level:            3,
		IsSystemRole:     true,
		MaxItems:         1000,
		MaxSharedItems:   100,
		MaxTeamMembers:   0,
		StorageLimit:     1024 * 1024 * 1024 * 5, // 5GB
		SessionTimeout:   14400,                  // 4 hours
		MFARequired:      true,
	},
	{
		Name:             RoleVaultAdmin,
		DisplayName:      "Quản trị viên Vault",
		Description:      "Quản lý vault và người dùng trong tổ chức",
		Level:            4,
		IsSystemRole:     true,
		MaxItems:         -1, // unlimited
		MaxSharedItems:   -1, // unlimited
		MaxTeamMembers:   50,
		StorageLimit:     -1, // unlimited
		SessionTimeout:   28800, // 8 hours
		MFARequired:      true,
	},
	{
		Name:             RoleSecurityAdmin,
		DisplayName:      "Quản trị viên Bảo mật",
		Description:      "Quản lý bảo mật và tuân thủ hệ thống",
		Level:            5,
		IsSystemRole:     true,
		MaxItems:         -1, // unlimited
		MaxSharedItems:   -1, // unlimited
		MaxTeamMembers:   100,
		StorageLimit:     -1, // unlimited
		SessionTimeout:   28800, // 8 hours
		MFARequired:      true,
	},
	{
		Name:             RoleSuperAdmin,
		DisplayName:      "Quản trị viên tối cao",
		Description:      "Quyền truy cập toàn bộ hệ thống",
		Level:            6,
		IsSystemRole:     true,
		MaxItems:         -1, // unlimited
		MaxSharedItems:   -1, // unlimited
		MaxTeamMembers:   -1, // unlimited
		StorageLimit:     -1, // unlimited
		SessionTimeout:   43200, // 12 hours
		MFARequired:      true,
	},
}
