package database

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
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
	MFABackupCodes         StringArray     `json:"-" db:"mfa_backup_codes"`
	LoginAttempts          int             `json:"-" db:"login_attempts"`
	LockedUntil            *time.Time      `json:"-" db:"locked_until"`
	LastLoginAt            *time.Time      `json:"last_login_at" db:"last_login_at"`
	LastLoginIP            string          `json:"last_login_ip" db:"last_login_ip"`
	PasswordHistory        StringArray     `json:"-" db:"password_history"`
	TwoFactorEnabled       bool            `json:"two_factor_enabled" db:"two_factor_enabled"`
	TwoFactorMethods       MFAMethods      `json:"two_factor_methods" db:"two_factor_methods"`
	EmailVerified          bool            `json:"email_verified" db:"email_verified"`
	EmailVerificationToken string          `json:"-" db:"email_verification_token"`
	PasswordResetToken     string          `json:"-" db:"password_reset_token"`
	PasswordResetExpiry    *time.Time      `json:"-" db:"password_reset_expiry"`
	Preferences            UserPreferences `json:"preferences" db:"preferences"`
	CreatedAt              time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt              time.Time       `json:"updated_at" db:"updated_at"`
	DeletedAt              *time.Time      `json:"deleted_at,omitempty" db:"deleted_at"`
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
	StatusSuspended UserStatus = "suspended"
	StatusPending   UserStatus = "pending"
	StatusDeleted   UserStatus = "deleted"
)

// MFAMethod represents a multi-factor authentication method
type MFAMethod struct {
	ID        uuid.UUID  `json:"id"`
	Type      MFAType    `json:"type"`
	Name      string     `json:"name"`
	Data      MFAData    `json:"data"`
	Verified  bool       `json:"verified"`
	CreatedAt time.Time  `json:"created_at"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
}

// MFAType represents types of MFA
type MFAType string

const (
	MFATypeTOTP     MFAType = "totp"
	MFATypeWebAuthn MFAType = "webauthn"
	MFATypeSMS      MFAType = "sms"
	MFATypeEmail    MFAType = "email"
)

// MFAData holds MFA-specific data
type MFAData struct {
	Secret       string                 `json:"secret,omitempty"`
	PhoneNumber  string                 `json:"phone_number,omitempty"`
	CredentialID string                 `json:"credential_id,omitempty"`
	PublicKey    string                 `json:"public_key,omitempty"`
	Counter      uint32                 `json:"counter,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// UserPreferences holds user preferences
type UserPreferences struct {
	Language      string               `json:"language"`
	Theme         string               `json:"theme"`
	Timezone      string               `json:"timezone"`
	Notifications NotificationSettings `json:"notifications"`
}

// NotificationSettings holds notification preferences
type NotificationSettings struct {
	Email    bool `json:"email"`
	SMS      bool `json:"sms"`
	Push     bool `json:"push"`
	Security bool `json:"security"`
}

// VaultItem represents an encrypted vault item
type VaultItem struct {
	ID           uuid.UUID          `json:"id" db:"id"`
	UserID       uuid.UUID          `json:"user_id" db:"user_id"`
	FolderID     *uuid.UUID         `json:"folder_id,omitempty" db:"folder_id"`
	Type         VaultItemType      `json:"type" db:"type"`
	Name         string             `json:"name" db:"name"`
	Data         EncryptedData      `json:"data" db:"data"`
	SearchTokens StringArray        `json:"-" db:"search_tokens"`
	Tags         StringArray        `json:"tags" db:"tags"`
	Favorite     bool               `json:"favorite" db:"favorite"`
	SharedWith   ShareInfoArray     `json:"shared_with" db:"shared_with"`
	LastUsed     *time.Time         `json:"last_used" db:"last_used"`
	ExpiresAt    *time.Time         `json:"expires_at,omitempty" db:"expires_at"`
	Version      int                `json:"version" db:"version"`
	History      []VaultItemHistory `json:"-" db:"history"`
	CreatedAt    time.Time          `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at" db:"updated_at"`
	DeletedAt    *time.Time         `json:"deleted_at,omitempty" db:"deleted_at"`
}

// VaultItemType represents types of vault items
type VaultItemType string

const (
	VaultItemTypePassword   VaultItemType = "password"
	VaultItemTypeSecureNote VaultItemType = "secure_note"
	VaultItemTypeCreditCard VaultItemType = "credit_card"
	VaultItemTypeIdentity   VaultItemType = "identity"
	VaultItemTypeCryptoKey  VaultItemType = "crypto_key"
	VaultItemTypeFile       VaultItemType = "file"
)

// EncryptedData represents encrypted vault item data
type EncryptedData struct {
	Data      string    `json:"data"`
	Nonce     string    `json:"nonce"`
	Algorithm string    `json:"algorithm"`
	KeyID     string    `json:"key_id"`
	Timestamp time.Time `json:"timestamp"`
}

// ShareInfo represents sharing information
type ShareInfo struct {
	UserID      uuid.UUID   `json:"user_id"`
	Email       string      `json:"email"`
	Permissions Permissions `json:"permissions"`
	SharedAt    time.Time   `json:"shared_at"`
	ExpiresAt   *time.Time  `json:"expires_at,omitempty"`
}

// Permissions represents item permissions
type Permissions struct {
	Read   bool `json:"read"`
	Write  bool `json:"write"`
	Delete bool `json:"delete"`
	Share  bool `json:"share"`
}

// VaultItemHistory represents item version history
type VaultItemHistory struct {
	ID        uuid.UUID     `json:"id"`
	Version   int           `json:"version"`
	Data      EncryptedData `json:"data"`
	ChangedBy uuid.UUID     `json:"changed_by"`
	ChangedAt time.Time     `json:"changed_at"`
	Action    string        `json:"action"`
}

// Folder represents a vault folder
type Folder struct {
	ID         uuid.UUID      `json:"id" db:"id"`
	UserID     uuid.UUID      `json:"user_id" db:"user_id"`
	ParentID   *uuid.UUID     `json:"parent_id,omitempty" db:"parent_id"`
	Name       string         `json:"name" db:"name"`
	Color      string         `json:"color" db:"color"`
	Icon       string         `json:"icon" db:"icon"`
	SharedWith ShareInfoArray `json:"shared_with" db:"shared_with"`
	CreatedAt  time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at" db:"updated_at"`
	DeletedAt  *time.Time     `json:"deleted_at,omitempty" db:"deleted_at"`
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

// AuditLog represents an audit log entry
type AuditLog struct {
	ID         uuid.UUID              `json:"id" db:"id"`
	UserID     *uuid.UUID             `json:"user_id,omitempty" db:"user_id"`
	Action     string                 `json:"action" db:"action"`
	Resource   string                 `json:"resource" db:"resource"`
	ResourceID *uuid.UUID             `json:"resource_id,omitempty" db:"resource_id"`
	Details    map[string]interface{} `json:"details" db:"details"`
	IPAddress  string                 `json:"ip_address" db:"ip_address"`
	UserAgent  string                 `json:"user_agent" db:"user_agent"`
	Success    bool                   `json:"success" db:"success"`
	Error      string                 `json:"error,omitempty" db:"error"`
	Timestamp  time.Time              `json:"timestamp" db:"timestamp"`
	HashChain  string                 `json:"hash_chain" db:"hash_chain"`
}

// SecurityPolicy represents security policies
type SecurityPolicy struct {
	ID        uuid.UUID              `json:"id" db:"id"`
	Name      string                 `json:"name" db:"name"`
	Category  string                 `json:"category" db:"category"`
	Rules     map[string]interface{} `json:"rules" db:"rules"`
	Enabled   bool                   `json:"enabled" db:"enabled"`
	CreatedBy uuid.UUID              `json:"created_by" db:"created_by"`
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt time.Time              `json:"updated_at" db:"updated_at"`
}

// SystemConfig represents system configuration
type SystemConfig struct {
	ID        uuid.UUID              `json:"id" db:"id"`
	Key       string                 `json:"key" db:"key"`
	Value     map[string]interface{} `json:"value" db:"value"`
	Category  string                 `json:"category" db:"category"`
	UpdatedBy uuid.UUID              `json:"updated_by" db:"updated_by"`
	UpdatedAt time.Time              `json:"updated_at" db:"updated_at"`
}

// Value implements driver.Valuer for JSON fields
func (j EncryptedData) Value() (driver.Value, error) {
	return json.Marshal(j)
}

// Scan implements sql.Scanner for JSON fields
func (j *EncryptedData) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into EncryptedData", value)
	}

	return json.Unmarshal(bytes, j)
}

// MFAMethods is a custom type for []MFAMethod to implement driver.Valuer and sql.Scanner
type MFAMethods []MFAMethod

// Value implements driver.Valuer for JSON fields
func (m MFAMethods) Value() (driver.Value, error) {
	return json.Marshal(m)
}

// Scan implements sql.Scanner for JSON fields
func (m *MFAMethods) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into MFAMethods", value)
	}

	return json.Unmarshal(bytes, m)
}

// Value implements driver.Valuer for JSON fields
func (p UserPreferences) Value() (driver.Value, error) {
	return json.Marshal(p)
}

// Scan implements sql.Scanner for JSON fields
func (p *UserPreferences) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into UserPreferences", value)
	}

	return json.Unmarshal(bytes, p)
}

// StringArray is a custom type for []string to implement driver.Valuer and sql.Scanner
type StringArray []string

// Value implements driver.Valuer for string arrays
func (s StringArray) Value() (driver.Value, error) {
	return json.Marshal(s)
}

// Scan implements sql.Scanner for string arrays
func (s *StringArray) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into StringArray", value)
	}

	return json.Unmarshal(bytes, s)
}

// ShareInfoArray is a custom type for []ShareInfo to implement driver.Valuer and sql.Scanner
type ShareInfoArray []ShareInfo

// Value implements driver.Valuer for ShareInfo arrays
func (s ShareInfoArray) Value() (driver.Value, error) {
	return json.Marshal(s)
}

// Scan implements sql.Scanner for ShareInfo arrays
func (s *ShareInfoArray) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into ShareInfoArray", value)
	}

	return json.Unmarshal(bytes, s)
}

// Value implements driver.Valuer for DeviceInfo
func (d DeviceInfo) Value() (driver.Value, error) {
	return json.Marshal(d)
}

// Scan implements sql.Scanner for DeviceInfo
func (d *DeviceInfo) Scan(value interface{}) error {
	if value == nil {
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into DeviceInfo", value)
	}

	return json.Unmarshal(bytes, d)
}
