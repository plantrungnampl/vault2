package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"securevault/internal/database"
	"securevault/internal/models"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserService struct {
	db *gorm.DB
}

func NewUserService() *UserService {
	return &UserService{
		db: database.GetDB(),
	}
}

// CreateUser creates a new user with encrypted password
func (s *UserService) CreateUser(email, password, firstName, lastName string) (*models.User, error) {
	// Check if user already exists
	var existingUser models.User
	if err := s.db.Where("email = ?", email).First(&existingUser).Error; err == nil {
		return nil, errors.New("user already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}

	// Create user preferences
	prefs := models.UserPreferences{
		Language: "en",
		Theme:    "light",
		Timezone: "UTC",
		Notifications: models.NotificationSettings{
			Email:    true,
			SMS:      false,
			Push:     true,
			Security: true,
		},
	}

	prefsJSON, err := json.Marshal(prefs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal preferences: %v", err)
	}

	// Create user
	user := &models.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: string(hashedPassword),
		FirstName:    firstName,
		LastName:     lastName,
		Role:         models.RoleBasicUser,
		Status:       models.StatusActive,
		Preferences:  prefsJSON,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.db.Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	return user, nil
}

// GetUserByEmail retrieves user by email
func (s *UserService) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	if err := s.db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %v", err)
	}
	return &user, nil
}

// GetUserByID retrieves user by ID
func (s *UserService) GetUserByID(id uuid.UUID) (*models.User, error) {
	var user models.User
	if err := s.db.Where("id = ?", id).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %v", err)
	}
	return &user, nil
}

// UpdateUser updates user information
func (s *UserService) UpdateUser(id uuid.UUID, updates map[string]interface{}) (*models.User, error) {
	var user models.User
	if err := s.db.Where("id = ?", id).First(&user).Error; err != nil {
		return nil, errors.New("user not found")
	}

	updates["updated_at"] = time.Now()
	if err := s.db.Model(&user).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("failed to update user: %v", err)
	}

	return &user, nil
}

// VerifyPassword verifies user password
func (s *UserService) VerifyPassword(user *models.User, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	return err == nil
}

// ChangePassword changes user password
func (s *UserService) ChangePassword(userID uuid.UUID, currentPassword, newPassword string) error {
	user, err := s.GetUserByID(userID)
	if err != nil {
		return err
	}

	// Verify current password
	if !s.VerifyPassword(user, currentPassword) {
		return errors.New("invalid current password")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %v", err)
	}

	// Update password
	if err := s.db.Model(user).Update("password_hash", string(hashedPassword)).Error; err != nil {
		return fmt.Errorf("failed to update password: %v", err)
	}

	return nil
}

// ActivateUser activates a pending user account
func (s *UserService) ActivateUser(userID uuid.UUID) error {
	return s.db.Model(&models.User{}).Where("id = ?", userID).
		Updates(map[string]interface{}{
			"status":         models.StatusActive,
			"email_verified": true,
			"updated_at":     time.Now(),
		}).Error
}

// DeactivateUser deactivates a user account
func (s *UserService) DeactivateUser(userID uuid.UUID) error {
	return s.db.Model(&models.User{}).Where("id = ?", userID).
		Updates(map[string]interface{}{
			"status":     models.StatusDeactive,
			"updated_at": time.Now(),
		}).Error
}

// RecordLoginAttempt records a login attempt
func (s *UserService) RecordLoginAttempt(userID uuid.UUID, success bool, ipAddress string) error {
	user, err := s.GetUserByID(userID)
	if err != nil {
		return err
	}

	updates := map[string]interface{}{
		"last_login_ip": ipAddress,
		"updated_at":    time.Now(),
	}

	if success {
		updates["login_attempts"] = 0
		updates["last_login_at"] = time.Now()
	} else {
		updates["login_attempts"] = user.LoginAttempts + 1

		// Lock account if too many failed attempts
		if user.LoginAttempts+1 >= 5 {
			lockUntil := time.Now().Add(30 * time.Minute)
			updates["locked_until"] = &lockUntil
		}
	}

	return s.db.Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error
}

// IsAccountLocked checks if user account is locked
func (s *UserService) IsAccountLocked(userID uuid.UUID) (bool, error) {
	user, err := s.GetUserByID(userID)
	if err != nil {
		return false, err
	}

	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		return true, nil
	}

	return false, nil
}

// UnlockAccount unlocks a user account
func (s *UserService) UnlockAccount(userID uuid.UUID) error {
	return s.db.Model(&models.User{}).Where("id = ?", userID).
		Updates(map[string]interface{}{
			"login_attempts": 0,
			"locked_until":   nil,
			"updated_at":     time.Now(),
		}).Error
}

// EnableMFA enables MFA for user
func (s *UserService) EnableMFA(userID uuid.UUID) error {
	return s.db.Model(&models.User{}).Where("id = ?", userID).
		Updates(map[string]interface{}{
			"mfa_enabled": true,
			"updated_at":  time.Now(),
		}).Error
}

// DisableMFA disables MFA for user
func (s *UserService) DisableMFA(userID uuid.UUID) error {
	return s.db.Model(&models.User{}).Where("id = ?", userID).
		Updates(map[string]interface{}{
			"mfa_enabled": false,
			"updated_at":  time.Now(),
		}).Error
}

// ListUsers returns paginated list of users
func (s *UserService) ListUsers(offset, limit int, search string) ([]models.User, int64, error) {
	var users []models.User
	var total int64

	query := s.db.Model(&models.User{})

	if search != "" {
		query = query.Where("email ILIKE ? OR first_name ILIKE ? OR last_name ILIKE ?",
			"%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	// Get total count
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %v", err)
	}

	// Get users with pagination
	if err := query.Offset(offset).Limit(limit).Order("created_at DESC").Find(&users).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %v", err)
	}

	return users, total, nil
}

// DeleteUser soft deletes a user
func (s *UserService) DeleteUser(userID uuid.UUID) error {
	return s.db.Delete(&models.User{}, userID).Error
}

// GetUserStats returns user statistics
func (s *UserService) GetUserStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total users
	var totalUsers int64
	if err := s.db.Model(&models.User{}).Count(&totalUsers).Error; err != nil {
		return nil, err
	}
	stats["total_users"] = totalUsers

	// Active users
	var activeUsers int64
	if err := s.db.Model(&models.User{}).Where("status = ?", models.StatusActive).Count(&activeUsers).Error; err != nil {
		return nil, err
	}
	stats["active_users"] = activeUsers

	// Users with MFA enabled
	var mfaUsers int64
	if err := s.db.Model(&models.User{}).Where("mfa_enabled = ?", true).Count(&mfaUsers).Error; err != nil {
		return nil, err
	}
	stats["mfa_enabled_users"] = mfaUsers

	// New users this month
	startOfMonth := time.Now().AddDate(0, 0, -time.Now().Day()+1)
	var newUsersThisMonth int64
	if err := s.db.Model(&models.User{}).Where("created_at >= ?", startOfMonth).Count(&newUsersThisMonth).Error; err != nil {
		return nil, err
	}
	stats["new_users_this_month"] = newUsersThisMonth

	return stats, nil
}

// GetUsers returns paginated users with filtering
func (s *UserService) GetUsers(page, limit int, filters map[string]interface{}) ([]*models.User, int64, error) {
	var users []*models.User
	var total int64

	query := s.db.Model(&models.User{})

	// Apply filters
	if role, ok := filters["role"].(string); ok && role != "" {
		query = query.Where("role = ?", role)
	}
	if status, ok := filters["status"].(string); ok && status != "" {
		query = query.Where("status = ?", status)
	}
	if search, ok := filters["search"].(string); ok && search != "" {
		query = query.Where("email ILIKE ? OR first_name ILIKE ? OR last_name ILIKE ?",
			"%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	// Get total count
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %v", err)
	}

	// Get paginated results
	offset := (page - 1) * limit
	if err := query.Offset(offset).Limit(limit).Order("created_at DESC").Find(&users).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to get users: %v", err)
	}

	return users, total, nil
}

// InvalidateUserSessions invalidates all active sessions for a user
func (s *UserService) InvalidateUserSessions(userID uuid.UUID) error {
	// In a real implementation, this would invalidate sessions in Redis or database
	// For now, we'll just log it
	fmt.Printf("Invalidating all sessions for user: %s\n", userID.String())
	return nil
}

// AdminResetPassword allows admin to reset user password
func (s *UserService) AdminResetPassword(userID uuid.UUID, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	updates := map[string]interface{}{
		"password_hash": string(hashedPassword),
		"updated_at":    time.Now(),
	}

	if err := s.db.Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to reset password: %v", err)
	}

	return nil
}
