package services

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"securevault/internal/config"
	"securevault/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RBACService handles role-based access control operations
type RBACService struct {
	db     *gorm.DB
	config *config.Config
}

// NewRBACService creates a new RBAC service
func NewRBACService(db *gorm.DB, cfg *config.Config) *RBACService {
	return &RBACService{
		db:     db,
		config: cfg,
	}
}

// CheckPermission performs comprehensive permission checking
func (r *RBACService) CheckPermission(ctx context.Context, permCtx models.PermissionContext) (bool, error) {
	// Step 1: Get user and role information
	user, role, err := r.getUserAndRole(ctx, permCtx.UserID)
	if err != nil {
		return false, fmt.Errorf("không thể lấy thông tin người dùng: %w", err)
	}

	// Step 2: Check user status and account restrictions
	if !r.checkUserStatus(user) {
		return false, fmt.Errorf("tài khoản không hoạt động hoặc bị khóa")
	}

	// Step 3: Check time restrictions
	if !r.checkTimeRestrictions(role, permCtx.Time) {
		return false, fmt.Errorf("truy cập bị hạn chế theo thời gian")
	}

	// Step 4: Check IP whitelist
	if !r.checkIPWhitelist(role, permCtx.IPAddress) {
		return false, fmt.Errorf("địa chỉ IP không được phép")
	}

	// Step 5: Check MFA requirements
	if !r.checkMFARequirements(role, permCtx.MFAVerified) {
		return false, fmt.Errorf("yêu cầu xác thực đa yếu tố")
	}

	// Step 6: Check role-based permissions
	hasRolePermission, err := r.checkRolePermission(ctx, role.ID, permCtx)
	if err != nil {
		return false, fmt.Errorf("lỗi kiểm tra quyền vai trò: %w", err)
	}

	// Step 7: Check user-specific permission overrides
	hasOverride, overrideGranted, err := r.checkUserPermissionOverride(ctx, permCtx.UserID, permCtx)
	if err != nil {
		return false, fmt.Errorf("lỗi kiểm tra quyền cá nhân: %w", err)
	}

	// Step 8: Apply override logic
	if hasOverride {
		// User-specific override takes precedence
		return overrideGranted, nil
	}

	// Step 9: Check resource-specific access
	if permCtx.ResourceID != nil {
		hasResourceAccess, err := r.checkResourceAccess(ctx, permCtx.UserID, permCtx)
		if err != nil {
			return false, fmt.Errorf("lỗi kiểm tra quyền tài nguyên: %w", err)
		}
		
		// Resource access can grant additional permissions
		if hasResourceAccess {
			return true, nil
		}
	}

	// Step 10: Final permission evaluation
	return hasRolePermission, nil
}

// GrantPermissionToRole grants a permission to a role
func (r *RBACService) GrantPermissionToRole(ctx context.Context, roleID, permissionID, grantedBy uuid.UUID, conditions map[string]interface{}) error {
	conditionsJSON, err := json.Marshal(conditions)
	if err != nil {
		return fmt.Errorf("lỗi mã hóa điều kiện: %w", err)
	}

	rolePermission := models.RolePermission{
		RoleID:       roleID,
		PermissionID: permissionID,
		Conditions:   conditionsJSON,
		GrantedBy:    grantedBy,
		GrantedAt:    time.Now(),
	}

	if err := r.db.Create(&rolePermission).Error; err != nil {
		return fmt.Errorf("không thể cấp quyền cho vai trò: %w", err)
	}

	return nil
}

// RevokePermissionFromRole revokes a permission from a role
func (r *RBACService) RevokePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	if err := r.db.Where("role_id = ? AND permission_id = ?", roleID, permissionID).Delete(&models.RolePermission{}).Error; err != nil {
		return fmt.Errorf("không thể thu hồi quyền từ vai trò: %w", err)
	}
	return nil
}

// GrantPermissionToUser grants a specific permission to a user (override)
func (r *RBACService) GrantPermissionToUser(ctx context.Context, userID, permissionID, grantedBy uuid.UUID, reason string, expiresAt *time.Time) error {
	override := models.UserPermissionOverride{
		UserID:       userID,
		PermissionID: permissionID,
		Granted:      true,
		Reason:       reason,
		GrantedBy:    grantedBy,
		GrantedAt:    time.Now(),
		ExpiresAt:    expiresAt,
	}

	if err := r.db.Create(&override).Error; err != nil {
		return fmt.Errorf("không thể cấp quyền cho người dùng: %w", err)
	}

	return nil
}

// RevokePermissionFromUser revokes a specific permission from a user
func (r *RBACService) RevokePermissionFromUser(ctx context.Context, userID, permissionID, revokedBy uuid.UUID, reason string) error {
	override := models.UserPermissionOverride{
		UserID:       userID,
		PermissionID: permissionID,
		Granted:      false,
		Reason:       reason,
		GrantedBy:    revokedBy,
		GrantedAt:    time.Now(),
	}

	if err := r.db.Create(&override).Error; err != nil {
		return fmt.Errorf("không thể thu hồi quyền từ người dùng: %w", err)
	}

	return nil
}

// GetUserPermissions gets all effective permissions for a user
func (r *RBACService) GetUserPermissions(ctx context.Context, userID uuid.UUID) ([]models.Permission, error) {
	var permissions []models.Permission

	// Get role permissions
	var rolePermissions []models.Permission
	err := r.db.Table("permissions").
		Select("permissions.*").
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Joins("JOIN roles ON role_permissions.role_id = roles.id").
		Joins("JOIN users ON roles.name = users.role").
		Where("users.id = ? AND role_permissions.deleted_at IS NULL", userID).
		Find(&rolePermissions).Error
	
	if err != nil {
		return nil, fmt.Errorf("lỗi lấy quyền vai trò: %w", err)
	}

	permissions = append(permissions, rolePermissions...)

	// Get user-specific granted permissions
	var userPermissions []models.Permission
	err = r.db.Table("permissions").
		Select("permissions.*").
		Joins("JOIN user_permission_overrides ON permissions.id = user_permission_overrides.permission_id").
		Where("user_permission_overrides.user_id = ? AND user_permission_overrides.granted = true AND (user_permission_overrides.expires_at IS NULL OR user_permission_overrides.expires_at > ?) AND user_permission_overrides.deleted_at IS NULL", 
			userID, time.Now()).
		Find(&userPermissions).Error
	
	if err != nil {
		return nil, fmt.Errorf("lỗi lấy quyền người dùng: %w", err)
	}

	permissions = append(permissions, userPermissions...)

	// Remove duplicates and revoked permissions
	return r.deduplicateAndFilterPermissions(ctx, userID, permissions)
}

// GetRolePermissions gets all permissions for a specific role
func (r *RBACService) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]models.Permission, error) {
	var permissions []models.Permission
	
	err := r.db.Table("permissions").
		Select("permissions.*").
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Where("role_permissions.role_id = ? AND role_permissions.deleted_at IS NULL", roleID).
		Find(&permissions).Error
	
	if err != nil {
		return nil, fmt.Errorf("lỗi lấy quyền vai trò: %w", err)
	}

	return permissions, nil
}

// EvaluatePermissionConditions evaluates dynamic permission conditions
func (r *RBACService) EvaluatePermissionConditions(conditions []models.PermissionCondition, permCtx models.PermissionContext) bool {
	if len(conditions) == 0 {
		return true // No conditions = always allowed
	}

	result := true
	currentLogicalOp := "and" // Default to AND logic

	for _, condition := range conditions {
		conditionResult := r.evaluateCondition(condition, permCtx)
		
		switch currentLogicalOp {
		case "and":
			result = result && conditionResult
		case "or":
			result = result || conditionResult
		}

		// Update logical operator for next condition
		if condition.LogicalOp != "" {
			currentLogicalOp = condition.LogicalOp
		}
	}

	return result
}

// CreateRole creates a new role with specified permissions
func (r *RBACService) CreateRole(ctx context.Context, role models.Role, permissionIDs []uuid.UUID) error {
	tx := r.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Create the role
	if err := tx.Create(&role).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("không thể tạo vai trò: %w", err)
	}

	// Grant permissions to the role
	for _, permissionID := range permissionIDs {
		rolePermission := models.RolePermission{
			RoleID:       role.ID,
			PermissionID: permissionID,
			GrantedAt:    time.Now(),
		}
		
		if err := tx.Create(&rolePermission).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("không thể gán quyền cho vai trò: %w", err)
		}
	}

	return tx.Commit().Error
}

// UpdateRole updates an existing role and its permissions
func (r *RBACService) UpdateRole(ctx context.Context, roleID uuid.UUID, updates models.Role, permissionIDs []uuid.UUID) error {
	tx := r.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Update role information
	if err := tx.Where("id = ?", roleID).Updates(&updates).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("không thể cập nhật vai trò: %w", err)
	}

	// Remove existing permissions
	if err := tx.Where("role_id = ?", roleID).Delete(&models.RolePermission{}).Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("không thể xóa quyền cũ: %w", err)
	}

	// Add new permissions
	for _, permissionID := range permissionIDs {
		rolePermission := models.RolePermission{
			RoleID:       roleID,
			PermissionID: permissionID,
			GrantedAt:    time.Now(),
		}
		
		if err := tx.Create(&rolePermission).Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("không thể gán quyền mới: %w", err)
		}
	}

	return tx.Commit().Error
}

// ValidateRoleHierarchy validates role hierarchy for privilege escalation prevention
func (r *RBACService) ValidateRoleHierarchy(actorRole, targetRole models.UserRole) bool {
	actorLevel := r.getRoleLevel(actorRole)
	targetLevel := r.getRoleLevel(targetRole)
	
	// Higher level roles can manage lower level roles
	return actorLevel > targetLevel
}

// ========== PRIVATE HELPER METHODS ==========

func (r *RBACService) getUserAndRole(ctx context.Context, userID uuid.UUID) (models.User, models.Role, error) {
	var user models.User
	if err := r.db.Where("id = ?", userID).First(&user).Error; err != nil {
		return user, models.Role{}, err
	}

	var role models.Role
	if err := r.db.Where("name = ?", user.Role).First(&role).Error; err != nil {
		return user, role, err
	}

	return user, role, nil
}

func (r *RBACService) checkUserStatus(user models.User) bool {
	// Check if user is active and not locked
	if user.Status != models.StatusActive {
		return false
	}

	// Check if account is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return false
	}

	return true
}

func (r *RBACService) checkTimeRestrictions(role models.Role, currentTime time.Time) bool {
	if len(role.TimeRestrictions) == 0 {
		return true // No restrictions
	}

	var restrictions models.TimeRestriction
	if err := json.Unmarshal(role.TimeRestrictions, &restrictions); err != nil {
		return true // If can't parse, allow access
	}

	// Check day of week
	if len(restrictions.DaysOfWeek) > 0 {
		currentDay := int(currentTime.Weekday())
		allowed := false
		for _, day := range restrictions.DaysOfWeek {
			if day == currentDay {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	// Check time range
	if restrictions.StartTime != "" && restrictions.EndTime != "" {
		// Load timezone
		loc, err := time.LoadLocation(restrictions.Timezone)
		if err != nil {
			loc = time.UTC
		}
		
		currentTimeInTz := currentTime.In(loc)
		currentHour := currentTimeInTz.Hour()
		currentMinute := currentTimeInTz.Minute()
		currentTimeMinutes := currentHour*60 + currentMinute

		// Parse start and end times
		startTime, endTime := r.parseTimeRange(restrictions.StartTime, restrictions.EndTime)
		
		if startTime <= endTime {
			// Normal range (e.g., 09:00 - 17:00)
			return currentTimeMinutes >= startTime && currentTimeMinutes <= endTime
		} else {
			// Overnight range (e.g., 22:00 - 06:00)
			return currentTimeMinutes >= startTime || currentTimeMinutes <= endTime
		}
	}

	return true
}

func (r *RBACService) parseTimeRange(startTime, endTime string) (int, int) {
	parseTime := func(timeStr string) int {
		parts := strings.Split(timeStr, ":")
		if len(parts) != 2 {
			return 0
		}
		
		var hour, minute int
		fmt.Sscanf(parts[0], "%d", &hour)
		fmt.Sscanf(parts[1], "%d", &minute)
		
		return hour*60 + minute
	}

	return parseTime(startTime), parseTime(endTime)
}

func (r *RBACService) checkIPWhitelist(role models.Role, ipAddress string) bool {
	if len(role.IPWhitelist) == 0 {
		return true // No whitelist = all IPs allowed
	}

	for _, allowedIP := range role.IPWhitelist {
		// Support CIDR notation and exact matches
		if r.matchIP(ipAddress, allowedIP) {
			return true
		}
	}

	return false
}

func (r *RBACService) matchIP(ip, pattern string) bool {
	// Simple IP matching - in production, use proper CIDR matching
	if ip == pattern {
		return true
	}
	
	// Basic wildcard support
	if strings.Contains(pattern, "*") {
		regex := strings.ReplaceAll(pattern, "*", ".*")
		matched, _ := regexp.MatchString(regex, ip)
		return matched
	}

	return false
}

func (r *RBACService) checkMFARequirements(role models.Role, mfaVerified bool) bool {
	if !role.MFARequired {
		return true // MFA not required
	}

	return mfaVerified
}

func (r *RBACService) checkRolePermission(ctx context.Context, roleID uuid.UUID, permCtx models.PermissionContext) (bool, error) {
	var count int64
	
	query := r.db.Table("role_permissions").
		Joins("JOIN permissions ON role_permissions.permission_id = permissions.id").
		Where("role_permissions.role_id = ? AND permissions.resource = ? AND permissions.action = ? AND role_permissions.deleted_at IS NULL", 
			roleID, permCtx.Resource, permCtx.Action)

	// Check expiration
	query = query.Where("role_permissions.expires_at IS NULL OR role_permissions.expires_at > ?", time.Now())

	if err := query.Count(&count).Error; err != nil {
		return false, err
	}

	return count > 0, nil
}

func (r *RBACService) checkUserPermissionOverride(ctx context.Context, userID uuid.UUID, permCtx models.PermissionContext) (bool, bool, error) {
	var override models.UserPermissionOverride
	
	err := r.db.Table("user_permission_overrides").
		Joins("JOIN permissions ON user_permission_overrides.permission_id = permissions.id").
		Where("user_permission_overrides.user_id = ? AND permissions.resource = ? AND permissions.action = ?", 
			userID, permCtx.Resource, permCtx.Action).
		Where("user_permission_overrides.expires_at IS NULL OR user_permission_overrides.expires_at > ?", time.Now()).
		Where("user_permission_overrides.deleted_at IS NULL").
		Order("user_permission_overrides.granted_at DESC").
		First(&override).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, false, nil // No override found
		}
		return false, false, err
	}

	return true, override.Granted, nil
}

func (r *RBACService) checkResourceAccess(ctx context.Context, userID uuid.UUID, permCtx models.PermissionContext) (bool, error) {
	var access models.ResourceAccess
	
	err := r.db.Where("user_id = ? AND resource_type = ? AND resource_id = ?", 
		userID, permCtx.Resource, *permCtx.ResourceID).
		Where("expires_at IS NULL OR expires_at > ?", time.Now()).
		Where("deleted_at IS NULL").
		First(&access).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil // No specific resource access
		}
		return false, err
	}

	// Check if the required action is in the permissions list
	for _, permission := range access.Permissions {
		if permission == permCtx.Action {
			return true, nil
		}
	}

	return false, nil
}

func (r *RBACService) evaluateCondition(condition models.PermissionCondition, permCtx models.PermissionContext) bool {
	var fieldValue interface{}

	// Extract field value from context
	switch condition.Field {
	case "user_id":
		fieldValue = permCtx.UserID.String()
	case "role":
		fieldValue = string(permCtx.Role)
	case "ip_address":
		fieldValue = permCtx.IPAddress
	case "time":
		fieldValue = permCtx.Time.Unix()
	case "mfa_verified":
		fieldValue = permCtx.MFAVerified
	case "risk_score":
		fieldValue = permCtx.RiskScore
	case "security_level":
		fieldValue = string(permCtx.SecurityLevel)
	default:
		return false // Unknown field
	}

	// Evaluate condition based on operator
	switch condition.Operator {
	case "eq":
		return fieldValue == condition.Value
	case "ne":
		return fieldValue != condition.Value
	case "gt":
		return r.compareNumeric(fieldValue, condition.Value, ">")
	case "lt":
		return r.compareNumeric(fieldValue, condition.Value, "<")
	case "gte":
		return r.compareNumeric(fieldValue, condition.Value, ">=")
	case "lte":
		return r.compareNumeric(fieldValue, condition.Value, "<=")
	case "in":
		return r.valueInSlice(fieldValue, condition.Value)
	case "not_in":
		return !r.valueInSlice(fieldValue, condition.Value)
	case "contains":
		return r.stringContains(fieldValue, condition.Value)
	case "regex":
		return r.regexMatch(fieldValue, condition.Value)
	default:
		return false
	}
}

func (r *RBACService) compareNumeric(a, b interface{}, operator string) bool {
	// Simplified numeric comparison - in production, handle different types properly
	aFloat, aOk := a.(float64)
	bFloat, bOk := b.(float64)
	
	if !aOk || !bOk {
		return false
	}

	switch operator {
	case ">":
		return aFloat > bFloat
	case "<":
		return aFloat < bFloat
	case ">=":
		return aFloat >= bFloat
	case "<=":
		return aFloat <= bFloat
	default:
		return false
	}
}

func (r *RBACService) valueInSlice(value, slice interface{}) bool {
	// Simplified slice check - in production, handle different types properly
	valueStr := fmt.Sprintf("%v", value)
	sliceInterface, ok := slice.([]interface{})
	if !ok {
		return false
	}

	for _, item := range sliceInterface {
		if fmt.Sprintf("%v", item) == valueStr {
			return true
		}
	}
	return false
}

func (r *RBACService) stringContains(haystack, needle interface{}) bool {
	haystackStr := fmt.Sprintf("%v", haystack)
	needleStr := fmt.Sprintf("%v", needle)
	return strings.Contains(haystackStr, needleStr)
}

func (r *RBACService) regexMatch(value, pattern interface{}) bool {
	valueStr := fmt.Sprintf("%v", value)
	patternStr := fmt.Sprintf("%v", pattern)
	
	matched, err := regexp.MatchString(patternStr, valueStr)
	return err == nil && matched
}

func (r *RBACService) deduplicateAndFilterPermissions(ctx context.Context, userID uuid.UUID, permissions []models.Permission) ([]models.Permission, error) {
	// Get revoked permissions
	var revokedPermissions []uuid.UUID
	err := r.db.Table("user_permission_overrides").
		Select("permission_id").
		Where("user_id = ? AND granted = false AND (expires_at IS NULL OR expires_at > ?) AND deleted_at IS NULL", 
			userID, time.Now()).
		Find(&revokedPermissions).Error
	
	if err != nil {
		return nil, err
	}

	// Create revoked permissions map for fast lookup
	revokedMap := make(map[uuid.UUID]bool)
	for _, id := range revokedPermissions {
		revokedMap[id] = true
	}

	// Deduplicate and filter
	seen := make(map[uuid.UUID]bool)
	var result []models.Permission

	for _, permission := range permissions {
		// Skip if already seen or revoked
		if seen[permission.ID] || revokedMap[permission.ID] {
			continue
		}

		seen[permission.ID] = true
		result = append(result, permission)
	}

	return result, nil
}

func (r *RBACService) getRoleLevel(role models.UserRole) int {
	levelMap := map[models.UserRole]int{
		models.RoleBasicUser:     1,
		models.RolePremiumUser:   2,
		models.RoleTeamMember:    3,
		models.RoleVaultAdmin:    4,
		models.RoleSecurityAdmin: 5,
		models.RoleSuperAdmin:    6,
	}
	
	if level, exists := levelMap[role]; exists {
		return level
	}
	
	return 0 // Unknown role
}

// GetDB returns the database connection for external access
func (r *RBACService) GetDB() *gorm.DB {
	return r.db
}