package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"securevault/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RBACInitService handles initialization of RBAC system with real data
type RBACInitService struct {
	db *gorm.DB
}

// NewRBACInitService creates a new RBAC initialization service
func NewRBACInitService(db *gorm.DB) *RBACInitService {
	return &RBACInitService{
		db: db,
	}
}

// InitializeRBACSystem initializes the complete RBAC system with real data
func (r *RBACInitService) InitializeRBACSystem(ctx context.Context) error {
	log.Println("Initializing RBAC system with real data...")

	// Step 1: Create system permissions
	if err := r.createSystemPermissions(ctx); err != nil {
		return fmt.Errorf("failed to create system permissions: %w", err)
	}

	// Step 2: Create system roles
	if err := r.createSystemRoles(ctx); err != nil {
		return fmt.Errorf("failed to create system roles: %w", err)
	}

	// Step 3: Assign permissions to roles
	if err := r.assignPermissionsToRoles(ctx); err != nil {
		return fmt.Errorf("failed to assign permissions to roles: %w", err)
	}

	// Step 4: Create role hierarchy
	if err := r.createRoleHierarchy(ctx); err != nil {
		return fmt.Errorf("failed to create role hierarchy: %w", err)
	}

	// Step 5: Create permission templates
	if err := r.createPermissionTemplates(ctx); err != nil {
		return fmt.Errorf("failed to create permission templates: %w", err)
	}

	log.Println("RBAC system initialized successfully!")
	return nil
}

// createSystemPermissions creates all system permissions
func (r *RBACInitService) createSystemPermissions(ctx context.Context) error {
	log.Println("Creating system permissions...")

	for _, permission := range models.SystemPermissions {
		// Check if permission already exists
		var existingPermission models.Permission
		result := r.db.Where("name = ?", permission.Name).First(&existingPermission)

		if result.Error == gorm.ErrRecordNotFound {
			// Create new permission
			newPermission := models.Permission{
				ID:          uuid.New(),
				Name:        permission.Name,
				Resource:    permission.Resource,
				Action:      permission.Action,
				Description: permission.Description,
				Category:    permission.Category,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}

			if err := r.db.Create(&newPermission).Error; err != nil {
				return fmt.Errorf("failed to create permission %s: %w", permission.Name, err)
			}

			log.Printf("Created permission: %s", permission.Name)
		}
	}

	return nil
}

// createSystemRoles creates all system roles with real configuration
func (r *RBACInitService) createSystemRoles(ctx context.Context) error {
	log.Println("Creating system roles...")

	for _, role := range models.SystemRoles {
		// Check if role already exists
		var existingRole models.Role
		result := r.db.Where("name = ?", role.Name).First(&existingRole)

		if result.Error == gorm.ErrRecordNotFound {
			// Create new role
			newRole := models.Role{
				ID:             uuid.New(),
				Name:           role.Name,
				DisplayName:    role.DisplayName,
				Description:    role.Description,
				Level:          role.Level,
				IsSystemRole:   role.IsSystemRole,
				MaxItems:       role.MaxItems,
				MaxSharedItems: role.MaxSharedItems,
				MaxTeamMembers: role.MaxTeamMembers,
				StorageLimit:   role.StorageLimit,
				SessionTimeout: role.SessionTimeout,
				MFARequired:    role.MFARequired,
				IPWhitelist:    []string{}, // Empty by default
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			}

			// Set time restrictions for high-level roles
			if role.Level >= 4 {
				timeRestrictions := models.TimeRestriction{
					DaysOfWeek: []int{1, 2, 3, 4, 5}, // Monday to Friday
					StartTime:  "06:00",
					EndTime:    "22:00",
					Timezone:   "Asia/Ho_Chi_Minh",
				}
				newRole.TimeRestrictions, _ = r.marshalJSON(timeRestrictions)
			}

			// Set password policy for roles
			passwordPolicy := r.getPasswordPolicyForRole(role.Name)
			newRole.PasswordPolicy, _ = r.marshalJSON(passwordPolicy)

			if err := r.db.Create(&newRole).Error; err != nil {
				return fmt.Errorf("failed to create role %s: %w", role.Name, err)
			}

			log.Printf("Created role: %s (Level %d)", role.DisplayName, role.Level)
		}
	}

	return nil
}

// assignPermissionsToRoles assigns specific permissions to each role
func (r *RBACInitService) assignPermissionsToRoles(ctx context.Context) error {
	log.Println("Assigning permissions to roles...")

	// Get all permissions and roles
	var permissions []models.Permission
	if err := r.db.Find(&permissions).Error; err != nil {
		return err
	}

	var roles []models.Role
	if err := r.db.Find(&roles).Error; err != nil {
		return err
	}

	// Create permission maps for easier lookup
	permissionMap := make(map[string]models.Permission)
	roleMap := make(map[models.UserRole]models.Role)

	for _, p := range permissions {
		permissionMap[p.Name] = p
	}

	for _, r := range roles {
		roleMap[r.Name] = r
	}

	// Define role-permission mappings
	rolePermissions := r.defineRolePermissions()

	for roleName, permissionNames := range rolePermissions {
		role, exists := roleMap[roleName]
		if !exists {
			continue
		}

		for _, permissionName := range permissionNames {
			permission, exists := permissionMap[permissionName]
			if !exists {
				continue
			}

			// Check if assignment already exists
			var existing models.RolePermission
			result := r.db.Where("role_id = ? AND permission_id = ?", role.ID, permission.ID).First(&existing)

			if result.Error == gorm.ErrRecordNotFound {
				// Create role-permission assignment
				rolePermission := models.RolePermission{
					ID:           uuid.New(),
					RoleID:       role.ID,
					PermissionID: permission.ID,
					GrantedAt:    time.Now(),
					CreatedAt:    time.Now(),
					UpdatedAt:    time.Now(),
				}

				if err := r.db.Create(&rolePermission).Error; err != nil {
					log.Printf("Failed to assign permission %s to role %s: %v", permissionName, roleName, err)
				}
			}
		}

		log.Printf("Assigned permissions to role: %s", role.DisplayName)
	}

	return nil
}

// createRoleHierarchy creates the role inheritance hierarchy
func (r *RBACInitService) createRoleHierarchy(ctx context.Context) error {
	log.Println("Creating role hierarchy...")

	// Define role hierarchy (parent -> children)
	hierarchy := map[models.UserRole][]models.UserRole{
		models.RoleSuperAdmin: {
			models.RoleSecurityAdmin,
			models.RoleVaultAdmin,
		},
		models.RoleSecurityAdmin: {
			models.RoleVaultAdmin,
		},
		models.RoleVaultAdmin: {
			models.RoleTeamMember,
		},
		models.RoleTeamMember: {
			models.RolePremiumUser,
		},
		models.RolePremiumUser: {
			models.RoleBasicUser,
		},
	}

	for parentRole, childRoles := range hierarchy {
		for _, childRole := range childRoles {
			// Check if hierarchy already exists
			var existing models.RoleHierarchy
			result := r.db.Where("parent_role = ? AND child_role = ?", parentRole, childRole).First(&existing)

			if result.Error == gorm.ErrRecordNotFound {
				roleHierarchy := models.RoleHierarchy{
					ID:         uuid.New(),
					ParentRole: parentRole,
					ChildRole:  childRole,
					CreatedAt:  time.Now(),
				}

				if err := r.db.Create(&roleHierarchy).Error; err != nil {
					log.Printf("Failed to create hierarchy %s -> %s: %v", parentRole, childRole, err)
				}
			}
		}
	}

	return nil
}

// createPermissionTemplates creates pre-defined permission templates
func (r *RBACInitService) createPermissionTemplates(ctx context.Context) error {
	log.Println("Creating permission templates...")

	templates := r.definePermissionTemplates()

	// Get system user ID (or use a default system UUID)
	systemUserID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	for _, template := range templates {
		// Check if template already exists
		var existing models.PermissionTemplate
		result := r.db.Where("name = ?", template.Name).First(&existing)

		if result.Error == gorm.ErrRecordNotFound {
			newTemplate := models.PermissionTemplate{
				ID:          uuid.New(),
				Name:        template.Name,
				Description: template.Description,
				Category:    template.Category,
				Permissions: template.Permissions,
				IsActive:    true,
				CreatedBy:   systemUserID,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}

			if err := r.db.Create(&newTemplate).Error; err != nil {
				log.Printf("Failed to create permission template %s: %v", template.Name, err)
			} else {
				log.Printf("Created permission template: %s", template.Name)
			}
		}
	}

	return nil
}

// defineRolePermissions defines which permissions each role should have
func (r *RBACInitService) defineRolePermissions() map[models.UserRole][]string {
	return map[models.UserRole][]string{
		models.RoleBasicUser: {
			"vault.items.create",
			"vault.items.read",
			"vault.items.update",
			"vault.items.delete",
			"vault.folders.create",
			"vault.folders.read",
			"vault.folders.update",
			"vault.folders.delete",
		},
		models.RolePremiumUser: {
			"vault.items.create",
			"vault.items.read",
			"vault.items.update",
			"vault.items.delete",
			"vault.items.share",
			"vault.items.export",
			"vault.items.import",
			"vault.folders.create",
			"vault.folders.read",
			"vault.folders.update",
			"vault.folders.delete",
			"reports.usage.view",
		},
		models.RoleTeamMember: {
			"vault.items.create",
			"vault.items.read",
			"vault.items.update",
			"vault.items.delete",
			"vault.items.share",
			"vault.items.export",
			"vault.items.import",
			"vault.folders.create",
			"vault.folders.read",
			"vault.folders.update",
			"vault.folders.delete",
			"teams.read",
			"teams.update",
			"reports.usage.view",
		},
		models.RoleVaultAdmin: {
			// All vault permissions
			"vault.items.create",
			"vault.items.read",
			"vault.items.update",
			"vault.items.delete",
			"vault.items.share",
			"vault.items.export",
			"vault.items.import",
			"vault.folders.create",
			"vault.folders.read",
			"vault.folders.update",
			"vault.folders.delete",
			// User management
			"users.create",
			"users.read",
			"users.update",
			"users.suspend",
			"users.activate",
			"users.reset_password",
			"users.view_sessions",
			"users.terminate_sessions",
			// Team management
			"teams.create",
			"teams.read",
			"teams.update",
			"teams.delete",
			"teams.manage_members",
			// Basic security
			"security.incidents.read",
			"security.audit_logs.read",
			// Reports
			"reports.compliance.generate",
			"reports.usage.view",
		},
		models.RoleSecurityAdmin: {
			// All vault permissions
			"vault.items.create",
			"vault.items.read",
			"vault.items.update",
			"vault.items.delete",
			"vault.items.share",
			"vault.items.export",
			"vault.items.import",
			"vault.folders.create",
			"vault.folders.read",
			"vault.folders.update",
			"vault.folders.delete",
			// User management
			"users.create",
			"users.read",
			"users.update",
			"users.suspend",
			"users.activate",
			"users.reset_password",
			"users.manage_roles",
			"users.view_sessions",
			"users.terminate_sessions",
			// Security management
			"security.incidents.read",
			"security.incidents.resolve",
			"security.audit_logs.read",
			"security.audit_logs.export",
			"security.policies.read",
			"security.policies.update",
			"security.mfa.manage",
			"security.keys.rotate",
			// System monitoring
			"system.health.read",
			// Reports
			"reports.compliance.generate",
			"reports.usage.view",
			"reports.security.view",
		},
		models.RoleSuperAdmin: {
			// All permissions - Super admin has access to everything
			"vault.items.create",
			"vault.items.read",
			"vault.items.update",
			"vault.items.delete",
			"vault.items.share",
			"vault.items.export",
			"vault.items.import",
			"vault.folders.create",
			"vault.folders.read",
			"vault.folders.update",
			"vault.folders.delete",
			"users.create",
			"users.read",
			"users.update",
			"users.delete",
			"users.suspend",
			"users.activate",
			"users.reset_password",
			"users.manage_roles",
			"users.view_sessions",
			"users.terminate_sessions",
			"security.incidents.read",
			"security.incidents.resolve",
			"security.audit_logs.read",
			"security.audit_logs.export",
			"security.policies.read",
			"security.policies.update",
			"security.mfa.manage",
			"security.keys.rotate",
			"system.health.read",
			"system.config.read",
			"system.config.update",
			"system.backup.create",
			"system.backup.restore",
			"system.maintenance.manage",
			"reports.compliance.generate",
			"reports.usage.view",
			"reports.security.view",
			"teams.create",
			"teams.read",
			"teams.update",
			"teams.delete",
			"teams.manage_members",
		},
	}
}

// definePermissionTemplates defines pre-built permission templates
func (r *RBACInitService) definePermissionTemplates() []models.PermissionTemplate {
	// Get permission IDs by names (simplified for demo)
	getPermissionIDs := func(names []string) []uuid.UUID {
		var ids []uuid.UUID
		var permissions []models.Permission

		r.db.Where("name IN ?", names).Find(&permissions)
		for _, p := range permissions {
			ids = append(ids, p.ID)
		}

		return ids
	}

	return []models.PermissionTemplate{
		{
			Name:        "vault_basic",
			Description: "Quyền cơ bản cho vault cá nhân",
			Category:    "vault",
			Permissions: getPermissionIDs([]string{
				"vault.items.create",
				"vault.items.read",
				"vault.items.update",
				"vault.items.delete",
				"vault.folders.create",
				"vault.folders.read",
				"vault.folders.update",
				"vault.folders.delete",
			}),
		},
		{
			Name:        "vault_premium",
			Description: "Quyền nâng cao cho vault với chia sẻ",
			Category:    "vault",
			Permissions: getPermissionIDs([]string{
				"vault.items.create",
				"vault.items.read",
				"vault.items.update",
				"vault.items.delete",
				"vault.items.share",
				"vault.items.export",
				"vault.items.import",
				"vault.folders.create",
				"vault.folders.read",
				"vault.folders.update",
				"vault.folders.delete",
			}),
		},
		{
			Name:        "user_management",
			Description: "Quyền quản lý người dùng",
			Category:    "admin",
			Permissions: getPermissionIDs([]string{
				"users.create",
				"users.read",
				"users.update",
				"users.suspend",
				"users.activate",
				"users.reset_password",
				"users.view_sessions",
				"users.terminate_sessions",
			}),
		},
		{
			Name:        "security_management",
			Description: "Quyền quản lý bảo mật",
			Category:    "security",
			Permissions: getPermissionIDs([]string{
				"security.incidents.read",
				"security.incidents.resolve",
				"security.audit_logs.read",
				"security.policies.read",
				"security.policies.update",
				"security.mfa.manage",
			}),
		},
		{
			Name:        "system_admin",
			Description: "Quyền quản trị hệ thống",
			Category:    "system",
			Permissions: getPermissionIDs([]string{
				"system.health.read",
				"system.config.read",
				"system.config.update",
				"system.backup.create",
				"system.backup.restore",
				"system.maintenance.manage",
			}),
		},
	}
}

// getPasswordPolicyForRole returns password policy based on role
func (r *RBACInitService) getPasswordPolicyForRole(role models.UserRole) models.PasswordPolicy {
	switch role {
	case models.RoleBasicUser, models.RolePremiumUser:
		return models.PasswordPolicy{
			MinLength:             12,
			RequireUppercase:      true,
			RequireLowercase:      true,
			RequireNumbers:        true,
			RequireSpecialChars:   true,
			DisallowRepeatedChars: true,
			DisallowCommonWords:   true,
			PasswordHistoryCount:  12,
			MaxAge:                90,
		}
	case models.RoleTeamMember:
		return models.PasswordPolicy{
			MinLength:             14,
			RequireUppercase:      true,
			RequireLowercase:      true,
			RequireNumbers:        true,
			RequireSpecialChars:   true,
			DisallowRepeatedChars: true,
			DisallowCommonWords:   true,
			PasswordHistoryCount:  18,
			MaxAge:                60,
		}
	default: // Admin roles
		return models.PasswordPolicy{
			MinLength:             16,
			RequireUppercase:      true,
			RequireLowercase:      true,
			RequireNumbers:        true,
			RequireSpecialChars:   true,
			DisallowRepeatedChars: true,
			DisallowCommonWords:   true,
			PasswordHistoryCount:  24,
			MaxAge:                30,
		}
	}
}

// marshalJSON marshals any Go value to JSON for DB storage.
// It enforces safe defaults and wraps errors with context.
func (r *RBACInitService) marshalJSON(v interface{}) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("marshalJSON: cannot marshal nil value")
	}

	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshalJSON: %w", err)
	}
	return data, nil
}
