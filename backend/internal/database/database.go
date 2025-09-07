package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"securevault/internal/config"
	"securevault/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// InitDB initializes the database connection and runs migrations
func InitDB(cfg *config.Config) *gorm.DB {
	var dsn string
	if cfg.Database.URL != "" {
		dsn = cfg.Database.URL
	} else {
		log.Fatal("Database URL is required in configuration")
	}

	// Configure GORM logger
	gormLogger := logger.Default
	if cfg.Server.Environment == "production" {
		gormLogger = logger.Default.LogMode(logger.Silent)
	}

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormLogger,
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Get underlying SQL DB for connection pooling
	sqlDB, err := DB.DB()
	if err != nil {
		log.Fatalf("Failed to get underlying sql.DB: %v", err)
	}

	// Configure connection pool
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	if err := sqlDB.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("Database connection established successfully")

	// Run auto-migration
	if err := AutoMigrate(); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	return DB
}

// AutoMigrate runs database migrations
func AutoMigrate() error {
	// Enable UUID extension
	if err := DB.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"").Error; err != nil {
		return fmt.Errorf("failed to create uuid extension: %v", err)
	}

	// Disable foreign key checks during migration
	DB.Exec("SET session_replication_role = replica")
	
	// Auto migrate all models
	err := DB.AutoMigrate(
		// RBAC models first (dependencies)
		&models.Permission{},
		&models.Role{},
		&models.RolePermission{},
		&models.RoleHierarchy{},
		&models.PermissionTemplate{},
		// User models (depend on roles)
		&models.User{},
		&models.UserPermissionOverride{},
		&models.Session{},
		&models.MFACredential{},
		// Vault models (depend on users)
		&models.VaultItem{},
		&models.VaultFolder{},
		// Other models
		&models.AuditLog{},
		&models.PasswordPolicy{},
		&models.SecurityEvent{},
		&models.ComplianceReport{},
	)
	if err != nil {
		return fmt.Errorf("failed to auto migrate: %v", err)
	}

	// Re-enable foreign key checks
	DB.Exec("SET session_replication_role = DEFAULT")

	// Create indexes
	if err := createIndexes(); err != nil {
		return fmt.Errorf("failed to create indexes: %v", err)
	}

	log.Println("Database migrations completed successfully")
	return nil
}

// createIndexes creates additional database indexes for performance
func createIndexes() error {
	// Users table indexes
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at)")

	// Sessions table indexes
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash)")

	// Vault items table indexes
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_vault_items_user_id ON vault_items(user_id)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_vault_items_folder_id ON vault_items(folder_id)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_vault_items_type ON vault_items(type)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_vault_items_created_at ON vault_items(created_at)")

	// Audit logs table indexes
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)")

	// RBAC table indexes
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_permissions_category ON permissions(category)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_roles_level ON roles(level)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_user_permission_overrides_user_id ON user_permission_overrides(user_id)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_user_permission_overrides_permission_id ON user_permission_overrides(permission_id)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_role_hierarchy_parent ON role_hierarchies(parent_role)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_role_hierarchy_child ON role_hierarchies(child_role)")

	return nil
}

// CloseDB closes the database connection
func CloseDB() error {
	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// GetDB returns the database instance
func GetDB() *gorm.DB {
	return DB
}

// HealthCheck checks database connectivity
func HealthCheck() error {
	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

// GetStats returns database connection statistics
func GetStats() sql.DBStats {
	sqlDB, _ := DB.DB()
	return sqlDB.Stats()
}

// WithTransaction executes a function within a database transaction
func WithTransaction(fn func(*gorm.DB) error) error {
	return DB.Transaction(fn)
}
