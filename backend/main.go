package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"securevault/internal/api"
	"securevault/internal/config"
	"securevault/internal/database"
	"securevault/internal/logger"
	"securevault/internal/middleware"
	"securevault/internal/redis"
	"securevault/internal/security"
	"securevault/internal/services"
	"securevault/internal/websocket"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		// .env file is optional, so we just log and continue
		fmt.Printf("Warning: .env file not found: %v\n", err)
	}

	// Initialize logger
	logger.InitLogger()
	log := logger.GetLogger()

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Error("Failed to load configuration", "error", err)
		cfg = &config.Config{
			Server: config.ServerConfig{
				Port:        8080,
				Environment: "development",
			},
		}
	}

	// Initialize database
	db := database.InitDB(cfg)

	// Initialize Redis
	redisClient, err := redis.InitRedis(cfg)
	if err != nil {
		log.Fatal("Failed to initialize Redis", "error", err)
	}

	// Initialize crypto service
	cryptoService := security.NewCryptoService(cfg)
	
	// Initialize security services
	authService := services.NewAuthService(cfg)
	auditService := services.NewAuditService(cfg.Security.HMACSecret)
	vaultService := services.NewVaultService()
	securityService := services.NewSecurityService()
	
	// Initialize RBAC services
	rbacService := services.NewRBACService(db, cfg)
	rbacInitService := services.NewRBACInitService(db)
	
	// Initialize real MFA service with actual providers
	mfaService := services.NewRealMFAService(cfg, cryptoService, auditService)

	// Initialize RBAC system with real data
	if err := rbacInitService.InitializeRBACSystem(context.Background()); err != nil {
		log.Error("Failed to initialize RBAC system", "error", err)
	}

	// Initialize security monitoring service
	securityMonitor := services.NewSecurityMonitorService(cfg, auditService)
	securityMonitor.Start()
	defer securityMonitor.Stop()

	// Initialize WebSocket hub
	wsHub := websocket.NewHub()
	go wsHub.Run()

	// Set gin mode
	if cfg.Server.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create router
	router := gin.New()

	// Add middleware
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger())
	router.Use(middleware.Recovery())
	router.Use(middleware.CORS(cfg))
	router.Use(middleware.SecurityHeaders())

	// Health check endpoints
	router.GET("/health", api.HealthCheck)
	router.GET("/ready", api.ReadinessCheck(db, redisClient))

	// API routes
	v1 := router.Group("/api/v1")
	{
		// Authentication routes
		auth := v1.Group("/auth")
		{
			auth.POST("/register", api.Register(authService, auditService))
			auth.POST("/login", api.Login(authService, auditService))
			auth.POST("/logout", middleware.RequireAuth(authService), api.Logout(authService, auditService))
			auth.POST("/refresh", api.RefreshToken(authService, auditService))
			auth.POST("/verify-mfa", api.VerifyMFA(authService, mfaService, nil, auditService))
			auth.GET("/profile", middleware.RequireAuth(authService), api.GetProfile(authService))
			auth.PUT("/profile", middleware.RequireAuth(authService), api.UpdateProfile(authService, auditService))
			auth.POST("/change-password", middleware.RequireAuth(authService), api.ChangePassword(authService, auditService))
		}

		// MFA management routes
		mfa := v1.Group("/mfa")
		mfa.Use(middleware.RequireAuth(authService))
		{
			mfa.POST("/totp/setup", api.SetupTOTP(mfaService, auditService))
			mfa.POST("/totp/verify", api.VerifyTOTPSetup(mfaService, auditService))
			mfa.POST("/sms/setup", api.SetupSMS(mfaService, auditService))
			mfa.POST("/sms/verify", api.VerifySMSSetup(mfaService, auditService))
			mfa.POST("/email/send", api.SendEmailMFA(mfaService, auditService))
			mfa.POST("/backup-code/verify", api.VerifyBackupCode(mfaService, auditService))
			mfa.GET("/status", api.GetMFAStatus(mfaService))
		}

		// Vault routes
		vault := v1.Group("/vault")
		vault.Use(middleware.RequireAuth(authService))
		{
			vault.GET("/items", api.GetVaultItems(vaultService))
			vault.POST("/items", api.CreateVaultItem(vaultService))
			vault.GET("/items/:id", api.GetVaultItem(vaultService))
			vault.PUT("/items/:id", api.UpdateVaultItem(vaultService))
			vault.DELETE("/items/:id", api.DeleteVaultItem(vaultService))
			vault.POST("/items/:id/favorite", api.ToggleFavorite(vaultService))
			vault.POST("/folders", api.CreateFolder(vaultService))
			vault.GET("/folders", api.GetFolders(vaultService))
			vault.PUT("/folders/:id", api.UpdateFolder(vaultService))
			vault.DELETE("/folders/:id", api.DeleteFolder(vaultService))
			vault.GET("/stats", api.GetVaultStats(vaultService))
			vault.GET("/recent", api.GetRecentItems(vaultService))
		}

		// Search routes
		search := v1.Group("/search")
		search.Use(middleware.RequireAuth(authService))
		{
			search.GET("/items", api.SearchVaultItems(vaultService))
		}

		// WebSocket endpoint (with adapter to match interface)
		v1.GET("/ws", websocket.HandleWebSocket(wsHub, &authServiceAdapter{authService}))

		// Admin routes
		admin := v1.Group("/admin")
		admin.Use(middleware.RequireAdminAuth(authService))
		{
			// User management
			admin.GET("/users", api.GetUsers(authService, auditService))
			admin.POST("/users", api.CreateUser(authService, auditService))
			admin.GET("/users/:id", api.GetUser(authService, auditService))
			admin.PUT("/users/:id", api.UpdateUser(authService, auditService))
			admin.DELETE("/users/:id", api.DeleteUser(authService, auditService))
			admin.POST("/users/:id/suspend", api.SuspendUser(authService, auditService))
			admin.POST("/users/:id/activate", api.ActivateUser(authService, auditService))
			admin.POST("/users/:id/reset-password", api.AdminResetPassword(authService, auditService))

			// System management
			admin.GET("/system/health", api.AdminSystemHealth(db, redisClient))
			admin.GET("/system/metrics", api.AdminSystemMetrics())

			// Security management
			admin.GET("/security/policies", api.GetSecurityPolicies(authService))
			admin.PUT("/security/policies", api.UpdateSecurityPolicies(authService, auditService))
			admin.GET("/security/incidents", api.GetSecurityIncidents(securityService))
			admin.POST("/security/incidents/:id/resolve", api.ResolveSecurityIncident(securityService, auditService))
			admin.GET("/security/stats", api.GetSecurityStats(securityService))

			// Audit management
			admin.GET("/audit/logs", api.AdminGetAllAuditLogs(auditService))
			admin.POST("/audit/export", api.ExportAuditLogs(auditService))
			
			// RBAC management
			rbac := admin.Group("/rbac")
			{
				// Role management
				rbac.GET("/roles", api.GetAllRoles(rbacService))
				rbac.GET("/roles/:id/permissions", api.GetRolePermissions(rbacService, auditService))
				rbac.POST("/roles/:id/permissions/grant", api.GrantPermissionToRole(rbacService, auditService))
				rbac.POST("/roles/:id/permissions/:permission_id/revoke", api.RevokePermissionFromRole(rbacService, auditService))
				
				// User permission management
				rbac.GET("/users/:id/permissions", api.GetUserPermissions(rbacService, auditService))
				rbac.POST("/users/:id/permissions/grant", api.GrantPermissionToUser(rbacService, auditService))
				rbac.POST("/users/:id/permissions/:permission_id/revoke", api.RevokePermissionFromUser(rbacService, auditService))
				
				// Permission management
				rbac.GET("/permissions", api.GetAllPermissions(rbacService))
				rbac.POST("/check-permission", api.CheckPermission(rbacService, auditService))
			}
		}
	}

	// Create server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Info("Starting server", "port", cfg.Server.Port, "environment", cfg.Server.Environment)

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error("Server forced to shutdown", "error", err)
	}

	log.Info("Server exited")
}

// authServiceAdapter adapts AuthService to websocket.AuthValidator interface
type authServiceAdapter struct {
	authService *services.AuthService
}

func (a *authServiceAdapter) ValidateToken(token string) (websocket.Claims, error) {
	return a.authService.ValidateToken(token)
}
