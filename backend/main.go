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

	"github.com/gin-gonic/gin"
)

func main() {
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

	// Initialize database (mock for now)
	db, err := database.InitDB(cfg)
	if err != nil {
		log.Warn("Failed to initialize database, using mock", "error", err)
		db = nil
	}

	// Initialize Redis (mock for now)
	redisClient, err := redis.InitRedis(cfg)
	if err != nil {
		log.Warn("Failed to initialize Redis, using mock", "error", err)
		redisClient = &redis.Client{}
	}

	// Initialize security services
	cryptoService := security.NewCryptoService(cfg)
	authService := services.NewAuthService(db, redisClient, cryptoService, cfg)
	auditService := services.NewAuditService(db, cfg)
	vaultService := services.NewVaultService(db, cryptoService, auditService, cfg)

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
			auth.GET("/profile", middleware.RequireAuth(authService), api.GetProfile(authService))
			auth.PUT("/profile", middleware.RequireAuth(authService), api.UpdateProfile(authService, auditService))
			auth.POST("/change-password", middleware.RequireAuth(authService), api.ChangePassword(authService, auditService))
		}

		// Vault routes
		vault := v1.Group("/vault")
		vault.Use(middleware.RequireAuth(authService))
		{
			vault.GET("/items", api.GetVaultItems(vaultService))
			vault.POST("/items", api.CreateVaultItem(vaultService, auditService))
			vault.GET("/items/:id", api.GetVaultItem(vaultService))
			vault.PUT("/items/:id", api.UpdateVaultItem(vaultService, auditService))
			vault.DELETE("/items/:id", api.DeleteVaultItem(vaultService, auditService))
			vault.POST("/items/:id/share", api.ShareVaultItem(vaultService, auditService))
			vault.GET("/shared", api.GetSharedItems(vaultService))
			vault.POST("/folders", api.CreateFolder(vaultService, auditService))
			vault.GET("/folders", api.GetFolders(vaultService))
			vault.PUT("/folders/:id", api.UpdateFolder(vaultService, auditService))
			vault.DELETE("/folders/:id", api.DeleteFolder(vaultService, auditService))
		}

		// Search routes
		search := v1.Group("/search")
		search.Use(middleware.RequireAuth(authService))
		{
			search.GET("/", api.SearchVaultItems(vaultService))
			search.GET("/suggestions", api.GetSearchSuggestions(vaultService))
		}

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
			admin.GET("/system/config", api.AdminGetConfig(cfg))
			admin.PUT("/system/config", api.AdminUpdateConfig(cfg, auditService))

			// Security management
			admin.GET("/security/policies", api.GetSecurityPolicies(authService))
			admin.PUT("/security/policies", api.UpdateSecurityPolicies(authService, auditService))
			admin.GET("/security/incidents", api.GetSecurityIncidents(auditService))
			admin.POST("/security/incidents/:id/resolve", api.ResolveSecurityIncident(auditService))

			// Audit management
			admin.GET("/audit/logs", api.AdminGetAllAuditLogs(auditService))
			admin.GET("/audit/reports", api.GenerateComplianceReports(auditService))
			admin.POST("/audit/export", api.ExportAuditLogs(auditService))

			// Key management
			admin.POST("/keys/rotate", api.RotateEncryptionKeys(cryptoService, auditService))
			admin.GET("/keys/status", api.GetKeyStatus(cryptoService))
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
