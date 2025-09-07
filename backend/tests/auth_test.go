package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"securevault/internal/config"
	"securevault/internal/database"
	"securevault/internal/models"
	"securevault/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type AuthTestSuite struct {
	suite.Suite
	db          *gorm.DB
	authService *services.AuthService
	router      *gin.Engine
}

func (suite *AuthTestSuite) SetupSuite() {
	gin.SetMode(gin.TestMode)
	
	// Setup test database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	suite.Require().NoError(err)
	
	// Migrate tables
	err = db.AutoMigrate(&models.User{}, &models.AuditLog{})
	suite.Require().NoError(err)
	
	suite.db = db
	
	// Setup test config
	cfg := &config.Config{
		Security: config.SecurityConfig{
			JWTSecret:      "test-jwt-secret-key-for-testing-purposes",
			RefreshSecret:  "test-refresh-secret-key-for-testing-purposes",
			HMACSecret:     "test-hmac-secret-key-for-testing-purposes",
			AccessTokenTTL: time.Hour,
			RefreshTokenTTL: 24 * time.Hour,
		},
	}
	
	suite.authService = services.NewAuthService(cfg)
	
	// Setup router
	suite.router = gin.New()
	suite.setupRoutes()
}

func (suite *AuthTestSuite) setupRoutes() {
	auth := suite.router.Group("/api/auth")
	{
		auth.POST("/register", suite.handleRegister)
		auth.POST("/login", suite.handleLogin)
		auth.POST("/refresh", suite.handleRefresh)
		auth.POST("/logout", suite.handleLogout)
	}
}

func (suite *AuthTestSuite) handleRegister(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
		Name     string `json:"name" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Check if user exists
	var existingUser models.User
	if err := suite.db.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		return
	}
	
	// Create user
	user := &models.User{
		ID:       uuid.New(),
		Email:    req.Email,
		Name:     req.Name,
		IsActive: true,
	}
	
	// Hash password
	hashedPassword, err := suite.authService.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	user.Password = hashedPassword
	
	if err := suite.db.Create(user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}
	
	c.JSON(http.StatusCreated, gin.H{
		"message": "User created successfully",
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
		},
	})
}

func (suite *AuthTestSuite) handleLogin(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Find user
	var user models.User
	if err := suite.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	
	// Verify password
	if !suite.authService.VerifyPassword(req.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	
	// Generate tokens
	accessToken, err := suite.authService.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}
	
	refreshToken, err := suite.authService.GenerateRefreshToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
		},
	})
}

func (suite *AuthTestSuite) handleRefresh(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Validate refresh token
	userID, err := suite.authService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}
	
	// Get user
	var user models.User
	if err := suite.db.Where("id = ?", userID).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}
	
	// Generate new access token
	accessToken, err := suite.authService.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
	})
}

func (suite *AuthTestSuite) handleLogout(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func (suite *AuthTestSuite) TearDownSuite() {
	sqlDB, _ := suite.db.DB()
	sqlDB.Close()
}

func (suite *AuthTestSuite) TestRegisterUser() {
	registerData := map[string]string{
		"email":    "test@example.com",
		"password": "Password123!",
		"name":     "Test User",
	}
	
	jsonData, _ := json.Marshal(registerData)
	req, _ := http.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	
	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusCreated, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "User created successfully", response["message"])
	assert.NotNil(suite.T(), response["user"])
}

func (suite *AuthTestSuite) TestRegisterDuplicateUser() {
	// First registration
	registerData := map[string]string{
		"email":    "duplicate@example.com",
		"password": "Password123!",
		"name":     "Duplicate User",
	}
	
	jsonData, _ := json.Marshal(registerData)
	req, _ := http.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	
	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)
	assert.Equal(suite.T(), http.StatusCreated, w.Code)
	
	// Second registration with same email
	req, _ = http.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	
	w = httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)
	assert.Equal(suite.T(), http.StatusConflict, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "User already exists", response["error"])
}

func (suite *AuthTestSuite) TestLoginValidCredentials() {
	// Register user first
	registerData := map[string]string{
		"email":    "login@example.com",
		"password": "Password123!",
		"name":     "Login User",
	}
	
	jsonData, _ := json.Marshal(registerData)
	req, _ := http.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	
	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)
	assert.Equal(suite.T(), http.StatusCreated, w.Code)
	
	// Now test login
	loginData := map[string]string{
		"email":    "login@example.com",
		"password": "Password123!",
	}
	
	jsonData, _ = json.Marshal(loginData)
	req, _ = http.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	
	w = httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), response["access_token"])
	assert.NotEmpty(suite.T(), response["refresh_token"])
	assert.NotNil(suite.T(), response["user"])
}

func (suite *AuthTestSuite) TestLoginInvalidCredentials() {
	loginData := map[string]string{
		"email":    "nonexistent@example.com",
		"password": "WrongPassword",
	}
	
	jsonData, _ := json.Marshal(loginData)
	req, _ := http.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	
	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "Invalid credentials", response["error"])
}

func (suite *AuthTestSuite) TestRefreshToken() {
	// Register and login user first
	registerData := map[string]string{
		"email":    "refresh@example.com",
		"password": "Password123!",
		"name":     "Refresh User",
	}
	
	jsonData, _ := json.Marshal(registerData)
	req, _ := http.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	
	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)
	assert.Equal(suite.T(), http.StatusCreated, w.Code)
	
	// Login to get refresh token
	loginData := map[string]string{
		"email":    "refresh@example.com",
		"password": "Password123!",
	}
	
	jsonData, _ = json.Marshal(loginData)
	req, _ = http.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	
	w = httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)
	assert.Equal(suite.T(), http.StatusOK, w.Code)
	
	var loginResponse map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &loginResponse)
	assert.NoError(suite.T(), err)
	
	refreshToken := loginResponse["refresh_token"].(string)
	
	// Use refresh token to get new access token
	refreshData := map[string]string{
		"refresh_token": refreshToken,
	}
	
	jsonData, _ = json.Marshal(refreshData)
	req, _ = http.NewRequest("POST", "/api/auth/refresh", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	
	w = httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), response["access_token"])
}

func (suite *AuthTestSuite) TestRefreshTokenInvalid() {
	refreshData := map[string]string{
		"refresh_token": "invalid.refresh.token",
	}
	
	jsonData, _ := json.Marshal(refreshData)
	req, _ := http.NewRequest("POST", "/api/auth/refresh", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	
	w := httptest.NewRecorder()
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "Invalid refresh token", response["error"])
}

func (suite *AuthTestSuite) TestPasswordHashing() {
	password := "TestPassword123!"
	
	hashedPassword, err := suite.authService.HashPassword(password)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), hashedPassword)
	assert.NotEqual(suite.T(), password, hashedPassword)
	
	// Test password verification
	assert.True(suite.T(), suite.authService.VerifyPassword(password, hashedPassword))
	assert.False(suite.T(), suite.authService.VerifyPassword("WrongPassword", hashedPassword))
}

func (suite *AuthTestSuite) TestTokenGeneration() {
	userID := uuid.New()
	email := "test@example.com"
	
	accessToken, err := suite.authService.GenerateAccessToken(userID, email)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), accessToken)
	
	refreshToken, err := suite.authService.GenerateRefreshToken(userID)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), refreshToken)
	
	// Validate tokens
	claims, err := suite.authService.ValidateAccessToken(accessToken)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), userID.String(), claims.UserID)
	assert.Equal(suite.T(), email, claims.Email)
	
	validatedUserID, err := suite.authService.ValidateRefreshToken(refreshToken)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), userID, validatedUserID)
}

func TestAuthSuite(t *testing.T) {
	suite.Run(t, new(AuthTestSuite))
}