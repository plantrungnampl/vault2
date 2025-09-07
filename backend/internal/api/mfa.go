package api

import (
	"net/http"

	"securevault/internal/models"
	"securevault/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// MFA Setup and Management Handlers

func SetupTOTP(mfaService *services.RealMFAService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized",
				"code":  "UNAUTHORIZED",
			})
			return
		}

		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "User information not found",
				"code":  "USER_NOT_FOUND",
			})
			return
		}

		userObj := user.(*models.User)
		userUUID := userID.(uuid.UUID)

		// Setup TOTP
		totpSetup, err := mfaService.SetupTOTP(
			userUUID,
			"SecureVault",
			userObj.Email,
		)
		if err != nil {
			auditService.LogEvent(userUUID, "mfa_totp_setup_failed", "mfa", "", false,
				map[string]interface{}{"error": err.Error()},
				c.ClientIP(), c.GetHeader("User-Agent"))

			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Không thể thiết lập TOTP",
				"code":    "TOTP_SETUP_FAILED",
				"details": err.Error(),
			})
			return
		}

		// Return setup information (including QR code and backup codes)
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"qr_code":          totpSetup.QRCodePNG,
				"manual_entry_key": totpSetup.ManualEntryKey,
				"backup_codes":     totpSetup.BackupCodes,
				"recovery_codes":   totpSetup.RecoveryCodes,
				"instructions": gin.H{
					"step_1": "Quét mã QR bằng ứng dụng Google Authenticator hoặc tương tự",
					"step_2": "Hoặc nhập thủ công mã: " + totpSetup.ManualEntryKey,
					"step_3": "Nhập mã 6 số từ ứng dụng để xác thực",
					"backup": "Lưu các mã backup an toàn, mỗi mã chỉ dùng được một lần",
				},
			},
		})
	}
}

func VerifyTOTPSetup(mfaService *services.RealMFAService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Code string `json:"code" binding:"required,len=6"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Mã TOTP không hợp lệ",
				"code":  "INVALID_REQUEST",
			})
			return
		}

		userID := c.MustGet("user_id").(uuid.UUID)

		// Verify TOTP setup
		if err := mfaService.VerifyTOTPSetup(userID, req.Code); err != nil {
			auditService.LogEvent(userID, "mfa_totp_verify_failed", "mfa", "", false,
				map[string]interface{}{"error": err.Error()},
				c.ClientIP(), c.GetHeader("User-Agent"))

			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Mã TOTP không đúng",
				"code":  "INVALID_TOTP_CODE",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "TOTP đã được kích hoạt thành công",
		})
	}
}

func SetupSMS(mfaService *services.RealMFAService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			PhoneNumber string `json:"phone_number" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Số điện thoại không hợp lệ",
				"code":  "INVALID_REQUEST",
			})
			return
		}

		userID := c.MustGet("user_id").(uuid.UUID)

		// Setup SMS
		if err := mfaService.SetupSMS(userID, req.PhoneNumber); err != nil {
			auditService.LogEvent(userID, "mfa_sms_setup_failed", "mfa", "", false,
				map[string]interface{}{"error": err.Error()},
				c.ClientIP(), c.GetHeader("User-Agent"))

			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Không thể thiết lập SMS",
				"code":    "SMS_SETUP_FAILED",
				"details": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success":      true,
			"message":      "Mã xác thực đã được gửi qua SMS",
			"instructions": "Nhập mã 6 số nhận được qua SMS để kích hoạt",
		})
	}
}

func VerifySMSSetup(mfaService *services.RealMFAService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Code string `json:"code" binding:"required,len=6"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Mã SMS không hợp lệ",
				"code":  "INVALID_REQUEST",
			})
			return
		}

		userID := c.MustGet("user_id").(uuid.UUID)

		// Verify SMS setup
		if err := mfaService.VerifySMSSetup(userID, req.Code); err != nil {
			auditService.LogEvent(userID, "mfa_sms_verify_failed", "mfa", "", false,
				map[string]interface{}{"error": err.Error()},
				c.ClientIP(), c.GetHeader("User-Agent"))

			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Mã SMS không đúng",
				"code":  "INVALID_SMS_CODE",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "SMS MFA đã được kích hoạt thành công",
		})
	}
}

func SendEmailMFA(mfaService *services.RealMFAService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.MustGet("user_id").(uuid.UUID)
		user := c.MustGet("user").(*models.User)

		// Send email MFA code
		if err := mfaService.SendEmailMFA(userID, user.Email); err != nil {
			auditService.LogEvent(userID, "mfa_email_send_failed", "mfa", "", false,
				map[string]interface{}{"error": err.Error()},
				c.ClientIP(), c.GetHeader("User-Agent"))

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Không thể gửi email",
				"code":  "EMAIL_SEND_FAILED",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Mã xác thực đã được gửi qua email",
		})
	}
}

func VerifyBackupCode(mfaService *services.RealMFAService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Code string `json:"code" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Mã backup không hợp lệ",
				"code":  "INVALID_REQUEST",
			})
			return
		}

		userID := c.MustGet("user_id").(uuid.UUID)

		// Verify backup code
		if err := mfaService.VerifyBackupCode(userID, req.Code); err != nil {
			auditService.LogEvent(userID, "mfa_backup_verify_failed", "mfa", "", false,
				map[string]interface{}{"error": err.Error()},
				c.ClientIP(), c.GetHeader("User-Agent"))

			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Mã backup không đúng",
				"code":  "INVALID_BACKUP_CODE",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Xác thực thành công",
			"warning": "Mã backup đã được sử dụng và không thể dùng lại",
		})
	}
}

func GetMFAStatus(mfaService *services.RealMFAService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// This would require implementing GetMFAStatus method in RealMFAService
		// For now, return a placeholder response
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"totp_enabled":           false,
				"sms_enabled":            false,
				"email_enabled":          false,
				"push_enabled":           false,
				"backup_codes_remaining": 0,
			},
		})
	}
}

// Enhanced Login with MFA support - DISABLED due to duplicate function
/*func Login(authService *services.AuthService, auditService *services.AuditService, mfaService *services.RealMFAService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required,min=8"`
			MFACode  string `json:"mfa_code,omitempty"`
			Remember bool   `json:"remember,omitempty"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Dữ liệu đăng nhập không hợp lệ",
				"code":  "INVALID_REQUEST",
			})
			return
		}

		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")

		// Step 1: Verify credentials
		user, err := authService.ValidateCredentials(req.Email, req.Password)
		if err != nil {
			// Log failed login attempt
			auditService.LogEvent(uuid.Nil, "login_failed", "auth", "", false,
				map[string]interface{}{
					"email": req.Email,
					"error": err.Error(),
					"stage": "credential_validation",
				}, clientIP, userAgent)

			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Email hoặc mật khẩu không đúng",
				"code":  "INVALID_CREDENTIALS",
			})
			return
		}

		// Check if user account is active
		if user.Status != models.UserStatusActive {
			auditService.LogEvent(user.ID, "login_blocked_inactive", "auth", "", false,
				map[string]interface{}{
					"user_status": string(user.Status),
				}, clientIP, userAgent)

			c.JSON(http.StatusForbidden, gin.H{
				"error": "Tài khoản không hoạt động",
				"code":  "ACCOUNT_INACTIVE",
			})
			return
		}

		// Step 2: Check if MFA is required
		mfaRequired := user.MFAEnabled

		if mfaRequired && req.MFACode == "" {
			// Create MFA challenge session
			sessionID := uuid.New().String()

			// Try to create TOTP challenge first (most common)
			challenge, err := mfaService.CreateMFAChallenge(
				user.ID,
				sessionID,
				"totp", // Default to TOTP first
				clientIP,
				userAgent,
			)

			if err != nil {
				// If TOTP fails, try SMS
				challenge, err = mfaService.CreateMFAChallenge(
					user.ID,
					sessionID,
					"sms",
					clientIP,
					userAgent,
				)
			}

			if err != nil {
				auditService.LogEvent(user.ID, "mfa_challenge_failed", "auth", "", false,
					map[string]interface{}{"error": err.Error()}, clientIP, userAgent)

				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Không thể tạo thử thách MFA",
					"code":  "MFA_CHALLENGE_FAILED",
				})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"mfa_required": true,
				"mfa_methods": []string{"totp", "sms", "email", "backup_code"},
				"challenge_id": challenge.ID.String(),
				"session_id": sessionID,
				"expires_at": challenge.ExpiresAt,
				"message": "Nhập mã xác thực để hoàn tất đăng nhập",
			})
			return
		}

		// Step 3: Verify MFA if provided
		if mfaRequired && req.MFACode != "" {
			// This would require challenge ID from previous step
			// In a real implementation, you'd get this from session or request
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Vui lòng sử dụng endpoint /auth/verify-mfa",
				"code":  "USE_MFA_ENDPOINT",
			})
			return
		}

		// Step 4: Generate tokens (if no MFA required)
		accessToken, refreshToken, err := authService.GenerateTokens(user.ID, req.Remember)
		if err != nil {
			auditService.LogEvent(user.ID, "token_generation_failed", "auth", "", false,
				map[string]interface{}{"error": err.Error()}, clientIP, userAgent)

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Lỗi tạo token",
				"code":  "TOKEN_GENERATION_FAILED",
			})
			return
		}

		// Step 5: Update user's last login
		authService.UpdateLastLogin(user.ID, clientIP)

		// Step 6: Log successful login
		auditService.LogEvent(user.ID, "login_success", "auth", "", true,
			map[string]interface{}{
				"mfa_required": mfaRequired,
				"remember": req.Remember,
			}, clientIP, userAgent)

		// Step 7: Return success response
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"user": gin.H{
				"id":         user.ID,
				"email":      user.Email,
				"first_name": user.FirstName,
				"last_name":  user.LastName,
				"role":       user.Role,
				"mfa_enabled": user.MFAEnabled,
			},
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"expires_in":    3600, // 1 hour
		})
	}
}*/

/*func VerifyMFA(authService *services.AuthService, mfaService *services.RealMFAService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			ChallengeID string `json:"challenge_id" binding:"required"`
			MFACode     string `json:"mfa_code" binding:"required"`
			Remember    bool   `json:"remember,omitempty"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Dữ liệu xác thực không hợp lệ",
				"code":  "INVALID_REQUEST",
			})
			return
		}

		challengeUUID, err := uuid.Parse(req.ChallengeID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Challenge ID không hợp lệ",
				"code":  "INVALID_CHALLENGE_ID",
			})
			return
		}

		clientIP := c.ClientIP()
		userAgent := c.GetHeader("User-Agent")

		// Verify MFA challenge
		challenge, err := mfaService.VerifyMFAChallenge(challengeUUID, req.MFACode)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Mã xác thực không đúng",
				"code":  "INVALID_MFA_CODE",
				"details": err.Error(),
			})
			return
		}

		if challenge.Status != "verified" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Xác thực thất bại",
				"code":  "VERIFICATION_FAILED",
				"status": challenge.Status,
			})
			return
		}

		// Get user information
		user, err := authService.GetUserByID(challenge.UserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Không thể lấy thông tin người dùng",
				"code":  "USER_FETCH_FAILED",
			})
			return
		}

		// Generate tokens
		accessToken, refreshToken, err := authService.GenerateTokens(user.ID, req.Remember)
		if err != nil {
			auditService.LogEvent(user.ID, "token_generation_failed", "auth", "", false,
				map[string]interface{}{"error": err.Error()}, clientIP, userAgent)

			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Lỗi tạo token",
				"code":  "TOKEN_GENERATION_FAILED",
			})
			return
		}

		// Update last login
		authService.UpdateLastLogin(user.ID, clientIP)

		// Log successful MFA login
		auditService.LogEvent(user.ID, "mfa_login_success", "auth", challenge.ID.String(), true,
			map[string]interface{}{
				"mfa_method": challenge.Method,
				"remember": req.Remember,
			}, clientIP, userAgent)

		// Return success response
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"user": gin.H{
				"id":         user.ID,
				"email":      user.Email,
				"first_name": user.FirstName,
				"last_name":  user.LastName,
				"role":       user.Role,
				"mfa_enabled": user.MFAEnabled,
			},
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"expires_in":    3600, // 1 hour
			"message": "Đăng nhập thành công",
		})
	}
}*/
