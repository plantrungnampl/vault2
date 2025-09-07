package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type SecurityConfig struct {
	ContentSecurityPolicy string          `json:"content_security_policy"`
	HSTSMaxAge            int             `json:"hsts_max_age"`
	HSTSIncludeSubdomains bool            `json:"hsts_include_subdomains"`
	HSTSPreload           bool            `json:"hsts_preload"`
	FrameOptions          string          `json:"frame_options"`
	ContentTypeOptions    bool            `json:"content_type_options"`
	XSSProtection         string          `json:"xss_protection"`
	ReferrerPolicy        string          `json:"referrer_policy"`
	PermissionsPolicy     string          `json:"permissions_policy"`
	ExpectCT              *ExpectCTConfig `json:"expect_ct,omitempty"`
	EnableNonce           bool            `json:"enable_nonce"`
}

type ExpectCTConfig struct {
	MaxAge    int    `json:"max_age"`
	Enforce   bool   `json:"enforce"`
	ReportURI string `json:"report_uri,omitempty"`
}

var defaultSecurityConfig = SecurityConfig{
	ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https:; media-src 'self'; object-src 'none'; child-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';",
	HSTSMaxAge:            31536000,
	HSTSIncludeSubdomains: true,
	HSTSPreload:           true,
	FrameOptions:          "DENY",
	ContentTypeOptions:    true,
	XSSProtection:         "1; mode=block",
	ReferrerPolicy:        "strict-origin-when-cross-origin",
	PermissionsPolicy:     "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=()",
	ExpectCT: &ExpectCTConfig{
		MaxAge:  86400,
		Enforce: true,
	},
	EnableNonce: true,
}

func SecurityHeaders(config *SecurityConfig) gin.HandlerFunc {
	if config == nil {
		config = &defaultSecurityConfig
	}

	return func(c *gin.Context) {
		var nonce string
		if config.EnableNonce {
			nonce = generateNonce()
			c.Set("nonce", nonce)
		}

		headers := c.Writer.Header()

		if config.ContentSecurityPolicy != "" {
			csp := config.ContentSecurityPolicy
			if config.EnableNonce && nonce != "" {
				csp = strings.ReplaceAll(csp, "'unsafe-inline'", fmt.Sprintf("'nonce-%s'", nonce))
			}
			headers.Set("Content-Security-Policy", csp)
		}

		if config.HSTSMaxAge > 0 {
			hstsValue := fmt.Sprintf("max-age=%d", config.HSTSMaxAge)
			if config.HSTSIncludeSubdomains {
				hstsValue += "; includeSubDomains"
			}
			if config.HSTSPreload {
				hstsValue += "; preload"
			}
			headers.Set("Strict-Transport-Security", hstsValue)
		}

		if config.FrameOptions != "" {
			headers.Set("X-Frame-Options", config.FrameOptions)
		}

		if config.ContentTypeOptions {
			headers.Set("X-Content-Type-Options", "nosniff")
		}

		if config.XSSProtection != "" {
			headers.Set("X-XSS-Protection", config.XSSProtection)
		}

		if config.ReferrerPolicy != "" {
			headers.Set("Referrer-Policy", config.ReferrerPolicy)
		}

		if config.PermissionsPolicy != "" {
			headers.Set("Permissions-Policy", config.PermissionsPolicy)
		}

		if config.ExpectCT != nil {
			expectCTValue := fmt.Sprintf("max-age=%d", config.ExpectCT.MaxAge)
			if config.ExpectCT.Enforce {
				expectCTValue += ", enforce"
			}
			if config.ExpectCT.ReportURI != "" {
				expectCTValue += fmt.Sprintf(`, report-uri="%s"`, config.ExpectCT.ReportURI)
			}
			headers.Set("Expect-CT", expectCTValue)
		}

		headers.Set("X-Powered-By", "")
		headers.Set("Server", "SecureVault")
		headers.Set("X-Robots-Tag", "noindex, nofollow, nosnippet, noarchive")

		c.Next()
	}
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		allowedOrigins := []string{
			"https://securevault.local",
			"https://admin.securevault.local",
			"http://localhost:3000",
			"http://localhost:3001",
		}

		var allowOrigin string
		for _, allowed := range allowedOrigins {
			if origin == allowed {
				allowOrigin = origin
				break
			}
		}

		if allowOrigin != "" {
			c.Header("Access-Control-Allow-Origin", allowOrigin)
		}

		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func ContentTypeValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			contentType := c.GetHeader("Content-Type")
			if contentType == "" {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Content-Type header is required",
					"code":  "MISSING_CONTENT_TYPE",
				})
				c.Abort()
				return
			}

			allowedTypes := []string{
				"application/json",
				"application/x-www-form-urlencoded",
				"multipart/form-data",
			}

			valid := false
			for _, allowedType := range allowedTypes {
				if strings.HasPrefix(contentType, allowedType) {
					valid = true
					break
				}
			}

			if !valid {
				c.JSON(http.StatusUnsupportedMediaType, gin.H{
					"error": "Unsupported content type",
					"code":  "UNSUPPORTED_CONTENT_TYPE",
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

func RequestSizeLimit(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxSize {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": fmt.Sprintf("Request body too large. Maximum size: %d bytes", maxSize),
				"code":  "REQUEST_TOO_LARGE",
			})
			c.Abort()
			return
		}

		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
		c.Next()
	}
}

func HTTPSRedirect() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Header.Get("X-Forwarded-Proto") == "http" {
			httpsURL := "https://" + c.Request.Host + c.Request.RequestURI
			c.Redirect(http.StatusMovedPermanently, httpsURL)
			c.Abort()
			return
		}
		c.Next()
	}
}

func CSRFProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		token := c.GetHeader("X-CSRF-Token")
		if token == "" {
			token = c.PostForm("_token")
		}

		if token == "" {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "CSRF token missing",
				"code":  "CSRF_TOKEN_MISSING",
			})
			c.Abort()
			return
		}

		if !validateCSRFToken(token) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Invalid CSRF token",
				"code":  "CSRF_TOKEN_INVALID",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func ClickjackingProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("Content-Security-Policy", "frame-ancestors 'none'")
		c.Next()
	}
}

func MIMESniffingProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Next()
	}
}

func XSSProtectionHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Next()
	}
}

func SecurityHeadersReporting(reportURI string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if reportURI != "" {
			csp := c.Writer.Header().Get("Content-Security-Policy")
			if csp != "" {
				csp += fmt.Sprintf("; report-uri %s", reportURI)
				c.Header("Content-Security-Policy", csp)
			}

			c.Header("Report-To", fmt.Sprintf(`{"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"%s"}]}`, reportURI))
		}
		c.Next()
	}
}

func ReferrerPolicyHeader(policy string) gin.HandlerFunc {
	if policy == "" {
		policy = "strict-origin-when-cross-origin"
	}

	return func(c *gin.Context) {
		c.Header("Referrer-Policy", policy)
		c.Next()
	}
}

func FeaturePolicyHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		policy := "geolocation 'none'; microphone 'none'; camera 'none'; payment 'none'; usb 'none'; magnetometer 'none'; gyroscope 'none'; speaker 'none'"
		c.Header("Feature-Policy", policy)
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=()")
		c.Next()
	}
}

func DNSPrefetchControl() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-DNS-Prefetch-Control", "off")
		c.Next()
	}
}

func ExpectCTHeader(config *ExpectCTConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if config != nil {
			value := fmt.Sprintf("max-age=%d", config.MaxAge)
			if config.Enforce {
				value += ", enforce"
			}
			if config.ReportURI != "" {
				value += fmt.Sprintf(`, report-uri="%s"`, config.ReportURI)
			}
			c.Header("Expect-CT", value)
		}
		c.Next()
	}
}

func HSTSHeader(maxAge int, includeSubdomains, preload bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		value := fmt.Sprintf("max-age=%d", maxAge)
		if includeSubdomains {
			value += "; includeSubDomains"
		}
		if preload {
			value += "; preload"
		}
		c.Header("Strict-Transport-Security", value)
		c.Next()
	}
}

func NoIndexHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Robots-Tag", "noindex, nofollow, nosnippet, noarchive")
		c.Next()
	}
}

func ServerHeader(serverName string) gin.HandlerFunc {
	if serverName == "" {
		serverName = "SecureVault"
	}

	return func(c *gin.Context) {
		c.Header("Server", serverName)
		c.Header("X-Powered-By", "")
		c.Next()
	}
}

func SubresourceIntegrityHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy",
			"require-sri-for script style; "+
				"script-src 'self' 'unsafe-inline' 'unsafe-eval'; "+
				"style-src 'self' 'unsafe-inline';")
		c.Next()
	}
}

func generateNonce() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}

func validateCSRFToken(token string) bool {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil || len(decoded) < 32 {
		return false
	}

	timestamp := int64(0)
	if len(decoded) >= 40 {
		timestamp = int64(decoded[32])<<24 | int64(decoded[33])<<16 | int64(decoded[34])<<8 | int64(decoded[35])
	}

	if timestamp > 0 && time.Now().Unix()-timestamp > 3600 {
		return false
	}

	return true
}

func GenerateCSRFToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)

	timestamp := time.Now().Unix()
	timestampBytes := []byte{
		byte(timestamp >> 24),
		byte(timestamp >> 16),
		byte(timestamp >> 8),
		byte(timestamp),
	}

	token := append(bytes, timestampBytes...)
	return base64.StdEncoding.EncodeToString(token)
}

func SecurityHeadersBundle() []gin.HandlerFunc {
	return []gin.HandlerFunc{
		SecurityHeaders(nil),
		CORSMiddleware(),
		ContentTypeValidation(),
		RequestSizeLimit(10 * 1024 * 1024), // 10MB
		HTTPSRedirect(),
		CSRFProtection(),
		ClickjackingProtection(),
		MIMESniffingProtection(),
		XSSProtectionHeader(),
		ReferrerPolicyHeader("strict-origin-when-cross-origin"),
		FeaturePolicyHeader(),
		DNSPrefetchControl(),
		ExpectCTHeader(&ExpectCTConfig{
			MaxAge:  86400,
			Enforce: true,
		}),
		HSTSHeader(31536000, true, true),
		NoIndexHeader(),
		ServerHeader("SecureVault"),
		SubresourceIntegrityHeader(),
	}
}

type SecurityMiddleware struct {
	config *SecurityConfig
}

func NewSecurityMiddleware(config *SecurityConfig) *SecurityMiddleware {
	if config == nil {
		config = &defaultSecurityConfig
	}
	return &SecurityMiddleware{config: config}
}

func (sm *SecurityMiddleware) Headers() gin.HandlerFunc {
	return SecurityHeaders(sm.config)
}

func (sm *SecurityMiddleware) CORS() gin.HandlerFunc {
	return CORSMiddleware()
}

func (sm *SecurityMiddleware) ContentType() gin.HandlerFunc {
	return ContentTypeValidation()
}

func (sm *SecurityMiddleware) RequestSize(maxSize int64) gin.HandlerFunc {
	return RequestSizeLimit(maxSize)
}

func (sm *SecurityMiddleware) HTTPS() gin.HandlerFunc {
	return HTTPSRedirect()
}

func (sm *SecurityMiddleware) CSRF() gin.HandlerFunc {
	return CSRFProtection()
}

func (sm *SecurityMiddleware) Bundle() []gin.HandlerFunc {
	return SecurityHeadersBundle()
}

func APISecurityMiddleware() []gin.HandlerFunc {
	return []gin.HandlerFunc{
		CORSMiddleware(),
		ContentTypeValidation(),
		RequestSizeLimit(1 * 1024 * 1024), // 1MB for API
		SecurityHeaders(&SecurityConfig{
			ContentSecurityPolicy: "default-src 'none'; frame-ancestors 'none';",
			HSTSMaxAge:            31536000,
			HSTSIncludeSubdomains: true,
			HSTSPreload:           true,
			FrameOptions:          "DENY",
			ContentTypeOptions:    true,
			XSSProtection:         "1; mode=block",
			ReferrerPolicy:        "no-referrer",
			PermissionsPolicy:     "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=()",
		}),
		func(c *gin.Context) {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")
			c.Next()
		},
	}
}

func WebSecurityMiddleware() []gin.HandlerFunc {
	return SecurityHeadersBundle()
}
