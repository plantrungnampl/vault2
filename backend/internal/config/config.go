package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	Database   DatabaseConfig   `mapstructure:"database"`
	Redis      RedisConfig      `mapstructure:"redis"`
	Security   SecurityConfig   `mapstructure:"security"`
	Logging    LoggingConfig    `mapstructure:"logging"`
	MFA        MFAConfig        `mapstructure:"mfa"`
	Backup     BackupConfig     `mapstructure:"backup"`
	Monitoring MonitoringConfig `mapstructure:"monitoring"`
}

type ServerConfig struct {
	Port        int        `mapstructure:"port"`
	Environment string     `mapstructure:"environment"`
	TLS         TLSConfig  `mapstructure:"tls"`
	CORS        CORSConfig `mapstructure:"cors"`
}

type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type CORSConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	AllowedMethods []string `mapstructure:"allowed_methods"`
	AllowedHeaders []string `mapstructure:"allowed_headers"`
}

type DatabaseConfig struct {
	URL             string        `mapstructure:"url"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	SSLMode         string        `mapstructure:"ssl_mode"`
	EncryptionKey   string        `mapstructure:"encryption_key"`
}

type RedisConfig struct {
	URL      string `mapstructure:"url"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	TLS      bool   `mapstructure:"tls"`
}

type SecurityConfig struct {
	JWTSecret           string        `mapstructure:"jwt_secret"`
	JWTExpiry           time.Duration `mapstructure:"jwt_expiry"`
	RefreshTokenExpiry  time.Duration `mapstructure:"refresh_token_expiry"`
	PasswordMinLength   int           `mapstructure:"password_min_length"`
	PasswordComplexity  bool          `mapstructure:"password_complexity"`
	MaxLoginAttempts    int           `mapstructure:"max_login_attempts"`
	AccountLockoutTime  time.Duration `mapstructure:"account_lockout_time"`
	SessionTimeout      time.Duration `mapstructure:"session_timeout"`
	EncryptionAlgorithm string        `mapstructure:"encryption_algorithm"`
	KeyRotationInterval time.Duration `mapstructure:"key_rotation_interval"`
	RateLimitRPM        int           `mapstructure:"rate_limit_rpm"`
	HMACSecret          string        `mapstructure:"hmac_secret"`
	CSRFSecret          string        `mapstructure:"csrf_secret"`
	PasswordHistory     int           `mapstructure:"password_history"`
}

type MFAConfig struct {
	TOTPIssuer     string `mapstructure:"totp_issuer"`
	TOTPKeySize    int    `mapstructure:"totp_key_size"`
	WebAuthnRPID   string `mapstructure:"webauthn_rp_id"`
	WebAuthnRPName string `mapstructure:"webauthn_rp_name"`
	WebAuthnOrigin string `mapstructure:"webauthn_origin"`
	SMSProvider    string `mapstructure:"sms_provider"`
	SMSAPIKey      string `mapstructure:"sms_api_key"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

type BackupConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	Interval        time.Duration `mapstructure:"interval"`
	Retention       time.Duration `mapstructure:"retention"`
	StorageProvider string        `mapstructure:"storage_provider"`
	S3Bucket        string        `mapstructure:"s3_bucket"`
	S3Region        string        `mapstructure:"s3_region"`
	EncryptionKey   string        `mapstructure:"encryption_key"`
}

type MonitoringConfig struct {
	PrometheusEnabled bool   `mapstructure:"prometheus_enabled"`
	JaegerEndpoint    string `mapstructure:"jaeger_endpoint"`
	MetricsPath       string `mapstructure:"metrics_path"`
}

// LoadConfig loads configuration from environment variables and config files
func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("$HOME/.securevault")
	viper.AddConfigPath("/etc/securevault")

	// Set default values
	setDefaults()

	// Bind environment variables
	bindEnvironmentVariables()

	// Read config file if it exists
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

func setDefaults() {
	// Server defaults
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.environment", "development")
	viper.SetDefault("server.tls.enabled", false)
	viper.SetDefault("server.cors.allowed_origins", []string{"http://localhost:3000", "http://localhost:3001"})
	viper.SetDefault("server.cors.allowed_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	viper.SetDefault("server.cors.allowed_headers", []string{"Authorization", "Content-Type", "X-Requested-With"})

	// Database defaults
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)
	viper.SetDefault("database.conn_max_lifetime", time.Hour)
	viper.SetDefault("database.ssl_mode", "prefer")

	// Redis defaults
	viper.SetDefault("redis.url", "redis://localhost:6379")
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.tls", false)

	// Security defaults
	viper.SetDefault("security.jwt_expiry", 15*time.Minute)
	viper.SetDefault("security.refresh_token_expiry", 7*24*time.Hour)
	viper.SetDefault("security.password_min_length", 14)
	viper.SetDefault("security.password_complexity", true)
	viper.SetDefault("security.max_login_attempts", 5)
	viper.SetDefault("security.account_lockout_time", 30*time.Minute)
	viper.SetDefault("security.session_timeout", 2*time.Hour)
	viper.SetDefault("security.encryption_algorithm", "AES-256-GCM")
	viper.SetDefault("security.key_rotation_interval", 90*24*time.Hour)
	viper.SetDefault("security.rate_limit_rpm", 100)
	viper.SetDefault("security.password_history", 24)

	// MFA defaults
	viper.SetDefault("mfa.totp_issuer", "SecureVault")
	viper.SetDefault("mfa.totp_key_size", 32)
	viper.SetDefault("mfa.webauthn_rp_id", "localhost")
	viper.SetDefault("mfa.webauthn_rp_name", "SecureVault")
	viper.SetDefault("mfa.webauthn_origin", "http://localhost:3000")

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stdout")

	// Backup defaults
	viper.SetDefault("backup.enabled", true)
	viper.SetDefault("backup.interval", 24*time.Hour)
	viper.SetDefault("backup.retention", 90*24*time.Hour)
	viper.SetDefault("backup.storage_provider", "local")

	// Monitoring defaults
	viper.SetDefault("monitoring.prometheus_enabled", true)
	viper.SetDefault("monitoring.metrics_path", "/metrics")
}

func bindEnvironmentVariables() {
	viper.SetEnvPrefix("SECUREVAULT")
	viper.AutomaticEnv()

	// Bind specific environment variables
	envVars := map[string]string{
		"SERVER_PORT":             "server.port",
		"SERVER_ENVIRONMENT":      "server.environment",
		"SERVER_TLS_ENABLED":      "server.tls.enabled",
		"SERVER_TLS_CERT_FILE":    "server.tls.cert_file",
		"SERVER_TLS_KEY_FILE":     "server.tls.key_file",
		"DATABASE_URL":            "database.url",
		"DATABASE_ENCRYPTION_KEY": "database.encryption_key",
		"REDIS_URL":               "redis.url",
		"REDIS_PASSWORD":          "redis.password",
		"JWT_SECRET":              "security.jwt_secret",
		"HMAC_SECRET":             "security.hmac_secret",
		"CSRF_SECRET":             "security.csrf_secret",
		"WEBAUTHN_RP_ID":          "mfa.webauthn_rp_id",
		"WEBAUTHN_RP_NAME":        "mfa.webauthn_rp_name",
		"WEBAUTHN_ORIGIN":         "mfa.webauthn_origin",
		"SMS_API_KEY":             "mfa.sms_api_key",
		"BACKUP_S3_BUCKET":        "backup.s3_bucket",
		"BACKUP_S3_REGION":        "backup.s3_region",
		"BACKUP_ENCRYPTION_KEY":   "backup.encryption_key",
	}

	for envVar, configKey := range envVars {
		viper.BindEnv(configKey, "SECUREVAULT_"+envVar)
	}
}

func validateConfig(config *Config) error {
	// Validate required fields
	if config.Security.JWTSecret == "" {
		return fmt.Errorf("JWT secret is required")
	}

	if config.Security.HMACSecret == "" {
		return fmt.Errorf("HMAC secret is required")
	}

	if config.Database.URL == "" {
		return fmt.Errorf("database URL is required")
	}

	if config.Database.EncryptionKey == "" {
		return fmt.Errorf("database encryption key is required")
	}

	// Validate security settings
	if config.Security.PasswordMinLength < 8 {
		return fmt.Errorf("password minimum length must be at least 8 characters")
	}

	if config.Security.MaxLoginAttempts < 1 {
		return fmt.Errorf("max login attempts must be at least 1")
	}

	// Validate TLS configuration
	if config.Server.TLS.Enabled {
		if config.Server.TLS.CertFile == "" || config.Server.TLS.KeyFile == "" {
			return fmt.Errorf("TLS cert and key files are required when TLS is enabled")
		}

		if _, err := os.Stat(config.Server.TLS.CertFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS cert file does not exist: %s", config.Server.TLS.CertFile)
		}

		if _, err := os.Stat(config.Server.TLS.KeyFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS key file does not exist: %s", config.Server.TLS.KeyFile)
		}
	}

	return nil
}

// GetConfigPath returns the path to the configuration file
func GetConfigPath() string {
	if configFile := viper.ConfigFileUsed(); configFile != "" {
		return configFile
	}

	// Return default config path
	return filepath.Join(".", "config.yaml")
}

// SaveConfig saves the current configuration to file
func SaveConfig(config *Config) error {
	viper.Set("server", config.Server)
	viper.Set("database", config.Database)
	viper.Set("redis", config.Redis)
	viper.Set("security", config.Security)
	viper.Set("logging", config.Logging)
	viper.Set("mfa", config.MFA)
	viper.Set("backup", config.Backup)
	viper.Set("monitoring", config.Monitoring)

	return viper.WriteConfig()
}
