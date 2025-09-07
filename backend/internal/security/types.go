package security

import "time"

// SecurityAnalysisRequest represents a request to analyze for security threats
type SecurityAnalysisRequest struct {
	RequestID    string                 `json:"request_id"`
	UserID       string                 `json:"user_id,omitempty"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	Method       string                 `json:"method"`
	URI          string                 `json:"uri"`
	Headers      map[string]string      `json:"headers"`
	Body         interface{}            `json:"body,omitempty"`
	StatusCode   int                    `json:"status_code,omitempty"`
	Country      string                 `json:"country,omitempty"`
	City         string                 `json:"city,omitempty"`
	ISP          string                 `json:"isp,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
}

// SecurityAnalysisResult represents the result of a security analysis
type SecurityAnalysisResult struct {
	RequestID       string           `json:"request_id"`
	Blocked         bool             `json:"blocked"`
	RiskScore       int              `json:"risk_score"`
	Threats         []DetectedThreat `json:"threats"`
	Recommendations []string         `json:"recommendations"`
	ProcessingTime  time.Duration    `json:"processing_time"`
}

// DetectedThreat represents a detected security threat
type DetectedThreat struct {
	Type        ThreatType  `json:"type"`
	Level       ThreatLevel `json:"level"`
	Description string      `json:"description"`
	Score       int         `json:"score"`
	Pattern     string      `json:"pattern"`
	Confidence  float64     `json:"confidence"`
}

// SecurityMetrics holds security metrics for monitoring
type SecurityMetrics struct {
	TotalRequests         int64                      `json:"total_requests"`
	BlockedRequests       int64                      `json:"blocked_requests"`
	ThreatsByType         map[ThreatType]int64       `json:"threats_by_type"`
	ThreatsByLevel        map[ThreatLevel]int64      `json:"threats_by_level"`
	TopThreateningIPs     []IPThreatSummary          `json:"top_threatening_ips"`
	RecentIncidents       []SecurityIncident         `json:"recent_incidents"`
	AverageRiskScore      float64                    `json:"average_risk_score"`
	DetectionAccuracy     float64                    `json:"detection_accuracy"`
	ResponseTime          time.Duration              `json:"response_time"`
	UpdatedAt             time.Time                  `json:"updated_at"`
}

// IPThreatSummary provides a summary of threats from an IP
type IPThreatSummary struct {
	IPAddress   string    `json:"ip_address"`
	ThreatScore int       `json:"threat_score"`
	EventCount  int       `json:"event_count"`
	LastSeen    time.Time `json:"last_seen"`
	CountryCode string    `json:"country_code"`
	ISP         string    `json:"isp"`
	IsBlocked   bool      `json:"is_blocked"`
}

// SecurityIncident represents a high-level security incident
type SecurityIncident struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	UserID      *string                `json:"user_id,omitempty"`
	IPAddress   string                 `json:"ip_address"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details"`
	Status      string                 `json:"status"` // open, investigating, resolved
	CreatedAt   time.Time              `json:"created_at"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	ResolvedBy  *string                `json:"resolved_by,omitempty"`
}

// SecurityAlert represents an alert that should be sent to administrators
type SecurityAlert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Priority    string                 `json:"priority"` // low, medium, high, critical
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details"`
	Recipients  []string               `json:"recipients"`
	Channels    []string               `json:"channels"` // email, sms, slack, etc.
	CreatedAt   time.Time              `json:"created_at"`
	SentAt      *time.Time             `json:"sent_at,omitempty"`
	Status      string                 `json:"status"` // pending, sent, failed
}

// RealTimeSecurityStatus provides real-time security status
type RealTimeSecurityStatus struct {
	Status              string                    `json:"status"` // normal, elevated, high, critical
	ActiveThreats       int                       `json:"active_threats"`
	BlockedIPs          int                       `json:"blocked_ips"`
	RequestsLastHour    int                       `json:"requests_last_hour"`
	ThreatsLastHour     int                       `json:"threats_last_hour"`
	AverageRiskScore    float64                   `json:"average_risk_score"`
	TopThreatTypes      []ThreatTypeCount         `json:"top_threat_types"`
	GeographicalSpread  []CountryThreatCount      `json:"geographical_spread"`
	SystemHealth        SecuritySystemHealth      `json:"system_health"`
	LastUpdated         time.Time                 `json:"last_updated"`
}

// ThreatTypeCount represents count of threats by type
type ThreatTypeCount struct {
	Type  ThreatType `json:"type"`
	Count int        `json:"count"`
}

// CountryThreatCount represents threats by country
type CountryThreatCount struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	Count       int    `json:"count"`
	RiskLevel   string `json:"risk_level"`
}

// SecuritySystemHealth represents the health of security systems
type SecuritySystemHealth struct {
	IDSStatus          string    `json:"ids_status"` // healthy, degraded, offline
	DatabaseLatency    int       `json:"database_latency_ms"`
	ProcessingLatency  int       `json:"processing_latency_ms"`
	MemoryUsage        float64   `json:"memory_usage_percent"`
	CPUUsage           float64   `json:"cpu_usage_percent"`
	QueueSize          int       `json:"queue_size"`
	ErrorRate          float64   `json:"error_rate_percent"`
	LastHealthCheck    time.Time `json:"last_health_check"`
}

// SecurityConfiguration represents IDS configuration settings
type SecurityConfiguration struct {
	GeneralSettings struct {
		MonitoringEnabled         bool `json:"monitoring_enabled"`
		AutoBlockEnabled          bool `json:"auto_block_enabled"`
		AlertingEnabled           bool `json:"alerting_enabled"`
		GeoLocationEnabled        bool `json:"geo_location_enabled"`
		BehavioralAnalysisEnabled bool `json:"behavioral_analysis_enabled"`
		LogRetentionDays          int  `json:"log_retention_days"`
	} `json:"general_settings"`

	ThreatDetection struct {
		BruteForceThreshold     int     `json:"brute_force_threshold"`
		RateLimitMaxRequests    int     `json:"rate_limit_max_requests"`
		RateLimitWindowMinutes  int     `json:"rate_limit_window_minutes"`
		AnomalyThreshold        float64 `json:"anomaly_threshold"`
		AutoBlockThreshold      int     `json:"auto_block_threshold"`
		BlockDurationHours      int     `json:"block_duration_hours"`
	} `json:"threat_detection"`

	IPManagement struct {
		WhitelistedIPs          []string `json:"whitelisted_ips"`
		BlacklistedIPs          []string `json:"blacklisted_ips"`
		AutoUpdateBlacklist     bool     `json:"auto_update_blacklist"`
		ThreatIntelligenceFeeds []string `json:"threat_intelligence_feeds"`
	} `json:"ip_management"`

	Alerting struct {
		EmailEnabled        bool     `json:"email_enabled"`
		SMSEnabled          bool     `json:"sms_enabled"`
		SlackEnabled        bool     `json:"slack_enabled"`
		WebhookEnabled      bool     `json:"webhook_enabled"`
		EmailRecipients     []string `json:"email_recipients"`
		SMSRecipients       []string `json:"sms_recipients"`
		SlackChannels       []string `json:"slack_channels"`
		WebhookURLs         []string `json:"webhook_urls"`
		AlertThresholds     struct {
			LowPriority      int `json:"low_priority"`
			MediumPriority   int `json:"medium_priority"`
			HighPriority     int `json:"high_priority"`
			CriticalPriority int `json:"critical_priority"`
		} `json:"alert_thresholds"`
	} `json:"alerting"`
}

// SecurityReport represents a comprehensive security report
type SecurityReport struct {
	ID              string                    `json:"id"`
	Type            string                    `json:"type"` // daily, weekly, monthly, custom
	Period          ReportPeriod              `json:"period"`
	Summary         SecurityReportSummary     `json:"summary"`
	ThreatAnalysis  ThreatAnalysis            `json:"threat_analysis"`
	IPAnalysis      IPAnalysis                `json:"ip_analysis"`
	UserAnalysis    UserAnalysis              `json:"user_analysis"`
	Trends          SecurityTrends            `json:"trends"`
	Recommendations []SecurityRecommendation  `json:"recommendations"`
	GeneratedAt     time.Time                 `json:"generated_at"`
	GeneratedBy     string                    `json:"generated_by"`
}

// ReportPeriod represents the time period for a report
type ReportPeriod struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
	TimeZone  string    `json:"timezone"`
}

// SecurityReportSummary provides high-level summary
type SecurityReportSummary struct {
	TotalRequests       int64   `json:"total_requests"`
	ThreatsDetected     int64   `json:"threats_detected"`
	BlockedRequests     int64   `json:"blocked_requests"`
	UniqueIPs           int64   `json:"unique_ips"`
	BlockedIPs          int64   `json:"blocked_ips"`
	AverageRiskScore    float64 `json:"average_risk_score"`
	DetectionAccuracy   float64 `json:"detection_accuracy"`
	FalsePositiveRate   float64 `json:"false_positive_rate"`
}

// ThreatAnalysis provides detailed threat analysis
type ThreatAnalysis struct {
	ThreatsByType         map[ThreatType]int64       `json:"threats_by_type"`
	ThreatsByLevel        map[ThreatLevel]int64      `json:"threats_by_level"`
	ThreatsByHour         []HourlyThreatCount        `json:"threats_by_hour"`
	MostTargetedEndpoints []EndpointThreatCount      `json:"most_targeted_endpoints"`
	AttackPatterns        []AttackPattern            `json:"attack_patterns"`
}

// IPAnalysis provides IP-based analysis
type IPAnalysis struct {
	TopThreateningIPs    []IPThreatSummary      `json:"top_threatening_ips"`
	GeographicalSpread   []CountryThreatCount   `json:"geographical_spread"`
	NewThreateningIPs    []IPThreatSummary      `json:"new_threatening_ips"`
	BlockedIPsAnalysis   []BlockedIPAnalysis    `json:"blocked_ips_analysis"`
}

// UserAnalysis provides user-based analysis
type UserAnalysis struct {
	UsersAtRisk          []UserRiskProfile      `json:"users_at_risk"`
	BehavioralAnomalies  []BehavioralAnomaly    `json:"behavioral_anomalies"`
	CompromisedAccounts  []CompromisedAccount   `json:"compromised_accounts"`
	UserSecurityScore    map[string]int         `json:"user_security_score"`
}

// SecurityTrends shows trends over time
type SecurityTrends struct {
	ThreatTrend        []TrendPoint `json:"threat_trend"`
	RiskScoreTrend     []TrendPoint `json:"risk_score_trend"`
	GeographicalTrend  []TrendPoint `json:"geographical_trend"`
	DetectionTrend     []TrendPoint `json:"detection_trend"`
}

// Additional supporting types
type HourlyThreatCount struct {
	Hour  int `json:"hour"`
	Count int `json:"count"`
}

type EndpointThreatCount struct {
	Endpoint string `json:"endpoint"`
	Count    int    `json:"count"`
}

type AttackPattern struct {
	Pattern     string  `json:"pattern"`
	Frequency   int     `json:"frequency"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
}

type BlockedIPAnalysis struct {
	IP           string    `json:"ip"`
	BlockReason  string    `json:"block_reason"`
	BlockedAt    time.Time `json:"blocked_at"`
	BlockedUntil time.Time `json:"blocked_until"`
	ThreatScore  int       `json:"threat_score"`
}

type UserRiskProfile struct {
	UserID      string  `json:"user_id"`
	Email       string  `json:"email"`
	RiskScore   int     `json:"risk_score"`
	RiskFactors []string `json:"risk_factors"`
	LastSeen    time.Time `json:"last_seen"`
}

type BehavioralAnomaly struct {
	UserID      string    `json:"user_id"`
	AnomalyType string    `json:"anomaly_type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	DetectedAt  time.Time `json:"detected_at"`
}

type CompromisedAccount struct {
	UserID       string    `json:"user_id"`
	Email        string    `json:"email"`
	CompromiseType string  `json:"compromise_type"`
	Indicators   []string  `json:"indicators"`
	DetectedAt   time.Time `json:"detected_at"`
	Status       string    `json:"status"`
}

type TrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

type SecurityRecommendation struct {
	Priority    string `json:"priority"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Effort      string `json:"effort"`
	Timeline    string `json:"timeline"`
}