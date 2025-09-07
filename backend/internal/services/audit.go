package services

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"securevault/internal/database"
	"securevault/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AuditService handles comprehensive audit logging with blockchain-style hash chaining
type AuditService struct {
	db         *gorm.DB
	secretKey  []byte
	lastHash   string
	hashCache  map[string]string
	verifyMode bool
}

// AuditConfiguration holds audit system configuration
type AuditConfiguration struct {
	EnableHashChaining     bool   `json:"enable_hash_chaining"`
	EnableTamperDetection  bool   `json:"enable_tamper_detection"`
	HashAlgorithm         string `json:"hash_algorithm"`
	RetentionDays         int    `json:"retention_days"`
	EnableEncryption      bool   `json:"enable_encryption"`
	CompressionEnabled    bool   `json:"compression_enabled"`
	BackupFrequency       string `json:"backup_frequency"`
	AlertOnTamper         bool   `json:"alert_on_tamper"`
	Vietnamese            bool   `json:"vietnamese_messages"`
}

// AuditMetrics holds audit system metrics
type AuditMetrics struct {
	TotalLogs        int64     `json:"total_logs"`
	LogsToday        int64     `json:"logs_today"`
	FailedAttempts   int64     `json:"failed_attempts"`
	SecurityEvents   int64     `json:"security_events"`
	TamperAttempts   int64     `json:"tamper_attempts"`
	ChainIntegrity   bool      `json:"chain_integrity"`
	LastVerification time.Time `json:"last_verification"`
	StorageUsed      int64     `json:"storage_used"`
}

// AuditChainBlock represents a block in the audit chain
type AuditChainBlock struct {
	ID            uuid.UUID   `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	BlockNumber   int64       `json:"block_number" gorm:"uniqueIndex;not null"`
	PreviousHash  string      `json:"previous_hash" gorm:"not null;index"`
	BlockHash     string      `json:"block_hash" gorm:"not null;uniqueIndex"`
	Timestamp     time.Time   `json:"timestamp" gorm:"not null;index"`
	LogCount      int         `json:"log_count" gorm:"not null"`
	LogsHash      string      `json:"logs_hash" gorm:"not null"`
	Merkleroot    string      `json:"merkle_root" gorm:"not null"`
	Nonce         int64       `json:"nonce" gorm:"not null"`
	Signature     string      `json:"signature" gorm:"not null"`
	Verified      bool        `json:"verified" gorm:"default:true"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `json:"-" gorm:"index"`
}

// Enhanced AuditLog with blockchain features
type EnhancedAuditLog struct {
	models.AuditLog
	BlockNumber    int64  `json:"block_number" gorm:"index"`
	LogHash        string `json:"log_hash" gorm:"not null;index"`
	PreviousLogHash string `json:"previous_log_hash" gorm:"index"`
	ChainPosition  int    `json:"chain_position" gorm:"not null"`
	Integrity      bool   `json:"integrity" gorm:"default:true"`
	Encrypted      bool   `json:"encrypted" gorm:"default:false"`
	CompressedSize int    `json:"compressed_size"`
	OriginalSize   int    `json:"original_size"`
	Checksum       string `json:"checksum" gorm:"not null"`
	Version        int    `json:"version" gorm:"default:1"`
}

// AuditAnalytics provides advanced analytics on audit logs
type AuditAnalytics struct {
	UserActivity      map[string]int64    `json:"user_activity"`
	ActionFrequency   map[string]int64    `json:"action_frequency"`
	ResourceAccess    map[string]int64    `json:"resource_access"`
	SecurityPatterns  []SecurityPattern   `json:"security_patterns"`
	AnomalousActivity []AnomalousActivity `json:"anomalous_activity"`
	TrendAnalysis     TrendAnalysis       `json:"trend_analysis"`
	ComplianceMetrics ComplianceMetrics   `json:"compliance_metrics"`
	RiskScores        map[string]float64  `json:"risk_scores"`
}

// SecurityPattern represents detected security patterns
type SecurityPattern struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Count       int64     `json:"count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	UserIDs     []string  `json:"user_ids"`
	IPAddresses []string  `json:"ip_addresses"`
	Actions     []string  `json:"actions"`
	RiskScore   float64   `json:"risk_score"`
}

// AnomalousActivity represents detected anomalies
type AnomalousActivity struct {
	ID          uuid.UUID            `json:"id"`
	Type        string               `json:"type"`
	Description string               `json:"description"`
	UserID      uuid.UUID            `json:"user_id"`
	IPAddress   string               `json:"ip_address"`
	Actions     []string             `json:"actions"`
	Timestamp   time.Time            `json:"timestamp"`
	Severity    models.SecuritySeverity `json:"severity"`
	Confidence  float64              `json:"confidence"`
	Context     map[string]interface{} `json:"context"`
}

// TrendAnalysis provides trend analysis data
type TrendAnalysis struct {
	LoginTrends     []DataPoint `json:"login_trends"`
	ActivityTrends  []DataPoint `json:"activity_trends"`
	SecurityTrends  []DataPoint `json:"security_trends"`
	ErrorTrends     []DataPoint `json:"error_trends"`
	PredictedRisks  []RiskPrediction `json:"predicted_risks"`
}

// DataPoint represents a data point in trend analysis
type DataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Label     string    `json:"label"`
}

// RiskPrediction represents predicted security risks
type RiskPrediction struct {
	Type        string    `json:"type"`
	Risk        float64   `json:"risk"`
	Confidence  float64   `json:"confidence"`
	TimeFrame   string    `json:"time_frame"`
	Description string    `json:"description"`
	Mitigation  []string  `json:"mitigation"`
}

// ComplianceMetrics provides compliance-related metrics
type ComplianceMetrics struct {
	DataRetention   ComplianceCheck `json:"data_retention"`
	AccessLogging   ComplianceCheck `json:"access_logging"`
	FailureLogging  ComplianceCheck `json:"failure_logging"`
	IntegrityChecks ComplianceCheck `json:"integrity_checks"`
	BackupStatus    ComplianceCheck `json:"backup_status"`
	OverallScore    float64         `json:"overall_score"`
	LastAudit       time.Time       `json:"last_audit"`
	NextAudit       time.Time       `json:"next_audit"`
}

// ComplianceCheck represents a compliance check result
type ComplianceCheck struct {
	Status      string    `json:"status"` // compliant, non_compliant, warning
	Score       float64   `json:"score"`
	Description string    `json:"description"`
	LastCheck   time.Time `json:"last_check"`
	Issues      []string  `json:"issues,omitempty"`
}

// NewAuditService creates a new comprehensive audit service
func NewAuditService(secretKey string) *AuditService {
	service := &AuditService{
		db:        database.GetDB(),
		secretKey: []byte(secretKey),
		hashCache: make(map[string]string),
	}
	
	// Initialize the audit chain if it doesn't exist
	service.initializeChain()
	
	return service
}

// ========== BLOCKCHAIN-STYLE AUDIT LOGGING ==========

// LogEvent logs an audit event with blockchain-style hash chaining
func (as *AuditService) LogEvent(userID uuid.UUID, action, resource, resourceID string, success bool, details map[string]interface{}, ipAddress, userAgent string) error {
	// Start transaction for atomic operations
	tx := as.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Create base audit log
	auditLog := &models.AuditLog{
		ID:         uuid.New(),
		UserID:     userID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		Success:    success,
		Details:    details,
		Timestamp:  time.Now(),
	}

	// Create enhanced audit log with blockchain features
	enhancedLog, err := as.createEnhancedLog(auditLog, tx)
	if err != nil {
		tx.Rollback()
		// Fallback to console logging
		as.logToConsole(auditLog, fmt.Sprintf("Lỗi tạo enhanced log: %v", err))
		return fmt.Errorf("không thể tạo log nâng cao: %w", err)
	}

	// Save the enhanced log
	if err := tx.Create(enhancedLog).Error; err != nil {
		tx.Rollback()
		as.logToConsole(auditLog, fmt.Sprintf("Lỗi lưu database: %v", err))
		return fmt.Errorf("không thể lưu audit log: %w", err)
	}

	// Update audit chain
	if err := as.updateAuditChain(enhancedLog, tx); err != nil {
		tx.Rollback()
		as.logToConsole(auditLog, fmt.Sprintf("Lỗi cập nhật chain: %v", err))
		return fmt.Errorf("không thể cập nhật audit chain: %w", err)
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		as.logToConsole(auditLog, fmt.Sprintf("Lỗi commit: %v", err))
		return fmt.Errorf("không thể commit audit log: %w", err)
	}

	// Run background integrity check
	go as.verifyChainIntegrity()

	return nil
}

// LogSecurityEvent logs a security event with enhanced details
func (as *AuditService) LogSecurityEvent(userID *uuid.UUID, eventType models.SecurityEventType, severity models.SecuritySeverity, ipAddress string, details map[string]interface{}) error {
	securityEvent := models.SecurityEvent{
		ID:        uuid.New(),
		Type:      eventType,
		Severity:  severity,
		IPAddress: ipAddress,
		Details: models.SecurityEventDetails{
			AdditionalInfo: details,
		},
		Timestamp: time.Now(),
	}

	if userID != nil {
		securityEvent.UserID = userID
	}

	// Log as audit event
	auditDetails := map[string]interface{}{
		"security_event_type": string(eventType),
		"severity":           string(severity),
		"original_details":   details,
	}

	var logUserID uuid.UUID
	if userID != nil {
		logUserID = *userID
	} else {
		logUserID = uuid.Nil // System event
	}

	return as.LogEvent(logUserID, "security_event", "security", securityEvent.ID.String(), true, auditDetails, ipAddress, "")
}

// GetAuditLogs retrieves audit logs with advanced filtering
func (as *AuditService) GetAuditLogs(filters AuditFilters) ([]EnhancedAuditLog, int64, error) {
	var logs []EnhancedAuditLog
	var total int64

	query := as.db.Model(&EnhancedAuditLog{})

	// Apply filters
	if filters.UserID != uuid.Nil {
		query = query.Where("user_id = ?", filters.UserID)
	}
	if filters.Action != "" {
		query = query.Where("action = ?", filters.Action)
	}
	if filters.Resource != "" {
		query = query.Where("resource = ?", filters.Resource)
	}
	if filters.Success != nil {
		query = query.Where("success = ?", *filters.Success)
	}
	if !filters.StartTime.IsZero() {
		query = query.Where("timestamp >= ?", filters.StartTime)
	}
	if !filters.EndTime.IsZero() {
		query = query.Where("timestamp <= ?", filters.EndTime)
	}
	if filters.IPAddress != "" {
		query = query.Where("ip_address = ?", filters.IPAddress)
	}

	// Get total count
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("không thể đếm audit logs: %w", err)
	}

	// Get logs with pagination
	query = query.Offset(filters.Offset).Limit(filters.Limit).Order("timestamp DESC")
	if err := query.Find(&logs).Error; err != nil {
		return nil, 0, fmt.Errorf("không thể lấy audit logs: %w", err)
	}

	return logs, total, nil
}

// AuditFilters represents filters for audit log queries
type AuditFilters struct {
	UserID      uuid.UUID  `json:"user_id"`
	Action      string     `json:"action"`
	Resource    string     `json:"resource"`
	Success     *bool      `json:"success"`
	StartTime   time.Time  `json:"start_time"`
	EndTime     time.Time  `json:"end_time"`
	IPAddress   string     `json:"ip_address"`
	Limit       int        `json:"limit"`
	Offset      int        `json:"offset"`
}

// GetAuditLog retrieves a specific audit log with integrity verification
func (as *AuditService) GetAuditLog(logID uuid.UUID) (*EnhancedAuditLog, error) {
	var log EnhancedAuditLog
	if err := as.db.Where("id = ?", logID).First(&log).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("không tìm thấy audit log")
		}
		return nil, fmt.Errorf("không thể lấy audit log: %w", err)
	}

	// Verify log integrity
	if !as.verifyLogIntegrity(&log) {
		log.Integrity = false
		// Update integrity status in database
		as.db.Model(&log).Update("integrity", false)
	}

	return &log, nil
}

// VerifyChainIntegrity verifies the entire audit chain integrity
func (as *AuditService) VerifyChainIntegrity() (bool, []string, error) {
	var issues []string
	
	// Get all chain blocks
	var blocks []AuditChainBlock
	if err := as.db.Order("block_number ASC").Find(&blocks).Error; err != nil {
		return false, issues, fmt.Errorf("không thể lấy chain blocks: %w", err)
	}

	// Verify each block
	for i, block := range blocks {
		// Verify hash chain
		if i > 0 {
			expectedPrevHash := blocks[i-1].BlockHash
			if block.PreviousHash != expectedPrevHash {
				issues = append(issues, fmt.Sprintf("Block %d: Hash chain bị hỏng", block.BlockNumber))
				as.db.Model(&block).Update("verified", false)
			}
		}

		// Verify block hash
		calculatedHash := as.calculateBlockHash(&block)
		if block.BlockHash != calculatedHash {
			issues = append(issues, fmt.Sprintf("Block %d: Hash không đúng", block.BlockNumber))
			as.db.Model(&block).Update("verified", false)
		}

		// Verify logs in block
		if err := as.verifyBlockLogs(&block); err != nil {
			issues = append(issues, fmt.Sprintf("Block %d: %v", block.BlockNumber, err))
		}
	}

	return len(issues) == 0, issues, nil
}

// GetAuditMetrics returns comprehensive audit metrics
func (as *AuditService) GetAuditMetrics() (*AuditMetrics, error) {
	metrics := &AuditMetrics{
		LastVerification: time.Now(),
	}

	// Count total logs
	if err := as.db.Model(&EnhancedAuditLog{}).Count(&metrics.TotalLogs).Error; err != nil {
		return nil, fmt.Errorf("không thể đếm tổng logs: %w", err)
	}

	// Count logs today
	today := time.Now().Truncate(24 * time.Hour)
	if err := as.db.Model(&EnhancedAuditLog{}).Where("timestamp >= ?", today).Count(&metrics.LogsToday).Error; err != nil {
		return nil, fmt.Errorf("không thể đếm logs hôm nay: %w", err)
	}

	// Count failed attempts
	if err := as.db.Model(&EnhancedAuditLog{}).Where("success = false").Count(&metrics.FailedAttempts).Error; err != nil {
		return nil, fmt.Errorf("không thể đếm failed attempts: %w", err)
	}

	// Count security events
	if err := as.db.Model(&models.SecurityEvent{}).Count(&metrics.SecurityEvents).Error; err != nil {
		return nil, fmt.Errorf("không thể đếm security events: %w", err)
	}

	// Count tamper attempts (logs with integrity false)
	if err := as.db.Model(&EnhancedAuditLog{}).Where("integrity = false").Count(&metrics.TamperAttempts).Error; err != nil {
		return nil, fmt.Errorf("không thể đếm tamper attempts: %w", err)
	}

	// Check chain integrity
	chainIntegrity, _, err := as.VerifyChainIntegrity()
	if err != nil {
		metrics.ChainIntegrity = false
	} else {
		metrics.ChainIntegrity = chainIntegrity
	}

	// Calculate storage used (approximate)
	metrics.StorageUsed = metrics.TotalLogs * 1024 // Approximate 1KB per log

	return metrics, nil
}

// GetAuditAnalytics provides comprehensive audit analytics
func (as *AuditService) GetAuditAnalytics(startTime, endTime time.Time) (*AuditAnalytics, error) {
	analytics := &AuditAnalytics{
		UserActivity:    make(map[string]int64),
		ActionFrequency: make(map[string]int64),
		ResourceAccess:  make(map[string]int64),
		RiskScores:      make(map[string]float64),
	}

	// Get user activity
	type UserActivityResult struct {
		UserID string `json:"user_id"`
		Count  int64  `json:"count"`
	}
	
	var userActivity []UserActivityResult
	err := as.db.Model(&EnhancedAuditLog{}).
		Select("user_id, count(*) as count").
		Where("timestamp BETWEEN ? AND ?", startTime, endTime).
		Group("user_id").
		Find(&userActivity).Error
	
	if err != nil {
		return nil, fmt.Errorf("không thể lấy user activity: %w", err)
	}

	for _, activity := range userActivity {
		analytics.UserActivity[activity.UserID] = activity.Count
	}

	// Get action frequency
	type ActionFrequencyResult struct {
		Action string `json:"action"`
		Count  int64  `json:"count"`
	}
	
	var actionFreq []ActionFrequencyResult
	err = as.db.Model(&EnhancedAuditLog{}).
		Select("action, count(*) as count").
		Where("timestamp BETWEEN ? AND ?", startTime, endTime).
		Group("action").
		Find(&actionFreq).Error
	
	if err != nil {
		return nil, fmt.Errorf("không thể lấy action frequency: %w", err)
	}

	for _, freq := range actionFreq {
		analytics.ActionFrequency[freq.Action] = freq.Count
	}

	// Detect security patterns
	patterns, err := as.detectSecurityPatterns(startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("không thể phát hiện security patterns: %w", err)
	}
	analytics.SecurityPatterns = patterns

	// Detect anomalous activity
	anomalies, err := as.detectAnomalousActivity(startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("không thể phát hiện anomalous activity: %w", err)
	}
	analytics.AnomalousActivity = anomalies

	// Generate trend analysis
	trends, err := as.generateTrendAnalysis(startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("không thể tạo trend analysis: %w", err)
	}
	analytics.TrendAnalysis = trends

	// Generate compliance metrics
	compliance, err := as.generateComplianceMetrics()
	if err != nil {
		return nil, fmt.Errorf("không thể tạo compliance metrics: %w", err)
	}
	analytics.ComplianceMetrics = compliance

	return analytics, nil
}

// ExportAuditLogs exports audit logs in various formats
func (as *AuditService) ExportAuditLogs(filters AuditFilters, format string) ([]byte, string, error) {
	logs, _, err := as.GetAuditLogs(filters)
	if err != nil {
		return nil, "", fmt.Errorf("không thể lấy audit logs: %w", err)
	}

	switch strings.ToLower(format) {
	case "json":
		data, err := json.MarshalIndent(logs, "", "  ")
		if err != nil {
			return nil, "", fmt.Errorf("không thể marshal JSON: %w", err)
		}
		return data, "application/json", nil
		
	case "csv":
		return as.exportToCSV(logs)
		
	case "xml":
		return as.exportToXML(logs)
		
	default:
		return nil, "", fmt.Errorf("định dạng không được hỗ trợ: %s", format)
	}
}

// ========== PRIVATE HELPER METHODS ==========

// initializeChain initializes the audit chain
func (as *AuditService) initializeChain() {
	// Check if genesis block exists
	var count int64
	as.db.Model(&AuditChainBlock{}).Count(&count)
	
	if count == 0 {
		// Create genesis block
		genesisBlock := &AuditChainBlock{
			BlockNumber:  0,
			PreviousHash: "0000000000000000000000000000000000000000000000000000000000000000",
			Timestamp:    time.Now(),
			LogCount:     0,
			LogsHash:     as.calculateSHA256("genesis"),
			Merkleroot:   as.calculateSHA256("genesis_merkle"),
			Nonce:        0,
			Signature:    as.signData("genesis_block"),
			Verified:     true,
		}
		
		genesisBlock.BlockHash = as.calculateBlockHash(genesisBlock)
		as.db.Create(genesisBlock)
		as.lastHash = genesisBlock.BlockHash
	} else {
		// Load last hash
		var lastBlock AuditChainBlock
		as.db.Order("block_number DESC").First(&lastBlock)
		as.lastHash = lastBlock.BlockHash
	}
}

// createEnhancedLog creates an enhanced audit log with blockchain features
func (as *AuditService) createEnhancedLog(baseLog *models.AuditLog, tx *gorm.DB) (*EnhancedAuditLog, error) {
	// Get chain position
	var chainPos int64
	tx.Model(&EnhancedAuditLog{}).Count(&chainPos)
	
	// Calculate log hash
	logData := fmt.Sprintf("%s|%s|%s|%s|%t|%s|%v", 
		baseLog.UserID.String(), baseLog.Action, baseLog.Resource, 
		baseLog.IPAddress, baseLog.Success, baseLog.Timestamp.Format(time.RFC3339),
		baseLog.Details)
	
	logHash := as.calculateHMAC(logData)
	checksum := as.calculateSHA256(logData)
	
	enhancedLog := &EnhancedAuditLog{
		AuditLog:        *baseLog,
		LogHash:         logHash,
		PreviousLogHash: as.lastHash,
		ChainPosition:   int(chainPos + 1),
		Integrity:       true,
		Encrypted:       false,
		OriginalSize:    len(logData),
		CompressedSize:  len(logData), // No compression for now
		Checksum:        checksum,
		Version:         1,
	}
	
	return enhancedLog, nil
}

// updateAuditChain updates the audit chain with new block
func (as *AuditService) updateAuditChain(log *EnhancedAuditLog, tx *gorm.DB) error {
	// Update last hash
	as.lastHash = log.LogHash
	
	// Check if we need to create a new block (every 100 logs)
	var logCount int64
	tx.Model(&EnhancedAuditLog{}).Where("block_number = 0 OR block_number IS NULL").Count(&logCount)
	
	if logCount >= 100 {
		return as.createNewBlock(tx)
	}
	
	return nil
}

// createNewBlock creates a new audit chain block
func (as *AuditService) createNewBlock(tx *gorm.DB) error {
	// Get current block number
	var lastBlockNumber int64
	tx.Model(&AuditChainBlock{}).Select("COALESCE(MAX(block_number), -1)").Scan(&lastBlockNumber)
	
	newBlockNumber := lastBlockNumber + 1
	
	// Get logs for this block
	var logs []EnhancedAuditLog
	tx.Where("block_number = 0 OR block_number IS NULL").Limit(100).Find(&logs)
	
	// Calculate merkle root
	merkleRoot := as.calculateMerkleRoot(logs)
	
	// Calculate logs hash
	var logHashes []string
	for _, log := range logs {
		logHashes = append(logHashes, log.LogHash)
	}
	logsHash := as.calculateSHA256(strings.Join(logHashes, ""))
	
	// Create new block
	block := &AuditChainBlock{
		BlockNumber:  newBlockNumber,
		PreviousHash: as.lastHash,
		Timestamp:    time.Now(),
		LogCount:     len(logs),
		LogsHash:     logsHash,
		Merkleroot:   merkleRoot,
		Nonce:        as.calculateNonce(),
		Signature:    as.signData(fmt.Sprintf("block_%d", newBlockNumber)),
		Verified:     true,
	}
	
	block.BlockHash = as.calculateBlockHash(block)
	
	// Save block
	if err := tx.Create(block).Error; err != nil {
		return err
	}
	
	// Update logs with block number
	for _, log := range logs {
		tx.Model(&log).Update("block_number", newBlockNumber)
	}
	
	// Update last hash
	as.lastHash = block.BlockHash
	
	return nil
}

// Cryptographic helper methods
func (as *AuditService) calculateSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (as *AuditService) calculateHMAC(data string) string {
	h := hmac.New(sha256.New, as.secretKey)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func (as *AuditService) calculateBlockHash(block *AuditChainBlock) string {
	blockData := fmt.Sprintf("%d|%s|%s|%d|%s|%s|%d",
		block.BlockNumber, block.PreviousHash, block.Timestamp.Format(time.RFC3339),
		block.LogCount, block.LogsHash, block.Merkleroot, block.Nonce)
	return as.calculateSHA256(blockData)
}

func (as *AuditService) calculateMerkleRoot(logs []EnhancedAuditLog) string {
	if len(logs) == 0 {
		return as.calculateSHA256("empty")
	}
	
	var hashes []string
	for _, log := range logs {
		hashes = append(hashes, log.LogHash)
	}
	
	// Simple merkle root calculation
	for len(hashes) > 1 {
		var newHashes []string
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := hashes[i] + hashes[i+1]
				newHashes = append(newHashes, as.calculateSHA256(combined))
			} else {
				newHashes = append(newHashes, hashes[i])
			}
		}
		hashes = newHashes
	}
	
	return hashes[0]
}

func (as *AuditService) calculateNonce() int64 {
	return time.Now().UnixNano()
}

func (as *AuditService) signData(data string) string {
	return as.calculateHMAC(data)
}

func (as *AuditService) verifyLogIntegrity(log *EnhancedAuditLog) bool {
	// Recalculate hash
	logData := fmt.Sprintf("%s|%s|%s|%s|%t|%s|%v", 
		log.UserID.String(), log.Action, log.Resource, 
		log.IPAddress, log.Success, log.Timestamp.Format(time.RFC3339),
		log.Details)
	
	expectedHash := as.calculateHMAC(logData)
	expectedChecksum := as.calculateSHA256(logData)
	
	return log.LogHash == expectedHash && log.Checksum == expectedChecksum
}

func (as *AuditService) verifyChainIntegrity() {
	// Background chain verification
	integrity, issues, err := as.VerifyChainIntegrity()
	if err != nil || !integrity {
		// Log integrity issues
		fmt.Printf("AUDIT CHAIN INTEGRITY ISSUES: %v (Error: %v)\n", issues, err)
	}
}

func (as *AuditService) verifyBlockLogs(block *AuditChainBlock) error {
	// Get logs in this block
	var logs []EnhancedAuditLog
	if err := as.db.Where("block_number = ?", block.BlockNumber).Find(&logs).Error; err != nil {
		return fmt.Errorf("không thể lấy logs trong block: %w", err)
	}
	
	// Verify log count
	if len(logs) != block.LogCount {
		return fmt.Errorf("số lượng logs không khớp: expected %d, got %d", block.LogCount, len(logs))
	}
	
	// Verify merkle root
	calculatedMerkleRoot := as.calculateMerkleRoot(logs)
	if calculatedMerkleRoot != block.Merkleroot {
		return fmt.Errorf("merkle root không khớp")
	}
	
	return nil
}

func (as *AuditService) logToConsole(log *models.AuditLog, error string) {
	fmt.Printf("AUDIT FALLBACK: UserID=%s Action=%s Resource=%s Success=%t Error=%s\n",
		log.UserID, log.Action, log.Resource, log.Success, error)
}

// Analytics helper methods (simplified implementations)
func (as *AuditService) detectSecurityPatterns(startTime, endTime time.Time) ([]SecurityPattern, error) {
	var patterns []SecurityPattern
	
	// Detect repeated failed login attempts
	var failedLogins []struct {
		IPAddress string `json:"ip_address"`
		Count     int64  `json:"count"`
	}
	
	err := as.db.Model(&EnhancedAuditLog{}).
		Select("ip_address, count(*) as count").
		Where("action = ? AND success = false AND timestamp BETWEEN ? AND ?", "login", startTime, endTime).
		Group("ip_address").
		Having("count(*) >= ?", 5).
		Find(&failedLogins).Error
	
	if err == nil {
		for _, login := range failedLogins {
			patterns = append(patterns, SecurityPattern{
				Type:        "repeated_failed_login",
				Description: fmt.Sprintf("Nhiều lần đăng nhập thất bại từ IP %s", login.IPAddress),
				Severity:    "medium",
				Count:       login.Count,
				FirstSeen:   startTime,
				LastSeen:    endTime,
				IPAddresses: []string{login.IPAddress},
				Actions:     []string{"login"},
				RiskScore:   0.7,
			})
		}
	}
	
	return patterns, nil
}

func (as *AuditService) detectAnomalousActivity(startTime, endTime time.Time) ([]AnomalousActivity, error) {
	var anomalies []AnomalousActivity
	
	// Detect unusual activity times
	var nightActivity []struct {
		UserID    string `json:"user_id"`
		IPAddress string `json:"ip_address"`
		Count     int64  `json:"count"`
	}
	
	err := as.db.Model(&EnhancedAuditLog{}).
		Select("user_id, ip_address, count(*) as count").
		Where("EXTRACT(hour FROM timestamp) BETWEEN 0 AND 5 AND timestamp BETWEEN ? AND ?", startTime, endTime).
		Group("user_id, ip_address").
		Having("count(*) >= ?", 10).
		Find(&nightActivity).Error
	
	if err == nil {
		for _, activity := range nightActivity {
			userUUID, _ := uuid.Parse(activity.UserID)
			anomalies = append(anomalies, AnomalousActivity{
				ID:          uuid.New(),
				Type:        "unusual_time_activity",
				Description: "Hoạt động bất thường vào ban đêm",
				UserID:      userUUID,
				IPAddress:   activity.IPAddress,
				Actions:     []string{"various"},
				Timestamp:   time.Now(),
				Severity:    models.SeverityMedium,
				Confidence:  0.8,
				Context:     map[string]interface{}{"count": activity.Count},
			})
		}
	}
	
	return anomalies, nil
}

func (as *AuditService) generateTrendAnalysis(startTime, endTime time.Time) (TrendAnalysis, error) {
	trends := TrendAnalysis{}
	
	// Simple trend analysis - count logs per day
	var dailyActivity []struct {
		Date  string `json:"date"`
		Count int64  `json:"count"`
	}
	
	err := as.db.Model(&EnhancedAuditLog{}).
		Select("DATE(timestamp) as date, count(*) as count").
		Where("timestamp BETWEEN ? AND ?", startTime, endTime).
		Group("DATE(timestamp)").
		Order("date ASC").
		Find(&dailyActivity).Error
	
	if err == nil {
		for _, activity := range dailyActivity {
			date, _ := time.Parse("2006-01-02", activity.Date)
			trends.ActivityTrends = append(trends.ActivityTrends, DataPoint{
				Timestamp: date,
				Value:     float64(activity.Count),
				Label:     "Hoạt động hàng ngày",
			})
		}
	}
	
	return trends, nil
}

func (as *AuditService) generateComplianceMetrics() (ComplianceMetrics, error) {
	metrics := ComplianceMetrics{
		LastAudit: time.Now().AddDate(0, -1, 0), // Last month
		NextAudit: time.Now().AddDate(0, 1, 0),  // Next month
	}
	
	// Data retention compliance
	var oldLogsCount int64
	retentionDate := time.Now().AddDate(0, -12, 0) // 12 months retention
	as.db.Model(&EnhancedAuditLog{}).Where("timestamp < ?", retentionDate).Count(&oldLogsCount)
	
	if oldLogsCount == 0 {
		metrics.DataRetention = ComplianceCheck{
			Status:      "compliant",
			Score:       100.0,
			Description: "Dữ liệu cũ đã được xóa theo chính sách lưu trữ",
			LastCheck:   time.Now(),
		}
	} else {
		metrics.DataRetention = ComplianceCheck{
			Status:      "non_compliant",
			Score:       50.0,
			Description: fmt.Sprintf("%d logs cũ cần được xóa", oldLogsCount),
			LastCheck:   time.Now(),
			Issues:      []string{fmt.Sprintf("%d logs quá hạn lưu trữ", oldLogsCount)},
		}
	}
	
	// Overall compliance score
	metrics.OverallScore = (metrics.DataRetention.Score) / 1.0 // Add more checks later
	
	return metrics, nil
}

// Export helper methods
func (as *AuditService) exportToCSV(logs []EnhancedAuditLog) ([]byte, string, error) {
	var csv strings.Builder
	
	// Header
	csv.WriteString("ID,UserID,Action,Resource,Success,Timestamp,IPAddress,LogHash,Integrity\n")
	
	// Data
	for _, log := range logs {
		csv.WriteString(fmt.Sprintf("%s,%s,%s,%s,%t,%s,%s,%s,%t\n",
			log.ID, log.UserID, log.Action, log.Resource, log.Success,
			log.Timestamp.Format(time.RFC3339), log.IPAddress, log.LogHash, log.Integrity))
	}
	
	return []byte(csv.String()), "text/csv", nil
}

func (as *AuditService) exportToXML(logs []EnhancedAuditLog) ([]byte, string, error) {
	var xml strings.Builder
	
	xml.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	xml.WriteString("<AuditLogs>\n")
	
	for _, log := range logs {
		xml.WriteString(fmt.Sprintf("  <Log id=\"%s\">\n", log.ID))
		xml.WriteString(fmt.Sprintf("    <UserID>%s</UserID>\n", log.UserID))
		xml.WriteString(fmt.Sprintf("    <Action>%s</Action>\n", log.Action))
		xml.WriteString(fmt.Sprintf("    <Resource>%s</Resource>\n", log.Resource))
		xml.WriteString(fmt.Sprintf("    <Success>%t</Success>\n", log.Success))
		xml.WriteString(fmt.Sprintf("    <Timestamp>%s</Timestamp>\n", log.Timestamp.Format(time.RFC3339)))
		xml.WriteString(fmt.Sprintf("    <IPAddress>%s</IPAddress>\n", log.IPAddress))
		xml.WriteString(fmt.Sprintf("    <LogHash>%s</LogHash>\n", log.LogHash))
		xml.WriteString(fmt.Sprintf("    <Integrity>%t</Integrity>\n", log.Integrity))
		xml.WriteString("  </Log>\n")
	}
	
	xml.WriteString("</AuditLogs>")
	
	return []byte(xml.String()), "application/xml", nil
}
