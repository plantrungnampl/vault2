package services

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"securevault/internal/config"
	"securevault/internal/models"
	"securevault/internal/security"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// BackupService handles automated backups and disaster recovery
type BackupService struct {
	db              *gorm.DB
	cryptoService   *security.CryptoService
	config          *BackupConfig
	storageProvider StorageProvider
	auditService    *AuditService
	encryptionKey   []byte
	backupHistory   []*BackupRecord
	mutex           sync.RWMutex
	isRunning       bool
	stopChannel     chan struct{}
}

// BackupConfig holds backup configuration
type BackupConfig struct {
	EnableAutoBackup      bool          `json:"enable_auto_backup"`
	BackupInterval        time.Duration `json:"backup_interval"`
	RetentionDays         int           `json:"retention_days"`
	MaxBackupSize         int64         `json:"max_backup_size_mb"`
	CompressionLevel      int           `json:"compression_level"`
	EncryptBackups        bool          `json:"encrypt_backups"`
	VerifyBackupIntegrity bool          `json:"verify_backup_integrity"`
	StorageType           string        `json:"storage_type"`
	BackupPath            string        `json:"backup_path"`
	NotifyOnSuccess       bool          `json:"notify_on_success"`
	NotifyOnFailure       bool          `json:"notify_on_failure"`
	MaxConcurrentBackups  int           `json:"max_concurrent_backups"`
}

// BackupRecord represents a backup entry
type BackupRecord struct {
	ID              string    `json:"id" gorm:"primaryKey"`
	Type            string    `json:"type"`
	Status          string    `json:"status"`
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
	Duration        time.Duration `json:"duration"`
	BackupSize      int64     `json:"backup_size"`
	CompressedSize  int64     `json:"compressed_size"`
	RecordCount     int       `json:"record_count"`
	FilePath        string    `json:"file_path"`
	StorageLocation string    `json:"storage_location"`
	Checksum        string    `json:"checksum"`
	CreatedBy       string    `json:"created_by"`
	ErrorMessage    string    `json:"error_message,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	VerifiedAt      time.Time `json:"verified_at,omitempty"`
	RestoredAt      time.Time `json:"restored_at,omitempty"`
}

// BackupData represents the structure of a complete backup
type BackupData struct {
	Version     string                 `json:"version"`
	BackupType  string                 `json:"backup_type"`
	Timestamp   time.Time              `json:"timestamp"`
	Tables      map[string]interface{} `json:"tables"`
	Metadata    BackupMetadata         `json:"metadata"`
	Checksums   map[string]string      `json:"checksums"`
}

// BackupMetadata contains backup metadata
type BackupMetadata struct {
	ServerVersion  string `json:"server_version"`
	DatabaseSchema string `json:"database_schema"`
	TotalRecords   int    `json:"total_records"`
	BackupSize     int64  `json:"backup_size"`
	Compression    string `json:"compression"`
	Encryption     string `json:"encryption"`
	Environment    string `json:"environment"`
}

// RestoreRequest represents a restoration request
type RestoreRequest struct {
	BackupID      string   `json:"backup_id"`
	RestoreType   string   `json:"restore_type"`
	TargetTables  []string `json:"target_tables,omitempty"`
	PreserveData  bool     `json:"preserve_data"`
	VerifyRestore bool     `json:"verify_restore"`
}

// RestoreResult represents the result of a restoration
type RestoreResult struct {
	Success         bool          `json:"success"`
	RecordsRestored int           `json:"records_restored"`
	TablesRestored  []string      `json:"tables_restored"`
	Duration        time.Duration `json:"duration"`
	ErrorMessage    string        `json:"error_message,omitempty"`
}

// VerificationResult represents backup verification results
type VerificationResult struct {
	Success          bool          `json:"success"`
	ChecksumValid    bool          `json:"checksum_valid"`
	IntegrityValid   bool          `json:"integrity_valid"`
	RecordCount      int           `json:"record_count"`
	CorruptedTables  []string      `json:"corrupted_tables,omitempty"`
	MissingRecords   []string      `json:"missing_records,omitempty"`
	ErrorDetails     string        `json:"error_details,omitempty"`
	VerificationTime time.Duration `json:"verification_time"`
}

// StorageProvider interface for different storage backends
type StorageProvider interface {
	Store(filename string, data []byte) (string, error)
	Retrieve(location string) ([]byte, error)
	Delete(location string) error
	List(prefix string) ([]string, error)
	GetInfo(location string) (*StorageInfo, error)
}

// StorageInfo represents storage metadata
type StorageInfo struct {
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
	ContentType  string    `json:"content_type"`
}

// LocalStorageProvider implements local filesystem storage
type LocalStorageProvider struct {
	basePath string
}

// NewBackupService creates a new backup service
func NewBackupService(db *gorm.DB, cryptoService *security.CryptoService, auditService *AuditService, config *config.Config) *BackupService {
	// Auto-migrate backup records table
	db.AutoMigrate(&BackupRecord{})

	backupConfig := &BackupConfig{
		EnableAutoBackup:      true,
		BackupInterval:        24 * time.Hour,
		RetentionDays:         30,
		MaxBackupSize:         1024,
		CompressionLevel:      6,
		EncryptBackups:        true,
		VerifyBackupIntegrity: true,
		StorageType:           "local",
		BackupPath:            "./backups",
		NotifyOnSuccess:       false,
		NotifyOnFailure:       true,
		MaxConcurrentBackups:  2,
	}

	// Create storage provider
	os.MkdirAll(backupConfig.BackupPath, 0755)
	storageProvider := &LocalStorageProvider{basePath: backupConfig.BackupPath}

	service := &BackupService{
		db:              db,
		cryptoService:   cryptoService,
		config:          backupConfig,
		storageProvider: storageProvider,
		auditService:    auditService,
		backupHistory:   make([]*BackupRecord, 0),
		stopChannel:     make(chan struct{}),
	}

	// Start backup scheduler if auto-backup is enabled
	if backupConfig.EnableAutoBackup {
		go service.startScheduler()
	}

	return service
}

// CreateBackup creates a new backup
func (bs *BackupService) CreateBackup(backupType string, createdBy string) (*BackupRecord, error) {
	bs.mutex.Lock()
	defer bs.mutex.Unlock()

	// Create backup record
	backupRecord := &BackupRecord{
		ID:        uuid.New().String(),
		Type:      backupType,
		Status:    "running",
		StartTime: time.Now(),
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
	}

	// Store record in database
	if err := bs.db.Create(backupRecord).Error; err != nil {
		return nil, fmt.Errorf("failed to create backup record: %w", err)
	}

	// Perform backup in background
	go bs.performBackup(backupRecord)

	return backupRecord, nil
}

// performBackup performs the actual backup operation
func (bs *BackupService) performBackup(record *BackupRecord) {
	defer func() {
		if r := recover(); r != nil {
			bs.handleBackupError(record, fmt.Errorf("backup panic: %v", r))
		}
	}()

	// Log backup start
	bs.auditService.LogEvent(
		uuid.Nil,
		"backup_started",
		"backup",
		record.ID,
		true,
		map[string]interface{}{
			"backup_type": record.Type,
			"backup_id":   record.ID,
		},
		"",
		"system",
	)

	// Collect data for backup
	backupData, err := bs.collectBackupData(record.Type)
	if err != nil {
		bs.handleBackupError(record, fmt.Errorf("failed to collect backup data: %w", err))
		return
	}

	// Serialize backup data
	jsonData, err := json.Marshal(backupData)
	if err != nil {
		bs.handleBackupError(record, fmt.Errorf("failed to serialize backup data: %w", err))
		return
	}

	// Compress data
	compressedData, err := bs.compressData(jsonData)
	if err != nil {
		bs.handleBackupError(record, fmt.Errorf("failed to compress backup data: %w", err))
		return
	}

	// Encrypt data if enabled
	var finalData []byte
	if bs.config.EncryptBackups {
		encryptedData, err := bs.encryptBackupData(compressedData, record.ID)
		if err != nil {
			bs.handleBackupError(record, fmt.Errorf("failed to encrypt backup data: %w", err))
			return
		}
		finalData = encryptedData
	} else {
		finalData = compressedData
	}

	// Generate filename
	filename := bs.generateBackupFilename(record)
	
	// Store backup
	storageLocation, err := bs.storageProvider.Store(filename, finalData)
	if err != nil {
		bs.handleBackupError(record, fmt.Errorf("failed to store backup: %w", err))
		return
	}

	// Generate checksum
	checksum := bs.generateChecksum(finalData)

	// Update backup record
	record.EndTime = time.Now()
	record.Duration = record.EndTime.Sub(record.StartTime)
	record.Status = "completed"
	record.BackupSize = int64(len(jsonData))
	record.CompressedSize = int64(len(finalData))
	record.RecordCount = backupData.Metadata.TotalRecords
	record.FilePath = filename
	record.StorageLocation = storageLocation
	record.Checksum = checksum

	// Save updated record
	if err := bs.db.Save(record).Error; err != nil {
		bs.auditService.LogEvent(
			uuid.Nil,
			"backup_record_update_failed",
			"backup",
			record.ID,
			false,
			map[string]interface{}{
				"error": err.Error(),
			},
			"",
			"system",
		)
	}

	// Add to history
	bs.backupHistory = append(bs.backupHistory, record)

	// Log successful backup
	bs.auditService.LogEvent(
		uuid.Nil,
		"backup_completed",
		"backup",
		record.ID,
		true,
		map[string]interface{}{
			"backup_type":     record.Type,
			"backup_size":     record.BackupSize,
			"compressed_size": record.CompressedSize,
			"record_count":    record.RecordCount,
			"duration":        record.Duration.String(),
		},
		"",
		"system",
	)

	// Clean up old backups
	go bs.cleanupOldBackups()
}

// collectBackupData collects data for backup based on type
func (bs *BackupService) collectBackupData(backupType string) (*BackupData, error) {
	backupData := &BackupData{
		Version:   "1.0.0",
		BackupType: backupType,
		Timestamp: time.Now(),
		Tables:    make(map[string]interface{}),
		Checksums: make(map[string]string),
		Metadata: BackupMetadata{
			ServerVersion:  "SecureVault-1.0.0",
			DatabaseSchema: "securevault",
			Environment:    "production",
		},
	}

	totalRecords := 0

	// Backup users table
	var users []models.User
	if err := bs.db.Find(&users).Error; err != nil {
		return nil, fmt.Errorf("failed to backup users: %w", err)
	}
	backupData.Tables["users"] = users
	totalRecords += len(users)

	// Backup vault items table
	var vaultItems []models.VaultItem
	if err := bs.db.Find(&vaultItems).Error; err != nil {
		return nil, fmt.Errorf("failed to backup vault items: %w", err)
	}
	backupData.Tables["vault_items"] = vaultItems
	totalRecords += len(vaultItems)

	// Backup audit logs table
	var auditLogs []models.AuditLog
	if err := bs.db.Find(&auditLogs).Error; err != nil {
		return nil, fmt.Errorf("failed to backup audit logs: %w", err)
	}
	backupData.Tables["audit_logs"] = auditLogs
	totalRecords += len(auditLogs)

	// Backup sessions table
	var sessions []models.Session
	if err := bs.db.Find(&sessions).Error; err != nil {
		return nil, fmt.Errorf("failed to backup sessions: %w", err)
	}
	backupData.Tables["sessions"] = sessions
	totalRecords += len(sessions)

	// Backup WebAuthn credentials if table exists
	var webauthnCreds []WebAuthnCredential
	if bs.db.Migrator().HasTable(&WebAuthnCredential{}) {
		if err := bs.db.Find(&webauthnCreds).Error; err != nil {
			return nil, fmt.Errorf("failed to backup webauthn credentials: %w", err)
		}
		backupData.Tables["webauthn_credentials"] = webauthnCreds
		totalRecords += len(webauthnCreds)
	}

	// Backup biometric templates if table exists
	var biometricTemplates []BiometricTemplate
	if bs.db.Migrator().HasTable(&BiometricTemplate{}) {
		if err := bs.db.Find(&biometricTemplates).Error; err != nil {
			return nil, fmt.Errorf("failed to backup biometric templates: %w", err)
		}
		backupData.Tables["biometric_templates"] = biometricTemplates
		totalRecords += len(biometricTemplates)
	}

	// Backup backup records
	var backupRecords []BackupRecord
	if err := bs.db.Find(&backupRecords).Error; err != nil {
		return nil, fmt.Errorf("failed to backup backup records: %w", err)
	}
	backupData.Tables["backup_records"] = backupRecords
	totalRecords += len(backupRecords)

	backupData.Metadata.TotalRecords = totalRecords

	// Generate checksums for each table
	for tableName, tableData := range backupData.Tables {
		tableJSON, _ := json.Marshal(tableData)
		hash := sha256.Sum256(tableJSON)
		backupData.Checksums[tableName] = hex.EncodeToString(hash[:])
	}

	return backupData, nil
}

// RestoreBackup restores data from a backup
func (bs *BackupService) RestoreBackup(request *RestoreRequest) (*RestoreResult, error) {
	bs.mutex.Lock()
	defer bs.mutex.Unlock()

	startTime := time.Now()

	// Get backup record
	var backupRecord BackupRecord
	if err := bs.db.Where("id = ?", request.BackupID).First(&backupRecord).Error; err != nil {
		return nil, fmt.Errorf("backup not found: %w", err)
	}

	// Log restore start
	bs.auditService.LogEvent(
		uuid.Nil,
		"restore_started",
		"backup",
		request.BackupID,
		true,
		map[string]interface{}{
			"restore_type":   request.RestoreType,
			"backup_id":      request.BackupID,
			"target_tables":  request.TargetTables,
			"preserve_data":  request.PreserveData,
		},
		"",
		"system",
	)

	// Retrieve backup data
	rawData, err := bs.storageProvider.Retrieve(backupRecord.StorageLocation)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve backup data: %w", err)
	}

	// Verify checksum
	if bs.generateChecksum(rawData) != backupRecord.Checksum {
		return nil, fmt.Errorf("backup checksum verification failed")
	}

	// Decrypt data if encrypted
	var processedData []byte
	if bs.config.EncryptBackups {
		decryptedData, err := bs.decryptBackupData(rawData, backupRecord.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt backup data: %w", err)
		}
		processedData = decryptedData
	} else {
		processedData = rawData
	}

	// Decompress data
	decompressedData, err := bs.decompressData(processedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress backup data: %w", err)
	}

	// Parse backup data
	var backupData BackupData
	if err := json.Unmarshal(decompressedData, &backupData); err != nil {
		return nil, fmt.Errorf("failed to parse backup data: %w", err)
	}

	// Perform restoration
	result := &RestoreResult{
		TablesRestored: make([]string, 0),
	}

	// Begin transaction
	tx := bs.db.Begin()
	defer func() {
		if result.Success {
			tx.Commit()
		} else {
			tx.Rollback()
		}
	}()

	recordsRestored := 0

	// Restore each table
	for tableName, tableData := range backupData.Tables {
		// Skip if selective restore and table not in target list
		if request.RestoreType == "selective" && !bs.contains(request.TargetTables, tableName) {
			continue
		}

		// Clear existing data if not preserving
		if !request.PreserveData {
			if err := bs.clearTable(tx, tableName); err != nil {
				result.ErrorMessage = fmt.Sprintf("failed to clear table %s: %v", tableName, err)
				return result, err
			}
		}

		// Restore table data
		tableRecords, err := bs.restoreTable(tx, tableName, tableData)
		if err != nil {
			result.ErrorMessage = fmt.Sprintf("failed to restore table %s: %v", tableName, err)
			return result, err
		}

		recordsRestored += tableRecords
		result.TablesRestored = append(result.TablesRestored, tableName)
	}

	result.Success = true
	result.RecordsRestored = recordsRestored
	result.Duration = time.Since(startTime)

	// Update backup record
	if result.Success {
		backupRecord.RestoredAt = time.Now()
		bs.db.Save(&backupRecord)
	}

	// Log restore completion
	bs.auditService.LogEvent(
		uuid.Nil,
		"restore_completed",
		"backup",
		request.BackupID,
		result.Success,
		map[string]interface{}{
			"success":           result.Success,
			"records_restored":  result.RecordsRestored,
			"tables_restored":   result.TablesRestored,
			"duration":          result.Duration.String(),
			"error":             result.ErrorMessage,
		},
		"",
		"system",
	)

	return result, nil
}

// Helper methods

func (bs *BackupService) handleBackupError(record *BackupRecord, err error) {
	record.Status = "failed"
	record.EndTime = time.Now()
	record.Duration = record.EndTime.Sub(record.StartTime)
	record.ErrorMessage = err.Error()

	bs.db.Save(record)

	// Log error
	bs.auditService.LogEvent(
		uuid.Nil,
		"backup_failed",
		"backup",
		record.ID,
		false,
		map[string]interface{}{
			"backup_id": record.ID,
			"error":     err.Error(),
		},
		"",
		"system",
	)
}

func (bs *BackupService) compressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	
	gw, err := gzip.NewWriterLevel(&buf, bs.config.CompressionLevel)
	if err != nil {
		return nil, err
	}
	
	if _, err := gw.Write(data); err != nil {
		return nil, err
	}
	
	if err := gw.Close(); err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}

func (bs *BackupService) decompressData(data []byte) ([]byte, error) {
	buf := bytes.NewReader(data)
	gr, err := gzip.NewReader(buf)
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	
	return io.ReadAll(gr)
}

func (bs *BackupService) encryptBackupData(data []byte, keyID string) ([]byte, error) {
	// Use crypto service to encrypt backup data
	encryptedData, err := bs.cryptoService.Encrypt(data, "backup-"+keyID)
	if err != nil {
		return nil, err
	}

	// Serialize encrypted data structure
	return json.Marshal(encryptedData)
}

func (bs *BackupService) decryptBackupData(data []byte, keyID string) ([]byte, error) {
	// Parse encrypted data structure
	var encryptedData security.EncryptedData
	if err := json.Unmarshal(data, &encryptedData); err != nil {
		return nil, err
	}

	// Decrypt using crypto service
	return bs.cryptoService.Decrypt(&encryptedData)
}

func (bs *BackupService) generateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (bs *BackupService) generateBackupFilename(record *BackupRecord) string {
	timestamp := record.StartTime.Format("20060102-150405")
	return fmt.Sprintf("backup_%s_%s_%s.dat", record.Type, timestamp, record.ID[:8])
}

func (bs *BackupService) startScheduler() {
	bs.isRunning = true
	ticker := time.NewTicker(1 * time.Hour) // Check every hour
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bs.checkScheduledBackups()
		case <-bs.stopChannel:
			bs.isRunning = false
			return
		}
	}
}

func (bs *BackupService) checkScheduledBackups() {
	if !bs.config.EnableAutoBackup {
		return
	}

	// Check if it's time for a scheduled backup
	var lastBackup BackupRecord
	if err := bs.db.Where("status = 'completed'").Order("created_at DESC").First(&lastBackup).Error; err == nil {
		if time.Since(lastBackup.CreatedAt) >= bs.config.BackupInterval {
			bs.CreateBackup("full", "scheduler")
		}
	} else {
		// No previous backup, create one
		bs.CreateBackup("full", "scheduler")
	}
}

func (bs *BackupService) cleanupOldBackups() {
	cutoffDate := time.Now().AddDate(0, 0, -bs.config.RetentionDays)
	
	var oldBackups []BackupRecord
	if err := bs.db.Where("created_at < ?", cutoffDate).Find(&oldBackups).Error; err != nil {
		return
	}

	for _, backup := range oldBackups {
		if err := bs.DeleteBackup(backup.ID); err != nil {
			// Log error but continue with other deletions
			bs.auditService.LogEvent(
				uuid.Nil,
				"backup_cleanup_failed",
				"backup",
				backup.ID,
				false,
				map[string]interface{}{
					"error": err.Error(),
				},
				"",
				"system",
			)
		}
	}
}

func (bs *BackupService) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (bs *BackupService) clearTable(tx *gorm.DB, tableName string) error {
	// Clear table data based on table name
	switch tableName {
	case "users":
		return tx.Where("1 = 1").Delete(&models.User{}).Error
	case "vault_items":
		return tx.Where("1 = 1").Delete(&models.VaultItem{}).Error
	case "audit_logs":
		return tx.Where("1 = 1").Delete(&models.AuditLog{}).Error
	case "sessions":
		return tx.Where("1 = 1").Delete(&models.Session{}).Error
	case "webauthn_credentials":
		return tx.Where("1 = 1").Delete(&WebAuthnCredential{}).Error
	case "biometric_templates":
		return tx.Where("1 = 1").Delete(&BiometricTemplate{}).Error
	case "backup_records":
		return tx.Where("1 = 1").Delete(&BackupRecord{}).Error
	default:
		return fmt.Errorf("unknown table: %s", tableName)
	}
}

func (bs *BackupService) restoreTable(tx *gorm.DB, tableName string, tableData interface{}) (int, error) {
	// Convert table data to JSON and back to appropriate struct
	jsonData, err := json.Marshal(tableData)
	if err != nil {
		return 0, err
	}

	recordCount := 0

	switch tableName {
	case "users":
		var users []models.User
		if err := json.Unmarshal(jsonData, &users); err != nil {
			return 0, err
		}
		for _, user := range users {
			if err := tx.Create(&user).Error; err != nil {
				return recordCount, err
			}
			recordCount++
		}
	case "vault_items":
		var items []models.VaultItem
		if err := json.Unmarshal(jsonData, &items); err != nil {
			return 0, err
		}
		for _, item := range items {
			if err := tx.Create(&item).Error; err != nil {
				return recordCount, err
			}
			recordCount++
		}
	case "audit_logs":
		var logs []models.AuditLog
		if err := json.Unmarshal(jsonData, &logs); err != nil {
			return 0, err
		}
		for _, log := range logs {
			if err := tx.Create(&log).Error; err != nil {
				return recordCount, err
			}
			recordCount++
		}
	case "sessions":
		var sessions []models.Session
		if err := json.Unmarshal(jsonData, &sessions); err != nil {
			return 0, err
		}
		for _, session := range sessions {
			if err := tx.Create(&session).Error; err != nil {
				return recordCount, err
			}
			recordCount++
		}
	case "webauthn_credentials":
		var creds []WebAuthnCredential
		if err := json.Unmarshal(jsonData, &creds); err != nil {
			return 0, err
		}
		for _, cred := range creds {
			if err := tx.Create(&cred).Error; err != nil {
				return recordCount, err
			}
			recordCount++
		}
	case "biometric_templates":
		var templates []BiometricTemplate
		if err := json.Unmarshal(jsonData, &templates); err != nil {
			return 0, err
		}
		for _, template := range templates {
			if err := tx.Create(&template).Error; err != nil {
				return recordCount, err
			}
			recordCount++
		}
	case "backup_records":
		var records []BackupRecord
		if err := json.Unmarshal(jsonData, &records); err != nil {
			return 0, err
		}
		for _, record := range records {
			if err := tx.Create(&record).Error; err != nil {
				return recordCount, err
			}
			recordCount++
		}
	default:
		return 0, fmt.Errorf("unknown table: %s", tableName)
	}

	return recordCount, nil
}

// GetBackupHistory returns backup history
func (bs *BackupService) GetBackupHistory(limit int) ([]*BackupRecord, error) {
	var records []*BackupRecord
	query := bs.db.Order("created_at DESC")
	
	if limit > 0 {
		query = query.Limit(limit)
	}
	
	if err := query.Find(&records).Error; err != nil {
		return nil, fmt.Errorf("failed to get backup history: %w", err)
	}

	return records, nil
}

// DeleteBackup deletes a backup
func (bs *BackupService) DeleteBackup(backupID string) error {
	var record BackupRecord
	if err := bs.db.Where("id = ?", backupID).First(&record).Error; err != nil {
		return fmt.Errorf("backup not found: %w", err)
	}

	// Delete from storage
	if err := bs.storageProvider.Delete(record.StorageLocation); err != nil {
		return fmt.Errorf("failed to delete backup from storage: %w", err)
	}

	// Delete record from database
	if err := bs.db.Delete(&record).Error; err != nil {
		return fmt.Errorf("failed to delete backup record: %w", err)
	}

	// Log deletion
	bs.auditService.LogEvent(
		uuid.Nil,
		"backup_deleted",
		"backup",
		backupID,
		true,
		map[string]interface{}{
			"backup_id":   backupID,
			"backup_type": record.Type,
		},
		"",
		"system",
	)

	return nil
}

// LocalStorageProvider methods

func (lsp *LocalStorageProvider) Store(filename string, data []byte) (string, error) {
	filepath := filepath.Join(lsp.basePath, filename)
	
	if err := os.WriteFile(filepath, data, 0644); err != nil {
		return "", err
	}
	
	return filepath, nil
}

func (lsp *LocalStorageProvider) Retrieve(location string) ([]byte, error) {
	return os.ReadFile(location)
}

func (lsp *LocalStorageProvider) Delete(location string) error {
	return os.Remove(location)
}

func (lsp *LocalStorageProvider) List(prefix string) ([]string, error) {
	files := make([]string, 0)
	
	err := filepath.Walk(lsp.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && (prefix == "" || strings.HasPrefix(filepath.Base(path), prefix)) {
			files = append(files, path)
		}
		
		return nil
	})
	
	return files, err
}

func (lsp *LocalStorageProvider) GetInfo(location string) (*StorageInfo, error) {
	info, err := os.Stat(location)
	if err != nil {
		return nil, err
	}
	
	return &StorageInfo{
		Size:         info.Size(),
		LastModified: info.ModTime(),
		ContentType:  "application/octet-stream",
	}, nil
}

// Stop stops the backup service
func (bs *BackupService) Stop() {
	if bs.isRunning {
		close(bs.stopChannel)
	}
}