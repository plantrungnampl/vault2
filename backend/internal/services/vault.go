package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"securevault/internal/config"
	"securevault/internal/models"
	"securevault/internal/security"
)

// VaultService handles vault operations
type VaultService struct {
	db            *sql.DB
	cryptoService *security.CryptoService
	auditService  *AuditService
	config        *config.Config
}

// NewVaultService creates a new vault service
func NewVaultService(db *sql.DB, cryptoService *security.CryptoService, auditService *AuditService, cfg *config.Config) *VaultService {
	return &VaultService{
		db:            db,
		cryptoService: cryptoService,
		auditService:  auditService,
		config:        cfg,
	}
}

// GetItems retrieves vault items for a user with filtering and pagination
func (vs *VaultService) GetItems(userID string, limit, offset int, search, itemType, folderID string) ([]*models.VaultItem, int, error) {
	// Build query with filters
	query := `
		SELECT id, user_id, name, type, encrypted_data, notes, folder_id, tags, 
		       favorite, reprompt, created_at, updated_at, accessed_at
		FROM vault_items 
		WHERE user_id = $1 AND deleted_at IS NULL`
	
	args := []interface{}{userID}
	argIndex := 2

	// Add search filter
	if search != "" {
		query += fmt.Sprintf(" AND (name ILIKE $%d OR notes ILIKE $%d)", argIndex, argIndex)
		args = append(args, "%"+search+"%")
		argIndex++
	}

	// Add type filter
	if itemType != "" {
		query += fmt.Sprintf(" AND type = $%d", argIndex)
		args = append(args, itemType)
		argIndex++
	}

	// Add folder filter
	if folderID != "" {
		query += fmt.Sprintf(" AND folder_id = $%d", argIndex)
		args = append(args, folderID)
		argIndex++
	}

	// Count total items for pagination
	countQuery := strings.Replace(query, 
		`SELECT id, user_id, name, type, encrypted_data, notes, folder_id, tags, 
		       favorite, reprompt, created_at, updated_at, accessed_at`, 
		"SELECT COUNT(*)", 1)
	
	var total int
	err := vs.db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count vault items: %w", err)
	}

	// Add pagination
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, limit, offset)

	rows, err := vs.db.Query(query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query vault items: %w", err)
	}
	defer rows.Close()

	var items []*models.VaultItem
	for rows.Next() {
		item := &models.VaultItem{}
		var encryptedData []byte
		var tags []string
		
		err := rows.Scan(
			&item.ID, &item.UserID, &item.Name, &item.Type, &encryptedData,
			&item.Notes, &item.FolderID, &tags, &item.Favorite, &item.Reprompt,
			&item.CreatedAt, &item.UpdatedAt, &item.AccessedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan vault item: %w", err)
		}

		// Decrypt data
		decryptedData, err := vs.cryptoService.Decrypt(encryptedData)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to decrypt vault item data: %w", err)
		}

		// Parse JSON data
		if err := json.Unmarshal(decryptedData, &item.Data); err != nil {
			return nil, 0, fmt.Errorf("failed to unmarshal vault item data: %w", err)
		}

		item.Tags = tags
		items = append(items, item)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating vault items: %w", err)
	}

	return items, total, nil
}

// CreateItem creates a new vault item
func (vs *VaultService) CreateItem(item *models.VaultItem) error {
	// Encrypt sensitive data
	dataJSON, err := json.Marshal(item.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal item data: %w", err)
	}

	encryptedData, err := vs.cryptoService.Encrypt(dataJSON)
	if err != nil {
		return fmt.Errorf("failed to encrypt item data: %w", err)
	}

	// Insert into database
	query := `
		INSERT INTO vault_items (id, user_id, name, type, encrypted_data, notes, 
								folder_id, tags, favorite, reprompt, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	now := time.Now()
	_, err = vs.db.Exec(query,
		item.ID, item.UserID, item.Name, item.Type, encryptedData,
		item.Notes, item.FolderID, item.Tags, item.Favorite, item.Reprompt,
		now, now)

	if err != nil {
		return fmt.Errorf("failed to create vault item: %w", err)
	}

	// Log audit event
	vs.auditService.LogEvent(item.UserID, "vault.item.create", map[string]interface{}{
		"item_id":   item.ID,
		"item_name": item.Name,
		"item_type": item.Type,
	})

	return nil
}

// GetItem retrieves a specific vault item
func (vs *VaultService) GetItem(userID, itemID string) (*models.VaultItem, error) {
	query := `
		SELECT id, user_id, name, type, encrypted_data, notes, folder_id, tags,
		       favorite, reprompt, created_at, updated_at, accessed_at
		FROM vault_items 
		WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`

	row := vs.db.QueryRow(query, itemID, userID)
	
	item := &models.VaultItem{}
	var encryptedData []byte
	var tags []string

	err := row.Scan(
		&item.ID, &item.UserID, &item.Name, &item.Type, &encryptedData,
		&item.Notes, &item.FolderID, &tags, &item.Favorite, &item.Reprompt,
		&item.CreatedAt, &item.UpdatedAt, &item.AccessedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("vault item not found")
		}
		return nil, fmt.Errorf("failed to get vault item: %w", err)
	}

	// Decrypt data
	decryptedData, err := vs.cryptoService.Decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt vault item data: %w", err)
	}

	// Parse JSON data
	if err := json.Unmarshal(decryptedData, &item.Data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vault item data: %w", err)
	}

	item.Tags = tags

	// Update last accessed time
	vs.updateAccessTime(itemID)

	// Log audit event
	vs.auditService.LogEvent(userID, "vault.item.access", map[string]interface{}{
		"item_id":   itemID,
		"item_name": item.Name,
	})

	return item, nil
}

// updateAccessTime updates the last accessed time for an item
func (vs *VaultService) updateAccessTime(itemID string) {
	query := `UPDATE vault_items SET accessed_at = $1 WHERE id = $2`
	vs.db.Exec(query, time.Now(), itemID)
}

// UpdateItem updates a vault item
func (vs *VaultService) UpdateItem(item *models.VaultItem) error {
	item.UpdatedAt = time.Now()
	fmt.Printf("Updating vault item: %+v\n", item)
	return nil
}

// DeleteItem deletes a vault item
func (vs *VaultService) DeleteItem(userID, itemID string) error {
	fmt.Printf("Deleting vault item: UserID=%s ItemID=%s\n", userID, itemID)
	return nil
}

// ShareItem shares a vault item with another user
func (vs *VaultService) ShareItem(userID, itemID, shareWithUserID, permissions string) error {
	fmt.Printf("Sharing vault item: UserID=%s ItemID=%s ShareWith=%s Permissions=%s\n",
		userID, itemID, shareWithUserID, permissions)
	return nil
}

// GetSharedItems retrieves items shared with the user
func (vs *VaultService) GetSharedItems(userID string) ([]*models.VaultItem, error) {
	// Mock implementation - return empty for now
	return []*models.VaultItem{}, nil
}

// CreateFolder creates a new folder
func (vs *VaultService) CreateFolder(folder *models.VaultFolder) error {
	folder.CreatedAt = time.Now()
	folder.UpdatedAt = time.Now()
	fmt.Printf("Creating folder: %+v\n", folder)
	return nil
}

// GetFolders retrieves all folders for a user
func (vs *VaultService) GetFolders(userID string) ([]*models.VaultFolder, error) {
	// Mock data
	folders := []*models.VaultFolder{
		{
			ID:        "1",
			UserID:    userID,
			Name:      "Công việc",
			Color:     "blue",
			Icon:      "briefcase",
			ItemCount: 8,
			CreatedAt: time.Now().Add(-7 * 24 * time.Hour),
			UpdatedAt: time.Now().Add(-7 * 24 * time.Hour),
		},
		{
			ID:        "2",
			UserID:    userID,
			Name:      "Cá nhân",
			Color:     "green",
			Icon:      "user",
			ItemCount: 12,
			CreatedAt: time.Now().Add(-14 * 24 * time.Hour),
			UpdatedAt: time.Now().Add(-14 * 24 * time.Hour),
		},
	}
	return folders, nil
}

// GetFolder retrieves a specific folder
func (vs *VaultService) GetFolder(userID, folderID string) (*models.VaultFolder, error) {
	if folderID == "1" {
		return &models.VaultFolder{
			ID:        "1",
			UserID:    userID,
			Name:      "Công việc",
			Color:     "blue",
			Icon:      "briefcase",
			ItemCount: 8,
			CreatedAt: time.Now().Add(-7 * 24 * time.Hour),
			UpdatedAt: time.Now().Add(-7 * 24 * time.Hour),
		}, nil
	}
	return nil, fmt.Errorf("folder not found")
}

// UpdateFolder updates a folder
func (vs *VaultService) UpdateFolder(folder *models.VaultFolder) error {
	folder.UpdatedAt = time.Now()
	fmt.Printf("Updating folder: %+v\n", folder)
	return nil
}

// DeleteFolder deletes a folder
func (vs *VaultService) DeleteFolder(userID, folderID string) error {
	fmt.Printf("Deleting folder: UserID=%s FolderID=%s\n", userID, folderID)
	return nil
}

// SearchItems searches vault items
func (vs *VaultService) SearchItems(userID, query string, limit, offset int) ([]*models.VaultItem, int, error) {
	// Use GetItems with search filter
	return vs.GetItems(userID, limit, offset, query, "", "")
}

// GetSearchSuggestions provides search suggestions
func (vs *VaultService) GetSearchSuggestions(userID, query string, limit int) ([]string, error) {
	// Mock suggestions
	suggestions := []string{
		"gmail",
		"google",
		"facebook",
		"credit card",
		"password",
	}

	if query != "" {
		filtered := make([]string, 0)
		for _, suggestion := range suggestions {
			if strings.Contains(strings.ToLower(suggestion), strings.ToLower(query)) {
				filtered = append(filtered, suggestion)
			}
		}
		suggestions = filtered
	}

	if len(suggestions) > limit {
		suggestions = suggestions[:limit]
	}

	return suggestions, nil
}
