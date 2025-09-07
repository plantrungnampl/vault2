package services

import (
	"errors"
	"fmt"
	"time"

	"securevault/internal/database"
	"securevault/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type VaultService struct {
	db *gorm.DB
}

type CreateVaultItemRequest struct {
	Name     string                 `json:"name" binding:"required"`
	Type     string                 `json:"type" binding:"required"`
	Data     map[string]interface{} `json:"data" binding:"required"`
	Notes    string                 `json:"notes"`
	FolderID *uuid.UUID             `json:"folder_id"`
	Tags     []string               `json:"tags"`
	Favorite bool                   `json:"favorite"`
	Reprompt bool                   `json:"reprompt"`
}

type UpdateVaultItemRequest struct {
	Name     *string                `json:"name"`
	Type     *string                `json:"type"`
	Data     map[string]interface{} `json:"data"`
	Notes    *string                `json:"notes"`
	FolderID *uuid.UUID             `json:"folder_id"`
	Tags     []string               `json:"tags"`
	Favorite *bool                  `json:"favorite"`
	Reprompt *bool                  `json:"reprompt"`
}

type CreateFolderRequest struct {
	Name     string     `json:"name" binding:"required"`
	Color    string     `json:"color"`
	Icon     string     `json:"icon"`
	ParentID *uuid.UUID `json:"parent_id"`
}

type VaultStats struct {
	TotalItems    int64            `json:"total_items"`
	TotalFolders  int64            `json:"total_folders"`
	FavoriteItems int64            `json:"favorite_items"`
	RecentItems   int64            `json:"recent_items"`
	TypeStats     map[string]int64 `json:"type_stats"`
}

func NewVaultService() *VaultService {
	return &VaultService{
		db: database.GetDB(),
	}
}

// CreateVaultItem creates a new vault item for a user
func (s *VaultService) CreateVaultItem(userID uuid.UUID, req CreateVaultItemRequest) (*models.VaultItem, error) {
	// Validate folder ownership if folder_id provided
	if req.FolderID != nil {
		var folder models.VaultFolder
		if err := s.db.Where("id = ? AND user_id = ?", req.FolderID, userID).First(&folder).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, errors.New("folder not found or access denied")
			}
			return nil, fmt.Errorf("failed to validate folder: %v", err)
		}
	}

	// Create vault item
	item := &models.VaultItem{
		ID:       uuid.New(),
		UserID:   userID,
		Name:     req.Name,
		Type:     req.Type,
		Data:     req.Data,
		Notes:    req.Notes,
		FolderID: req.FolderID,
		Tags:     req.Tags,
		Favorite: req.Favorite,
		Reprompt: req.Reprompt,
	}

	if err := s.db.Create(item).Error; err != nil {
		return nil, fmt.Errorf("failed to create vault item: %v", err)
	}

	// Update folder item count if item was added to a folder
	if req.FolderID != nil {
		s.updateFolderItemCount(*req.FolderID)
	}

	return item, nil
}

// GetVaultItem retrieves a vault item by ID
func (s *VaultService) GetVaultItem(userID, itemID uuid.UUID) (*models.VaultItem, error) {
	var item models.VaultItem
	if err := s.db.Where("id = ? AND user_id = ?", itemID, userID).First(&item).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("vault item not found")
		}
		return nil, fmt.Errorf("failed to get vault item: %v", err)
	}
	return &item, nil
}

// UpdateVaultItem updates an existing vault item
func (s *VaultService) UpdateVaultItem(userID, itemID uuid.UUID, req UpdateVaultItemRequest) (*models.VaultItem, error) {
	// Get existing item
	item, err := s.GetVaultItem(userID, itemID)
	if err != nil {
		return nil, err
	}

	// Validate folder ownership if folder_id provided
	if req.FolderID != nil && *req.FolderID != uuid.Nil {
		var folder models.VaultFolder
		if err := s.db.Where("id = ? AND user_id = ?", req.FolderID, userID).First(&folder).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, errors.New("folder not found or access denied")
			}
			return nil, fmt.Errorf("failed to validate folder: %v", err)
		}
	}

	// Store old folder ID for count updates
	oldFolderID := item.FolderID

	// Update fields
	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Type != nil {
		updates["type"] = *req.Type
	}
	if req.Data != nil {
		updates["data"] = req.Data
	}
	if req.Notes != nil {
		updates["notes"] = *req.Notes
	}
	if req.FolderID != nil {
		updates["folder_id"] = req.FolderID
	}
	if req.Tags != nil {
		updates["tags"] = req.Tags
	}
	if req.Favorite != nil {
		updates["favorite"] = *req.Favorite
	}
	if req.Reprompt != nil {
		updates["reprompt"] = *req.Reprompt
	}
	updates["updated_at"] = time.Now()

	if err := s.db.Model(item).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("failed to update vault item: %v", err)
	}

	// Update folder item counts if folder changed
	if req.FolderID != nil && oldFolderID != req.FolderID {
		if oldFolderID != nil {
			s.updateFolderItemCount(*oldFolderID)
		}
		if *req.FolderID != uuid.Nil {
			s.updateFolderItemCount(*req.FolderID)
		}
	}

	return item, nil
}

// DeleteVaultItem soft deletes a vault item
func (s *VaultService) DeleteVaultItem(userID, itemID uuid.UUID) error {
	// Get item to check ownership and folder
	item, err := s.GetVaultItem(userID, itemID)
	if err != nil {
		return err
	}

	// Soft delete the item
	if err := s.db.Delete(item).Error; err != nil {
		return fmt.Errorf("failed to delete vault item: %v", err)
	}

	// Update folder item count
	if item.FolderID != nil {
		s.updateFolderItemCount(*item.FolderID)
	}

	return nil
}

// ListVaultItems returns paginated list of vault items for a user
func (s *VaultService) ListVaultItems(userID uuid.UUID, offset, limit int, folderID *uuid.UUID, search, itemType string, favorite bool) ([]models.VaultItem, int64, error) {
	var items []models.VaultItem
	var total int64

	query := s.db.Model(&models.VaultItem{}).Where("user_id = ?", userID)

	// Apply filters
	if folderID != nil {
		if *folderID == uuid.Nil {
			query = query.Where("folder_id IS NULL")
		} else {
			query = query.Where("folder_id = ?", *folderID)
		}
	}

	if search != "" {
		query = query.Where("name ILIKE ? OR notes ILIKE ?", "%"+search+"%", "%"+search+"%")
	}

	if itemType != "" {
		query = query.Where("type = ?", itemType)
	}

	if favorite {
		query = query.Where("favorite = ?", true)
	}

	// Get total count
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count vault items: %v", err)
	}

	// Get items with pagination
	if err := query.Offset(offset).Limit(limit).Order("updated_at DESC").Find(&items).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to list vault items: %v", err)
	}

	return items, total, nil
}

// CreateFolder creates a new vault folder
func (s *VaultService) CreateFolder(userID uuid.UUID, req CreateFolderRequest) (*models.VaultFolder, error) {
	// Validate parent folder ownership if parent_id provided
	if req.ParentID != nil {
		var parentFolder models.VaultFolder
		if err := s.db.Where("id = ? AND user_id = ?", req.ParentID, userID).First(&parentFolder).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, errors.New("parent folder not found or access denied")
			}
			return nil, fmt.Errorf("failed to validate parent folder: %v", err)
		}
	}

	folder := &models.VaultFolder{
		ID:       uuid.New(),
		UserID:   userID,
		Name:     req.Name,
		Color:    req.Color,
		Icon:     req.Icon,
		ParentID: req.ParentID,
	}

	if err := s.db.Create(folder).Error; err != nil {
		return nil, fmt.Errorf("failed to create folder: %v", err)
	}

	return folder, nil
}

// GetFolder retrieves a folder by ID
func (s *VaultService) GetFolder(userID, folderID uuid.UUID) (*models.VaultFolder, error) {
	var folder models.VaultFolder
	if err := s.db.Where("id = ? AND user_id = ?", folderID, userID).First(&folder).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("folder not found")
		}
		return nil, fmt.Errorf("failed to get folder: %v", err)
	}
	return &folder, nil
}

// UpdateFolder updates an existing folder
func (s *VaultService) UpdateFolder(userID, folderID uuid.UUID, name, color, icon string, parentID *uuid.UUID) (*models.VaultFolder, error) {
	// Get existing folder
	folder, err := s.GetFolder(userID, folderID)
	if err != nil {
		return nil, err
	}

	// Validate parent folder ownership if parent_id provided
	if parentID != nil && *parentID != uuid.Nil {
		var parentFolder models.VaultFolder
		if err := s.db.Where("id = ? AND user_id = ?", parentID, userID).First(&parentFolder).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, errors.New("parent folder not found or access denied")
			}
			return nil, fmt.Errorf("failed to validate parent folder: %v", err)
		}
	}

	// Update folder
	updates := map[string]interface{}{
		"updated_at": time.Now(),
	}
	if name != "" {
		updates["name"] = name
	}
	if color != "" {
		updates["color"] = color
	}
	if icon != "" {
		updates["icon"] = icon
	}
	if parentID != nil {
		updates["parent_id"] = parentID
	}

	if err := s.db.Model(folder).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("failed to update folder: %v", err)
	}

	return folder, nil
}

// DeleteFolder soft deletes a folder and moves items to root
func (s *VaultService) DeleteFolder(userID, folderID uuid.UUID) error {
	// Get folder to check ownership
	folder, err := s.GetFolder(userID, folderID)
	if err != nil {
		return err
	}

	// Move all items in this folder to root (no folder)
	if err := s.db.Model(&models.VaultItem{}).
		Where("user_id = ? AND folder_id = ?", userID, folderID).
		Update("folder_id", nil).Error; err != nil {
		return fmt.Errorf("failed to move items to root: %v", err)
	}

	// Move all subfolders to root
	if err := s.db.Model(&models.VaultFolder{}).
		Where("user_id = ? AND parent_id = ?", userID, folderID).
		Update("parent_id", nil).Error; err != nil {
		return fmt.Errorf("failed to move subfolders to root: %v", err)
	}

	// Delete the folder
	if err := s.db.Delete(folder).Error; err != nil {
		return fmt.Errorf("failed to delete folder: %v", err)
	}

	return nil
}

// ListFolders returns all folders for a user
func (s *VaultService) ListFolders(userID uuid.UUID) ([]models.VaultFolder, error) {
	var folders []models.VaultFolder
	if err := s.db.Where("user_id = ?", userID).Order("name ASC").Find(&folders).Error; err != nil {
		return nil, fmt.Errorf("failed to list folders: %v", err)
	}

	// Update item counts for all folders
	for i := range folders {
		s.updateFolderItemCount(folders[i].ID)
	}

	return folders, nil
}

// GetVaultStats returns vault statistics for a user
func (s *VaultService) GetVaultStats(userID uuid.UUID) (*VaultStats, error) {
	stats := &VaultStats{
		TypeStats: make(map[string]int64),
	}

	// Total items
	if err := s.db.Model(&models.VaultItem{}).Where("user_id = ?", userID).Count(&stats.TotalItems).Error; err != nil {
		return nil, fmt.Errorf("failed to count total items: %v", err)
	}

	// Total folders
	if err := s.db.Model(&models.VaultFolder{}).Where("user_id = ?", userID).Count(&stats.TotalFolders).Error; err != nil {
		return nil, fmt.Errorf("failed to count total folders: %v", err)
	}

	// Favorite items
	if err := s.db.Model(&models.VaultItem{}).Where("user_id = ? AND favorite = ?", userID, true).Count(&stats.FavoriteItems).Error; err != nil {
		return nil, fmt.Errorf("failed to count favorite items: %v", err)
	}

	// Recent items (last 7 days)
	sevenDaysAgo := time.Now().AddDate(0, 0, -7)
	if err := s.db.Model(&models.VaultItem{}).Where("user_id = ? AND created_at >= ?", userID, sevenDaysAgo).Count(&stats.RecentItems).Error; err != nil {
		return nil, fmt.Errorf("failed to count recent items: %v", err)
	}

	// Type statistics
	var typeResults []struct {
		Type  string `json:"type"`
		Count int64  `json:"count"`
	}
	if err := s.db.Model(&models.VaultItem{}).
		Select("type, COUNT(*) as count").
		Where("user_id = ?", userID).
		Group("type").
		Scan(&typeResults).Error; err != nil {
		return nil, fmt.Errorf("failed to get type statistics: %v", err)
	}

	for _, result := range typeResults {
		stats.TypeStats[result.Type] = result.Count
	}

	return stats, nil
}

// ToggleFavorite toggles the favorite status of a vault item
func (s *VaultService) ToggleFavorite(userID, itemID uuid.UUID) (*models.VaultItem, error) {
	item, err := s.GetVaultItem(userID, itemID)
	if err != nil {
		return nil, err
	}

	// Toggle favorite status
	newFavoriteStatus := !item.Favorite
	if err := s.db.Model(item).Update("favorite", newFavoriteStatus).Error; err != nil {
		return nil, fmt.Errorf("failed to toggle favorite: %v", err)
	}

	item.Favorite = newFavoriteStatus
	return item, nil
}

// updateFolderItemCount updates the item count for a folder
func (s *VaultService) updateFolderItemCount(folderID uuid.UUID) {
	var count int64
	s.db.Model(&models.VaultItem{}).Where("folder_id = ?", folderID).Count(&count)
	s.db.Model(&models.VaultFolder{}).Where("id = ?", folderID).Update("item_count", count)
}

// SearchVaultItems searches vault items by name, notes, and other fields
func (s *VaultService) SearchVaultItems(userID uuid.UUID, query string, limit int) ([]models.VaultItem, error) {
	var items []models.VaultItem

	searchPattern := "%" + query + "%"
	if err := s.db.Where("user_id = ? AND (name ILIKE ? OR notes ILIKE ?)",
		userID, searchPattern, searchPattern).
		Limit(limit).
		Order("updated_at DESC").
		Find(&items).Error; err != nil {
		return nil, fmt.Errorf("failed to search vault items: %v", err)
	}

	return items, nil
}

// GetRecentItems returns recently accessed/updated items
func (s *VaultService) GetRecentItems(userID uuid.UUID, limit int) ([]models.VaultItem, error) {
	var items []models.VaultItem
	if err := s.db.Where("user_id = ?", userID).
		Order("updated_at DESC").
		Limit(limit).
		Find(&items).Error; err != nil {
		return nil, fmt.Errorf("failed to get recent items: %v", err)
	}

	return items, nil
}
