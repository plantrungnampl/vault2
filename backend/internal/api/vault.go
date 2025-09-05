package api

import (
	"net/http"
	"strconv"

	"securevault/internal/models"
	"securevault/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// GetVaultItems retrieves all vault items for the authenticated user
func GetVaultItems(vaultService *services.VaultService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		// Parse query parameters
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
		search := c.Query("search")
		itemType := c.Query("type")
		folderID := c.Query("folder_id")

		items, total, err := vaultService.GetItems(userID, limit, offset, search, itemType, folderID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"items":  items,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		})
	}
}

// CreateVaultItem creates a new vault item
func CreateVaultItem(vaultService *services.VaultService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		var req struct {
			Name     string                 `json:"name" binding:"required"`
			Type     string                 `json:"type" binding:"required"`
			Data     map[string]interface{} `json:"data" binding:"required"`
			Notes    string                 `json:"notes"`
			FolderID *string                `json:"folder_id"`
			Tags     []string               `json:"tags"`
			Favorite bool                   `json:"favorite"`
			Reprompt bool                   `json:"reprompt"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Create vault item
		item := &models.VaultItem{
			ID:       uuid.New().String(),
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

		if err := vaultService.CreateItem(item); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Log audit event
		auditService.LogEvent(userID, "vault_item_created", "success", gin.H{
			"item_id":   item.ID,
			"item_type": item.Type,
		})

		c.JSON(http.StatusCreated, item)
	}
}

// GetVaultItem retrieves a specific vault item
func GetVaultItem(vaultService *services.VaultService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		itemID := c.Param("id")

		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		item, err := vaultService.GetItem(userID, itemID)
		if err != nil {
			if err.Error() == "item not found" {
				c.JSON(http.StatusNotFound, gin.H{"error": "Item not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, item)
	}
}

// UpdateVaultItem updates a vault item
func UpdateVaultItem(vaultService *services.VaultService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		itemID := c.Param("id")

		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		var req struct {
			Name     string                 `json:"name"`
			Type     string                 `json:"type"`
			Data     map[string]interface{} `json:"data"`
			Notes    string                 `json:"notes"`
			FolderID *string                `json:"folder_id"`
			Tags     []string               `json:"tags"`
			Favorite bool                   `json:"favorite"`
			Reprompt bool                   `json:"reprompt"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Get existing item
		existingItem, err := vaultService.GetItem(userID, itemID)
		if err != nil {
			if err.Error() == "item not found" {
				c.JSON(http.StatusNotFound, gin.H{"error": "Item not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Update fields
		if req.Name != "" {
			existingItem.Name = req.Name
		}
		if req.Type != "" {
			existingItem.Type = req.Type
		}
		if req.Data != nil {
			existingItem.Data = req.Data
		}
		existingItem.Notes = req.Notes
		existingItem.FolderID = req.FolderID
		existingItem.Tags = req.Tags
		existingItem.Favorite = req.Favorite
		existingItem.Reprompt = req.Reprompt

		if err := vaultService.UpdateItem(existingItem); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Log audit event
		auditService.LogEvent(userID, "vault_item_updated", "success", gin.H{
			"item_id":   itemID,
			"item_type": existingItem.Type,
		})

		c.JSON(http.StatusOK, existingItem)
	}
}

// DeleteVaultItem deletes a vault item
func DeleteVaultItem(vaultService *services.VaultService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		itemID := c.Param("id")

		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		// Get item details for logging
		item, err := vaultService.GetItem(userID, itemID)
		if err != nil {
			if err.Error() == "item not found" {
				c.JSON(http.StatusNotFound, gin.H{"error": "Item not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if err := vaultService.DeleteItem(userID, itemID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Log audit event
		auditService.LogEvent(userID, "vault_item_deleted", "success", gin.H{
			"item_id":   itemID,
			"item_type": item.Type,
		})

		c.JSON(http.StatusOK, gin.H{"message": "Item deleted successfully"})
	}
}

// ShareVaultItem shares a vault item with another user
func ShareVaultItem(vaultService *services.VaultService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		itemID := c.Param("id")

		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		var req struct {
			ShareWithUserID string `json:"share_with_user_id" binding:"required"`
			Permissions     string `json:"permissions" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := vaultService.ShareItem(userID, itemID, req.ShareWithUserID, req.Permissions); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Log audit event
		auditService.LogEvent(userID, "vault_item_shared", "success", gin.H{
			"item_id":     itemID,
			"shared_with": req.ShareWithUserID,
			"permissions": req.Permissions,
		})

		c.JSON(http.StatusOK, gin.H{"message": "Item shared successfully"})
	}
}

// GetSharedItems retrieves items shared with the user
func GetSharedItems(vaultService *services.VaultService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		items, err := vaultService.GetSharedItems(userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"items": items})
	}
}

// CreateFolder creates a new folder
func CreateFolder(vaultService *services.VaultService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		var req struct {
			Name  string `json:"name" binding:"required"`
			Color string `json:"color"`
			Icon  string `json:"icon"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		folder := &models.VaultFolder{
			ID:     uuid.New().String(),
			UserID: userID,
			Name:   req.Name,
			Color:  req.Color,
			Icon:   req.Icon,
		}

		if err := vaultService.CreateFolder(folder); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Log audit event
		auditService.LogEvent(userID, "vault_folder_created", "success", gin.H{
			"folder_id":   folder.ID,
			"folder_name": folder.Name,
		})

		c.JSON(http.StatusCreated, folder)
	}
}

// GetFolders retrieves all folders for the user
func GetFolders(vaultService *services.VaultService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		folders, err := vaultService.GetFolders(userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"folders": folders})
	}
}

// UpdateFolder updates a folder
func UpdateFolder(vaultService *services.VaultService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		folderID := c.Param("id")

		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		var req struct {
			Name  string `json:"name"`
			Color string `json:"color"`
			Icon  string `json:"icon"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		folder, err := vaultService.GetFolder(userID, folderID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Folder not found"})
			return
		}

		if req.Name != "" {
			folder.Name = req.Name
		}
		if req.Color != "" {
			folder.Color = req.Color
		}
		if req.Icon != "" {
			folder.Icon = req.Icon
		}

		if err := vaultService.UpdateFolder(folder); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Log audit event
		auditService.LogEvent(userID, "vault_folder_updated", "success", gin.H{
			"folder_id":   folderID,
			"folder_name": folder.Name,
		})

		c.JSON(http.StatusOK, folder)
	}
}

// DeleteFolder deletes a folder
func DeleteFolder(vaultService *services.VaultService, auditService *services.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		folderID := c.Param("id")

		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		// Get folder details for logging
		folder, err := vaultService.GetFolder(userID, folderID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Folder not found"})
			return
		}

		if err := vaultService.DeleteFolder(userID, folderID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Log audit event
		auditService.LogEvent(userID, "vault_folder_deleted", "success", gin.H{
			"folder_id":   folderID,
			"folder_name": folder.Name,
		})

		c.JSON(http.StatusOK, gin.H{"message": "Folder deleted successfully"})
	}
}

// SearchVaultItems searches vault items
func SearchVaultItems(vaultService *services.VaultService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		query := c.Query("q")
		if query == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Search query is required"})
			return
		}

		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

		items, total, err := vaultService.SearchItems(userID, query, limit, offset)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"items": items,
			"total": total,
			"query": query,
		})
	}
}

// GetSearchSuggestions provides search suggestions
func GetSearchSuggestions(vaultService *services.VaultService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		if userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		query := c.Query("q")
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))

		suggestions, err := vaultService.GetSearchSuggestions(userID, query, limit)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"suggestions": suggestions})
	}
}
