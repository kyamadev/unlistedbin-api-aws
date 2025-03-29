package controllers

import (
	"Unlistedbin-api/middleware"
	"Unlistedbin-api/models"
	"net/http"

	"gorm.io/gorm"

	"github.com/gin-gonic/gin"
)

func CreateRepository(c *gin.Context) {
	var repo models.Repository
	if err := c.ShouldBindJSON(&repo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	userID, err := middleware.GetUserIDFromContext(c, DB)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed", "details": err.Error()})
		return
	}

	repo.OwnerID = userID

	if err := DB.Create(&repo).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Creation failed"})
		return
	}
	c.JSON(http.StatusOK, repo)
}

func GetRepositories(c *gin.Context) {
	userID, err := middleware.GetUserIDFromContext(c, DB)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed", "details": err.Error()})
		return
	}

	var repos []models.Repository
	if err := DB.Where("owner_id = ?", userID).Find(&repos).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Query failed"})
		return
	}
	c.JSON(http.StatusOK, repos)
}

func UpdateVisibility(c *gin.Context) {
	uuidParam := c.Param("uuid")
	var payload struct {
		Public bool `json:"public"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	var repo models.Repository
	if err := DB.Where("uuid = ?", uuidParam).First(&repo).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Repository not found"})
		return
	}

	isOwner, err := middleware.OwnershipCheck(c, DB, repo.OwnerID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed", "details": err.Error()})
		return
	}

	if !isOwner {
		c.JSON(http.StatusForbidden, gin.H{"error": "No permission"})
		return
	}

	repo.Public = payload.Public
	if err := DB.Save(&repo).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Update failed"})
		return
	}
	c.JSON(http.StatusOK, repo)
}

func DeleteRepository(c *gin.Context) {
	uuidParam := c.Param("uuid")
	var repo models.Repository
	if err := DB.Where("uuid = ?", uuidParam).First(&repo).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Repository not found"})
		return
	}

	isOwner, err := middleware.OwnershipCheck(c, DB, repo.OwnerID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed", "details": err.Error()})
		return
	}

	if !isOwner {
		c.JSON(http.StatusForbidden, gin.H{"error": "No permission"})
		return
	}
	// Transaction
	err = DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("repository_id = ?", repo.ID).Unscoped().Delete(&models.File{}).Error; err != nil {
			return err
		}

		if err := tx.Unscoped().Delete(&repo).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database deletion failed", "details": err.Error()})
		return
	}

	if err := FileStorage.DeleteRepository(repo.UUID); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"message":   "Repository deleted from DB, but failed to remove files from storage",
			"repo_uuid": repo.UUID,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Repository deleted",
		"repo_uuid": repo.UUID,
	})
}

func UpdateDownloadPermission(c *gin.Context) {
	uuidParam := c.Param("uuid")
	var payload struct {
		DownloadAllowed bool `json:"download_allowed"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	var repo models.Repository
	if err := DB.Where("uuid = ?", uuidParam).First(&repo).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Repository not found"})
		return
	}

	isOwner, err := middleware.OwnershipCheck(c, DB, repo.OwnerID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed", "details": err.Error()})
		return
	}

	if !isOwner {
		c.JSON(http.StatusForbidden, gin.H{"error": "No permission"})
		return
	}

	repo.DownloadAllowed = payload.DownloadAllowed
	if err := DB.Save(&repo).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Update failed"})
		return
	}
	c.JSON(http.StatusOK, repo)
}
