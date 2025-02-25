package controllers

import (
	"net/http"

	"Unlistedbin-api/models"

	"github.com/gin-gonic/gin"
)

func CreateRepository(c *gin.Context) {
	var repo models.Repository
	if err := c.ShouldBindJSON(&repo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	repo.OwnerID = userID.(uint)
	if err := DB.Create(&repo).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Creation failed"})
		return
	}
	c.JSON(http.StatusOK, repo)
}

func GetRepositories(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	var repos []models.Repository
	if err := DB.Where("owner_id = ?", userID.(uint)).Find(&repos).Error; err != nil {
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
	userID, exists := c.Get("userID")
	if !exists || repo.OwnerID != userID.(uint) {
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
	userID, exists := c.Get("userID")
	if !exists || repo.OwnerID != userID.(uint) {
		c.JSON(http.StatusForbidden, gin.H{"error": "No permission"})
		return
	}
	if err := DB.Delete(&repo).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Deletion failed"})
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
