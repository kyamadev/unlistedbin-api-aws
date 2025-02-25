package controllers

import (
	"net/http"
	"time"

	"Unlistedbin-api/models"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var DB *gorm.DB

func SessionHandler(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("userID")
	if userID == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthenticated"})
		return
	}
	username := session.Get("username")
	c.JSON(http.StatusOK, gin.H{"isLoggedIn": true, "username": username})
}

func RegisterHandler(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if err := DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

func LoginHandler(c *gin.Context) {
	var login models.User
	if err := c.ShouldBindJSON(&login); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var user models.User
	if err := DB.Where("username = ?", login.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(login.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed"})
		return
	}

	// セッション
	session := sessions.Default(c)
	session.Set("userID", user.ID)
	session.Set("username", user.Username)
	session.Set("loginTime", time.Now().Unix())
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged in successfully"})
}

func LogoutHandler(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clear session"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func CheckUsernameHandler(c *gin.Context) {
	username := c.Query("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}

	var count int64
	if err := DB.Model(&models.User{}).Where("username = ?", username).Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	available := count == 0
	c.JSON(http.StatusOK, gin.H{"available": available})
}

func UpdateUsernameHandler(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("userID")
	if userID == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var payload struct {
		NewUsername string `json:"newUsername"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil || payload.NewUsername == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: newUsername required"})
		return
	}

	var count int64
	if err := DB.Model(&models.User{}).Where("username = ?", payload.NewUsername).Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	var user models.User
	if err := DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}
	user.Username = payload.NewUsername
	if err := DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update username"})
		return
	}

	// セッション内のusername更新
	session.Set("username", user.Username)
	session.Save()

	c.JSON(http.StatusOK, gin.H{"message": "Username updated successfully", "username": user.Username})
}

func DeleteAccountHandler(c *gin.Context) {
	session := sessions.Default(c)
	userIDVal := session.Get("userID")
	if userIDVal == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	uid := userIDVal.(uint)

	// ユーザーが所有するすべてのレポジトリを取得
	var repos []models.Repository
	if err := DB.Where("owner_id = ?", uid).Find(&repos).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve repositories"})
		return
	}

	// レポジトリ削除
	for _, repo := range repos {
		if err := DB.Delete(&repo).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete repository: " + repo.UUID})
			return
		}
		if err := FileStorage.DeleteRepository(repo.UUID); err != nil {
			c.JSON(http.StatusOK, gin.H{
				"message":   "Account deleted but failed to remove files for repository: " + repo.UUID,
				"repo_uuid": repo.UUID,
			})
			return
		}
	}

	// ユーザーアカウント削除
	var user models.User
	if err := DB.First(&user, uid).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
		return
	}
	// 暫定対応(削除したusernameを再取得できない):Unscoped() でソフトデリートを無効化し、物理削除
	if err := DB.Unscoped().Delete(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete account"})
		return
	}

	session.Clear()
	session.Save()

	c.JSON(http.StatusOK, gin.H{"message": "Account and all repositories deleted successfully"})
}
