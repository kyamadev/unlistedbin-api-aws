package middleware

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"Unlistedbin-api/models"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var (
	userIDCache     = make(map[string]uint)
	usernameCahce   = make(map[string]string)
	cacheMutex      = &sync.RWMutex{}
	cacheExpiration = 10 * time.Minute
	lastCleanup     = time.Now()
)

func GetUserIDFromContext(c *gin.Context, db *gorm.DB) (uint, error) {
	cognitoIDVal, exists := c.Get("userID")
	if !exists {
		return 0, errors.New("user ID not found in context")
	}

	cognitoID, ok := cognitoIDVal.(string)
	if !ok {
		return 0, errors.New("user ID is not a string")
	}

	cacheMutex.RLock()
	cachedID, found := userIDCache[cognitoID]
	cacheMutex.RUnlock()

	if found {
		return cachedID, nil
	}

	var user models.User
	if err := db.Where("cognito_id = ?", cognitoID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 自動ユーザー作成を試みる
			newUser, createErr := createUserFromContext(c, db, cognitoID)
			if createErr != nil {
				return 0, fmt.Errorf("user with cognito ID %s not found and auto-creation failed: %w", cognitoID, createErr)
			}
			return newUser.ID, nil
		}
		return 0, fmt.Errorf("database error: %w", err)
	}

	cacheMutex.Lock()
	userIDCache[cognitoID] = user.ID
	usernameCahce[cognitoID] = user.Username
	cacheMutex.Unlock()

	if time.Since(lastCleanup) > cacheExpiration {
		go cleanupCache()
	}

	return user.ID, nil
}

func GetUserFromContext(c *gin.Context, db *gorm.DB) (*models.User, error) {
	cognitoIDVal, exists := c.Get("userID")
	if !exists {
		return nil, errors.New("user ID not found in context")
	}

	cognitoID, ok := cognitoIDVal.(string)
	if !ok {
		return nil, errors.New("user ID is not a string")
	}

	var user models.User
	if err := db.Where("cognito_id = ?", cognitoID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 自動ユーザー作成を試みる
			return createUserFromContext(c, db, cognitoID)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	return &user, nil
}

func createUserFromContext(c *gin.Context, db *gorm.DB, cognitoID string) (*models.User, error) {
	emailVal, emailExists := c.Get("email")
	usernameVal, usernameExists := c.Get("username")

	var email, username string
	if emailExists {
		email, _ = emailVal.(string)
	}

	if usernameExists {
		username, _ = usernameVal.(string)
	}

	if email == "" && username == "" {
		return nil, fmt.Errorf("insufficient information to create user - both email and username are missing")
	}

	if email == "" {
		email = username
	}

	if username == "" {
		parts := strings.Split(email, "@")
		username = parts[0]

		// 既に存在するユーザー名であれば、ユニークなものにする
		var count int64
		db.Model(&models.User{}).Where("username = ?", username).Count(&count)
		if count > 0 {
			username = fmt.Sprintf("%s_%d", username, time.Now().Unix())
		}
	} else {
		// 既存のユーザー名と衝突しないか確認
		var count int64
		db.Model(&models.User{}).Where("username = ?", username).Count(&count)
		if count > 0 {
			username = fmt.Sprintf("%s_%d", username, time.Now().Unix())
		}
	}

	newUser := models.User{
		Username:      username,
		Email:         email,
		CognitoID:     cognitoID,
		EmailVerified: true,
	}

	if err := db.Create(&newUser).Error; err != nil {
		return nil, fmt.Errorf("failed to create user record: %w", err)
	}

	log.Printf("Auto-created user record for Cognito ID: %s, Username: %s, Email: %s", cognitoID, username, email)

	cacheMutex.Lock()
	userIDCache[cognitoID] = newUser.ID
	usernameCahce[cognitoID] = newUser.Username
	cacheMutex.Unlock()

	return &newUser, nil
}

func OwnershipCheck(c *gin.Context, db *gorm.DB, ownerID uint) (bool, error) {
	userID, err := GetUserIDFromContext(c, db)
	if err != nil {
		return false, err
	}

	return userID == ownerID, nil
}

func cleanupCache() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	userIDCache = make(map[string]uint)
	usernameCahce = make(map[string]string)
	lastCleanup = time.Now()

	log.Println("User ID cache cleaned up")
}
