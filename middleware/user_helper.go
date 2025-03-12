package middleware

import (
	"errors"
	"fmt"
	"log"
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
			return 0, fmt.Errorf("user with cognito ID %s not found", cognitoID)
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
			return nil, fmt.Errorf("user with cognito ID %s not found", cognitoID)
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	return &user, nil
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
