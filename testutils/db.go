package testutils

import (
	"testing"

	"Unlistedbin-api/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func SetupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}

	err = db.AutoMigrate(&models.User{}, &models.Repository{}, &models.File{})
	if err != nil {
		t.Fatalf("Failed to migrate models: %v", err)
	}

	return db
}
