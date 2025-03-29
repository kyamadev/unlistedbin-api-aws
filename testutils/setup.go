package testutils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"Unlistedbin-api/config"
	"Unlistedbin-api/models"
	"Unlistedbin-api/storage"
)

type TestEnv struct {
	DB        *gorm.DB
	Router    *gin.Engine
	Storage   storage.Storage
	ConfigDir string
}

func SetupTestEnvironment(t *testing.T) *TestEnv {
	currentDir, err := os.Getwd()
	if err != nil {
		t.Logf("Warning: Failed to get current directory: %v", err)
	}

	var envPath string
	if filepath.Base(currentDir) == "test" {
		envPath = "../.env.test"
	} else {
		envPath = "./.env.test"
	}

	if err := godotenv.Load(envPath); err != nil {
		t.Logf("Warning: .env.test file not found at %s, using environment variables", envPath)
	}

	config.LoadConfig()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	err = db.AutoMigrate(&models.User{}, &models.Repository{}, &models.File{})
	if err != nil {
		t.Fatalf("Failed to migrate database: %v", err)
	}

	testStoragePath := os.TempDir() + "/unlistedbin-test-storage"
	err = os.MkdirAll(testStoragePath, os.ModePerm)
	if err != nil {
		t.Fatalf("Failed to create test storage directory: %v", err)
	}

	fileStorage := storage.NewLocalStorage(testStoragePath)

	gin.SetMode(gin.TestMode)
	r := gin.Default()

	return &TestEnv{
		DB:        db,
		Router:    r,
		Storage:   fileStorage,
		ConfigDir: testStoragePath,
	}
}

func CleanupTestEnvironment(testEnv *TestEnv) {
	if testEnv != nil && testEnv.ConfigDir != "" {
		os.RemoveAll(testEnv.ConfigDir)
	}
}
