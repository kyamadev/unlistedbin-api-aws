package controllers

import (
	"testing"

	"Unlistedbin-api/models"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// SetupTestDB は in‑memory SQLite を用いてテスト用 DB を初期化し、
// 自動マイグレーションを実行後、グローバル変数 DB にセットします。
func SetupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open test DB: %v", err)
	}
	// User と Repository のマイグレーション（必要に応じて File なども）
	if err := db.AutoMigrate(&models.User{}, &models.Repository{}); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	DB = db
	return db
}
