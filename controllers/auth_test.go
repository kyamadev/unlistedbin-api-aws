package controllers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"Unlistedbin-api/controllers"
	"Unlistedbin-api/models"
	"Unlistedbin-api/storage"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect test database: %v", err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.Repository{}, &models.File{}); err != nil {
		t.Fatalf("failed to migrate test database: %v", err)
	}
	controllers.DB = db
	return db
}

func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	store := cookie.NewStore([]byte("secret-key"))
	router.Use(sessions.Sessions("mysession", store))

	// 認証不要のエンドポイント
	router.POST("/api/auth/register", controllers.RegisterHandler)
	router.POST("/api/auth/login", controllers.LoginHandler)
	router.POST("/api/auth/logout", controllers.LogoutHandler)
	router.GET("/auth/check-username", controllers.CheckUsernameHandler)

	// 認証が必要なエンドポイント
	router.PUT("/api/auth/update-username", controllers.UpdateUsernameHandler)
	router.DELETE("/api/auth/delete-account", controllers.DeleteAccountHandler)

	return router
}

func TestRegisterAndLogin(t *testing.T) {
	router := setupRouter()
	setupTestDB(t)

	// 初期化：テスト用の一時ディレクトリを設定して FileStorage を初期化
	testStoragePath := filepath.Join("/tmp", "local_test_storage")
	controllers.FileStorage = storage.NewLocalStorage(testStoragePath)

	// --- Registration Test ---
	regPayload := map[string]string{
		"username": "testuser",
		"password": "password123",
	}
	regBytes, _ := json.Marshal(regPayload)
	req, _ := http.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(regBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected registration status 200, got %d: %s", w.Code, w.Body.String())
	}

	// --- Login Test ---
	loginPayload := map[string]string{
		"username": "testuser",
		"password": "password123",
	}
	loginBytes, _ := json.Marshal(loginPayload)
	req, _ = http.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(loginBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected login status 200, got %d: %s", w.Code, w.Body.String())
	}

	// --- Check Username Test ---
	req, _ = http.NewRequest("GET", "/auth/check-username?username=testuser", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected check-username status 200, got %d: %s", w.Code, w.Body.String())
	}
	var checkResp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &checkResp); err != nil {
		t.Fatalf("failed to parse check-username response: %v", err)
	}
	if available, ok := checkResp["available"].(bool); !ok || available {
		t.Fatalf("expected username 'testuser' to be unavailable, got available: %v", available)
	}

	// --- Logout Test ---
	req, _ = http.NewRequest("POST", "/api/auth/logout", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected logout status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateUsername(t *testing.T) {
	router := setupRouter()
	db := setupTestDB(t)
	// 初期化：テスト用の一時ディレクトリ
	testStoragePath := filepath.Join("/tmp", "local_test_storage")
	db.AutoMigrate(&models.User{})
	controllers.FileStorage = storage.NewLocalStorage(testStoragePath)

	// 事前にテストユーザーを作成
	user := models.User{Username: "olduser", Password: "password123"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	// ログインリクエストでセッションCookieを取得
	loginPayload := map[string]string{
		"username": "olduser",
		"password": "password123",
	}
	loginBytes, _ := json.Marshal(loginPayload)
	req, _ := http.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(loginBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %s", w.Body.String())
	}

	// ユーザー名更新テスト： "olduser" → "newuser"
	updatePayload := map[string]string{
		"newUsername": "newuser",
	}
	updateBytes, _ := json.Marshal(updatePayload)
	req, _ = http.NewRequest("PUT", "/api/auth/update-username", bytes.NewBuffer(updateBytes))
	req.Header.Set("Content-Type", "application/json")
	// ログイン時に得たCookieを付与
	for _, cookie := range w.Result().Cookies() {
		req.AddCookie(cookie)
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected update username status 200, got %d: %s", w.Code, w.Body.String())
	}

	// DB上でユーザー名が更新されているか確認
	var updatedUser models.User
	if err := db.First(&updatedUser, user.ID).Error; err != nil {
		t.Fatalf("failed to retrieve updated user: %v", err)
	}
	if updatedUser.Username != "newuser" {
		t.Fatalf("expected username to be updated to 'newuser', got: %s", updatedUser.Username)
	}
}

func TestDeleteAccount(t *testing.T) {
	router := setupRouter()
	db := setupTestDB(t)
	// 初期化：テスト用の一時ディレクトリ
	testStoragePath := filepath.Join("/tmp", "local_test_storage")
	db.AutoMigrate(&models.User{}, &models.Repository{}, &models.File{})
	controllers.FileStorage = storage.NewLocalStorage(testStoragePath)

	// テストユーザーおよびレポジトリの作成
	user := models.User{Username: "deleteuser", Password: "password123"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	repo := models.Repository{OwnerID: user.ID, Name: "Test Repo", Public: false}
	if err := db.Create(&repo).Error; err != nil {
		t.Fatalf("failed to create test repository: %v", err)
	}

	// ログインリクエストでセッションCookieを取得
	loginPayload := map[string]string{
		"username": "deleteuser",
		"password": "password123",
	}
	loginBytes, _ := json.Marshal(loginPayload)
	req, _ := http.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(loginBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %s", w.Body.String())
	}

	// 退会（DeleteAccount）のテスト
	req, _ = http.NewRequest("DELETE", "/api/auth/delete-account", nil)
	for _, cookie := range w.Result().Cookies() {
		req.AddCookie(cookie)
	}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected delete account status 200, got %d: %s", w.Code, w.Body.String())
	}

	// DB上でユーザーが削除されているか確認
	var count int64
	if err := db.Model(&models.User{}).Where("id = ?", user.ID).Count(&count).Error; err != nil {
		t.Fatalf("failed to check user deletion: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected user to be deleted, count: %d", count)
	}
}
