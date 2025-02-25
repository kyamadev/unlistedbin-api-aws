package controllers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"Unlistedbin-api/models"

	"github.com/gin-gonic/gin"
)

// simulateAuthMiddleware は、テスト用に context に userID を設定するミドルウェアです。
func simulateAuthMiddleware(userID uint) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("userID", userID)
		c.Next()
	}
}

// TestCreateAndGetRepository は、リポジトリ作成と一覧取得が正しく動作するかを検証します。
func TestCreateAndGetRepository(t *testing.T) {
	db := SetupTestDB(t)

	// テストユーザー作成
	testUser := models.User{
		Username: "testuser",
		Password: "dummy",
	}
	if err := db.Create(&testUser).Error; err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	router := gin.Default()
	router.Use(simulateAuthMiddleware(testUser.ID))
	router.POST("/api/repositories", CreateRepository)
	router.GET("/api/repositories", GetRepositories)

	// POST リクエストでリポジトリ作成
	repoPayload := map[string]interface{}{
		"name":   "Test Repository",
		"public": false,
	}
	body, _ := json.Marshal(repoPayload)
	req, _ := http.NewRequest("POST", "/api/repositories", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 on create, got %d", w.Code)
	}

	var createdRepo models.Repository
	if err := json.Unmarshal(w.Body.Bytes(), &createdRepo); err != nil {
		t.Fatalf("failed to unmarshal create response: %v", err)
	}
	if createdRepo.Name != "Test Repository" || createdRepo.Public != false {
		t.Errorf("unexpected repository data: %+v", createdRepo)
	}
	if createdRepo.UUID == "" {
		t.Error("UUID was not generated")
	}

	// GET リクエストでリポジトリ一覧取得
	req2, _ := http.NewRequest("GET", "/api/repositories", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected status 200 on get, got %d", w2.Code)
	}
	var repos []models.Repository
	if err := json.Unmarshal(w2.Body.Bytes(), &repos); err != nil {
		t.Fatalf("failed to unmarshal get response: %v", err)
	}
	if len(repos) != 1 {
		t.Errorf("expected 1 repository, got %d", len(repos))
	}
}

// TestUpdateRepositoryVisibility は、リポジトリの公開設定更新が正しく動作するかを検証します。
func TestUpdateRepositoryVisibility(t *testing.T) {
	db := SetupTestDB(t)
	testUser := models.User{
		Username: "testuser",
		Password: "dummy",
	}
	if err := db.Create(&testUser).Error; err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	repo := models.Repository{
		Name:    "Visibility Repo",
		Public:  false,
		OwnerID: testUser.ID,
	}
	if err := db.Create(&repo).Error; err != nil {
		t.Fatalf("failed to create repository: %v", err)
	}

	router := gin.Default()
	router.Use(simulateAuthMiddleware(testUser.ID))
	router.PUT("/api/repositories/:uuid/visibility", UpdateVisibility)

	payload := map[string]bool{
		"public": true,
	}
	body, _ := json.Marshal(payload)
	url := "/api/repositories/" + repo.UUID + "/visibility"
	req, _ := http.NewRequest("PUT", url, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200 on update, got %d: %s", w.Code, w.Body.String())
	}
	var updatedRepo models.Repository
	if err := json.Unmarshal(w.Body.Bytes(), &updatedRepo); err != nil {
		t.Fatalf("failed to unmarshal update response: %v", err)
	}
	if updatedRepo.Public != true {
		t.Errorf("expected repository public to be true, got %v", updatedRepo.Public)
	}
}
