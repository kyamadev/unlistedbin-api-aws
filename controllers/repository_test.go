package controllers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"Unlistedbin-api/models"
	"Unlistedbin-api/storage"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// テスト用の独立したDBをセットアップ
func setupRepoTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err, "Failed to open in-memory database")

	err = db.AutoMigrate(&models.User{}, &models.Repository{}, &models.File{})
	require.NoError(t, err, "Failed to migrate models")

	return db
}

// JWTトークン認証をモックするミドルウェア
func mockAuthMiddleware(userID uint, username, cognitoID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// ユーザー情報をコンテキストに設定
		c.Set("userID", cognitoID)
		c.Set("username", username)
		c.Next()
	}
}

func TestCreateRepository(t *testing.T) {
	// テスト用DBセットアップ
	db := setupRepoTestDB(t)

	// グローバル変数を一時的に設定
	originalDB := DB
	DB = db
	defer func() {
		DB = originalDB
	}()

	// テスト用ユーザー作成
	testUser := &models.User{
		Username:  "testuser",
		Email:     "test@example.com",
		CognitoID: "test-cognito-id",
	}
	db.Create(testUser)

	// テスト用ルーター設定
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 認証済みユーザーとしてアクセスするルートをセットアップ
	authGroup := router.Group("/")
	authGroup.Use(mockAuthMiddleware(testUser.ID, testUser.Username, testUser.CognitoID))
	authGroup.POST("/api/repositories", CreateRepository)

	// リクエスト作成
	requestBody := map[string]interface{}{
		"name":   "New Test Repo",
		"public": true,
	}
	jsonData, _ := json.Marshal(requestBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/repositories", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	// リクエスト実行
	router.ServeHTTP(w, req)

	// レスポンス検証
	assert.Equal(t, http.StatusOK, w.Code)

	// 返却されたJSONレスポンスを検証
	var response models.Repository
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	assert.Equal(t, "New Test Repo", response.Name)
	assert.True(t, response.Public)
	assert.NotEmpty(t, response.UUID)

	// データベースにリポジトリが作成されたことを確認
	var createdRepo models.Repository
	db.Where("uuid = ?", response.UUID).First(&createdRepo)
	assert.Equal(t, testUser.ID, createdRepo.OwnerID)
	assert.Equal(t, "New Test Repo", createdRepo.Name)
}

func TestGetRepositories(t *testing.T) {
	// テスト用DBセットアップ
	db := setupRepoTestDB(t)

	// グローバル変数を一時的に設定
	originalDB := DB
	DB = db
	defer func() {
		DB = originalDB
	}()

	// テスト用ユーザー作成
	testUser := &models.User{
		Username:  "testuser",
		Email:     "test@example.com",
		CognitoID: "test-cognito-id",
	}
	db.Create(testUser)

	// テスト用リポジトリ作成
	repo1 := &models.Repository{
		Name:    "Repo 1",
		UUID:    "repo-uuid-1",
		OwnerID: testUser.ID,
		Public:  true,
	}
	db.Create(repo1)

	repo2 := &models.Repository{
		Name:    "Repo 2",
		UUID:    "repo-uuid-2",
		OwnerID: testUser.ID,
		Public:  false,
	}
	db.Create(repo2)

	// 別ユーザーのリポジトリ (取得されないはず)
	otherUser := &models.User{
		Username:  "otheruser",
		Email:     "other@example.com",
		CognitoID: "other-cognito-id",
	}
	db.Create(otherUser)

	otherRepo := &models.Repository{
		Name:    "Other Repo",
		UUID:    "other-repo-uuid",
		OwnerID: otherUser.ID,
		Public:  true,
	}
	db.Create(otherRepo)

	// テスト用ルーター設定
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 認証済みユーザーとしてアクセスするルートをセットアップ
	authGroup := router.Group("/")
	authGroup.Use(mockAuthMiddleware(testUser.ID, testUser.Username, testUser.CognitoID))
	authGroup.GET("/api/repositories", GetRepositories)

	// リクエスト実行
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/repositories", nil)
	router.ServeHTTP(w, req)

	// レスポンス検証
	assert.Equal(t, http.StatusOK, w.Code)

	// 返却されたJSONレスポンスを検証
	var response []models.Repository
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))

	// 自分のリポジトリのみ取得できていることを確認
	assert.Equal(t, 2, len(response))

	// 返された各リポジトリを検証
	repoUUIDs := []string{response[0].UUID, response[1].UUID}
	assert.Contains(t, repoUUIDs, repo1.UUID)
	assert.Contains(t, repoUUIDs, repo2.UUID)
	assert.NotContains(t, repoUUIDs, otherRepo.UUID)
}

func TestUpdateVisibility(t *testing.T) {
	// テスト用DBセットアップ
	db := setupRepoTestDB(t)

	// グローバル変数を一時的に設定
	originalDB := DB
	DB = db
	defer func() {
		DB = originalDB
	}()

	// テスト用ユーザー作成
	testUser := &models.User{
		Username:  "testuser",
		Email:     "test@example.com",
		CognitoID: "test-cognito-id",
	}
	db.Create(testUser)

	// テスト用リポジトリ作成 (初期状態は非公開)
	testRepo := &models.Repository{
		Name:    "Test Repo",
		UUID:    "test-repo-uuid",
		OwnerID: testUser.ID,
		Public:  false,
	}
	db.Create(testRepo)

	// テスト用ルーター設定
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 認証済みユーザーとしてアクセスするルートをセットアップ
	authGroup := router.Group("/")
	authGroup.Use(mockAuthMiddleware(testUser.ID, testUser.Username, testUser.CognitoID))
	authGroup.PUT("/api/repositories/:uuid/visibility", UpdateVisibility)

	// 可視性を変更するリクエスト (非公開→公開)
	requestBody := map[string]bool{
		"public": true,
	}
	jsonData, _ := json.Marshal(requestBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/api/repositories/"+testRepo.UUID+"/visibility", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	// リクエスト実行
	router.ServeHTTP(w, req)

	// レスポンス検証
	assert.Equal(t, http.StatusOK, w.Code)

	// データベースの値が更新されているか確認
	var updatedRepo models.Repository
	db.Where("uuid = ?", testRepo.UUID).First(&updatedRepo)
	assert.True(t, updatedRepo.Public)

	// 返却されたJSONレスポンスを検証
	var response models.Repository
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	assert.Equal(t, testRepo.UUID, response.UUID)
	assert.True(t, response.Public)
}

func TestUpdateDownloadPermission(t *testing.T) {
	// テスト用DBセットアップ
	db := setupRepoTestDB(t)

	// グローバル変数を一時的に設定
	originalDB := DB
	DB = db
	defer func() {
		DB = originalDB
	}()

	// テスト用ユーザー作成
	testUser := &models.User{
		Username:  "testuser",
		Email:     "test@example.com",
		CognitoID: "test-cognito-id",
	}
	db.Create(testUser)

	// テスト用リポジトリ作成
	testRepo := &models.Repository{
		Name:            "Test Repo",
		UUID:            "test-repo-uuid",
		OwnerID:         testUser.ID,
		Public:          true,
		DownloadAllowed: false, // 初期値はfalse
	}
	db.Create(testRepo)

	// テスト用ルーター設定
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 認証済みユーザーとしてアクセスするルートをセットアップ
	authGroup := router.Group("/")
	authGroup.Use(mockAuthMiddleware(testUser.ID, testUser.Username, testUser.CognitoID))
	authGroup.PUT("/api/repositories/:uuid/download-permission", UpdateDownloadPermission)

	// リクエスト作成
	requestBody := map[string]bool{
		"download_allowed": true,
	}
	jsonData, _ := json.Marshal(requestBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/api/repositories/"+testRepo.UUID+"/download-permission", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	// リクエスト実行
	router.ServeHTTP(w, req)

	// レスポンス検証
	assert.Equal(t, http.StatusOK, w.Code)

	// データベースの値が更新されているか確認
	var updatedRepo models.Repository
	db.Where("uuid = ?", testRepo.UUID).First(&updatedRepo)
	assert.True(t, updatedRepo.DownloadAllowed)

	// 返却されたJSONレスポンスを検証
	var response models.Repository
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	assert.Equal(t, testRepo.UUID, response.UUID)
	assert.True(t, response.DownloadAllowed)
}

func TestUpdateDownloadPermission_NotOwner(t *testing.T) {
	// テスト用DBセットアップ
	db := setupRepoTestDB(t)

	// グローバル変数を一時的に設定
	originalDB := DB
	DB = db
	defer func() {
		DB = originalDB
	}()

	// テスト用ユーザー作成
	owner := &models.User{
		Username:  "owner",
		Email:     "owner@example.com",
		CognitoID: "owner-cognito-id",
	}
	db.Create(owner)

	otherUser := &models.User{
		Username:  "other",
		Email:     "other@example.com",
		CognitoID: "other-cognito-id",
	}
	db.Create(otherUser)

	// テスト用リポジトリ作成
	testRepo := &models.Repository{
		Name:            "Test Repo",
		UUID:            "test-repo-uuid",
		OwnerID:         owner.ID, // ownerが所有
		Public:          true,
		DownloadAllowed: false,
	}
	db.Create(testRepo)

	// テスト用ルーター設定
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 別のユーザーとしてアクセスするルートをセットアップ
	authGroup := router.Group("/")
	authGroup.Use(mockAuthMiddleware(otherUser.ID, otherUser.Username, otherUser.CognitoID))
	authGroup.PUT("/api/repositories/:uuid/download-permission", UpdateDownloadPermission)

	// リクエスト作成
	requestBody := map[string]bool{
		"download_allowed": true,
	}
	jsonData, _ := json.Marshal(requestBody)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("PUT", "/api/repositories/"+testRepo.UUID+"/download-permission", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	// リクエスト実行
	router.ServeHTTP(w, req)

	// レスポンス検証 - 所有者でないためエラー
	assert.Equal(t, http.StatusForbidden, w.Code)

	// データベースの値が変更されていないことを確認
	var unchangedRepo models.Repository
	db.Where("uuid = ?", testRepo.UUID).First(&unchangedRepo)
	assert.False(t, unchangedRepo.DownloadAllowed)
}

func TestDeleteRepository(t *testing.T) {
	// テスト用DBセットアップ
	db := setupRepoTestDB(t)

	// テスト用ストレージをセットアップ
	tempDir, err := os.MkdirTemp("", "test-repo-delete-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	fileStorage := storage.NewLocalStorage(tempDir)

	// グローバル変数を一時的に設定
	originalDB := DB
	originalStorage := FileStorage
	DB = db
	FileStorage = fileStorage
	defer func() {
		DB = originalDB
		FileStorage = originalStorage
	}()

	// テスト用ユーザー作成
	testUser := &models.User{
		Username:  "testuser",
		Email:     "test@example.com",
		CognitoID: "test-cognito-id",
	}
	db.Create(testUser)

	// テスト用リポジトリ作成
	testRepo := &models.Repository{
		Name:    "Repo To Delete",
		UUID:    "repo-to-delete-uuid",
		OwnerID: testUser.ID,
		Public:  true,
	}
	db.Create(testRepo)

	// テスト用ファイル作成
	repoDir := filepath.Join(tempDir, testRepo.UUID)
	require.NoError(t, os.MkdirAll(repoDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "test.txt"), []byte("Test content"), 0644))

	testFile := &models.File{
		RepositoryID: testRepo.ID,
		FileName:     "test.txt",
		FilePath:     filepath.Join(repoDir, "test.txt"),
	}
	db.Create(testFile)

	// テスト用ルーター設定
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// 認証済みユーザーとしてアクセスするルートをセットアップ
	authGroup := router.Group("/")
	authGroup.Use(mockAuthMiddleware(testUser.ID, testUser.Username, testUser.CognitoID))
	authGroup.DELETE("/api/repositories/:uuid", DeleteRepository)

	// リクエスト実行
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/api/repositories/"+testRepo.UUID, nil)
	router.ServeHTTP(w, req)

	// レスポンス検証
	assert.Equal(t, http.StatusOK, w.Code)

	// レスポンスボディ検証
	var response map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	assert.Equal(t, "Repository deleted", response["message"])
	assert.Equal(t, testRepo.UUID, response["repo_uuid"])

	// データベースからリポジトリが削除されたことを確認 - 少し待機を追加
	time.Sleep(100 * time.Millisecond) // 短い待機を追加してトランザクションが確実に完了するようにする

	var deletedRepo models.Repository
	result := db.Unscoped().Where("uuid = ?", testRepo.UUID).First(&deletedRepo)
	assert.Error(t, result.Error)
	assert.True(t, errors.Is(result.Error, gorm.ErrRecordNotFound))

	// ストレージからも削除されたことを確認
	_, err = os.Stat(repoDir)
	assert.True(t, os.IsNotExist(err))

	// 関連するファイルレコードも削除されたことを確認
	var count int64
	db.Model(&models.File{}).Where("repository_id = ?", testRepo.ID).Count(&count)
	assert.Equal(t, int64(0), count)
}
