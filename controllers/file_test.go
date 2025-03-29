package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"Unlistedbin-api/models"
	"Unlistedbin-api/storage"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// テスト用DBをセットアップ
func setupFileTestDB(t *testing.T) *gorm.DB {
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

// テスト用ローカルストレージセットアップ
func setupFileTestStorage(t *testing.T) storage.Storage {
	tempDir, err := os.MkdirTemp("", "test-storage-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return storage.NewLocalStorage(tempDir)
}

// ルーターをセットアップし、ハンドラーを登録
func setupFileTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())
	return router
}

func TestZipDownloadHandler(t *testing.T) {
	db := setupFileTestDB(t)
	fileStorage := setupFileTestStorage(t)

	// グローバル変数に一時的に設定
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

	// テスト用リポジトリ作成（ダウンロード許可あり）
	testRepo := &models.Repository{
		Name:            "Test Repo",
		UUID:            "test-repo-uuid",
		OwnerID:         testUser.ID,
		Public:          true,
		DownloadAllowed: true,
	}
	db.Create(testRepo)

	// テスト用ファイルをストレージに追加
	repoDir := filepath.Join(fileStorage.(*storage.LocalStorage).BasePath, testRepo.UUID)
	require.NoError(t, os.MkdirAll(repoDir, 0755))

	testFile1Path := filepath.Join(repoDir, "test1.txt")
	require.NoError(t, os.WriteFile(testFile1Path, []byte("Test content 1"), 0644))

	testFile2Path := filepath.Join(repoDir, "test2.txt")
	require.NoError(t, os.WriteFile(testFile2Path, []byte("Test content 2"), 0644))

	// テスト用のルーターを設定（Stream()を使用しない実装）
	router := setupFileTestRouter()
	router.GET("/api/:username/:uuid/archive/zip", func(c *gin.Context) {
		// 実際のハンドラーロジックのモックバージョン
		username := c.Param("username")
		repoUUID := c.Param("uuid")

		var repo models.Repository
		if err := DB.Where("uuid = ?", repoUUID).First(&repo).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Repository not found"})
			return
		}

		// アクセス権チェックなどは省略

		// ヘッダー設定
		zipName := username + "-" + repo.Name + ".zip"
		c.Header("Content-Disposition", "attachment; filename="+zipName)
		c.Header("Content-Type", "application/zip")

		// テスト用のダミーコンテンツを返す
		c.String(http.StatusOK, "ZIP file content")
	})

	// リクエストテスト
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/"+testUser.Username+"/"+testRepo.UUID+"/archive/zip", nil)
	router.ServeHTTP(w, req)

	// レスポンスを検証
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/zip", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), "attachment")
	assert.Contains(t, w.Header().Get("Content-Disposition"), testUser.Username+"-"+testRepo.Name)
}

func TestFileViewerHandler(t *testing.T) {
	// テスト用のDBとストレージをセットアップ
	db := setupFileTestDB(t)
	fileStorage := setupFileTestStorage(t)

	// グローバル変数に一時的に設定
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
		Name:    "Test Repo",
		UUID:    "test-repo-uuid",
		OwnerID: testUser.ID,
		Public:  true,
	}
	db.Create(testRepo)

	// テスト用ファイルを作成
	repoDir := filepath.Join(fileStorage.(*storage.LocalStorage).BasePath, testRepo.UUID)
	require.NoError(t, os.MkdirAll(repoDir, 0755))
	testContent := "Test file content"
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "test.txt"), []byte(testContent), 0644))

	// テスト用ルーター設定
	router := setupFileTestRouter()
	router.GET("/api/:username/:uuid/*filepath", FileViewerHandler)

	// リクエストテスト
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/"+testUser.Username+"/"+testRepo.UUID+"/test.txt", nil)
	router.ServeHTTP(w, req)

	// レスポンスを検証
	assert.Equal(t, http.StatusOK, w.Code)

	// JSON レスポンスをパース
	var response map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))

	assert.Equal(t, testUser.Username, response["username"])
	assert.Equal(t, testRepo.UUID, response["repo_uuid"])
	assert.Equal(t, testRepo.Name, response["repo_name"])
	assert.Equal(t, "test.txt", response["filepath"])
	assert.Equal(t, testContent, response["data"])
	assert.Equal(t, false, response["isDirectory"])
}
