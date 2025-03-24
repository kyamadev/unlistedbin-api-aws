package middleware

import (
	"testing"

	"Unlistedbin-api/models"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// テスト用のDBセットアップ
func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}

	err = db.AutoMigrate(&models.User{})
	if err != nil {
		t.Fatalf("Failed to migrate User model: %v", err)
	}

	return db
}

// テスト用のGinコンテキスト作成
func setupGinContext() *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(nil)
	return c
}

// モック用のDB
type MockDB struct {
	mock.Mock
}

func (m *MockDB) Where(query interface{}, args ...interface{}) *gorm.DB {
	m.Called(query, args)
	return nil
}

func (m *MockDB) First(dest interface{}, conds ...interface{}) *gorm.DB {
	m.Called(dest, conds)
	return nil
}

func (m *MockDB) Create(value interface{}) *gorm.DB {
	m.Called(value)
	return nil
}

func TestGetUserFromContext_ExistingUser(t *testing.T) {
	// テスト用DBをセットアップ
	db := setupTestDB(t)

	// テストユーザーを作成
	testUser := &models.User{
		Username:  "testuser",
		Email:     "test@example.com",
		CognitoID: "cognito123",
	}
	db.Create(testUser)

	// Ginコンテキストを設定
	c := setupGinContext()
	c.Set("userID", "cognito123")
	c.Set("email", "test@example.com")
	c.Set("username", "testuser")

	// テスト実行
	user, err := GetUserFromContext(c, db)

	// アサーション
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "cognito123", user.CognitoID)
}

func TestGetUserFromContext_NonExistingUser_AutoCreation(t *testing.T) {
	// テスト用DBをセットアップ
	db := setupTestDB(t)

	// Ginコンテキストを設定
	c := setupGinContext()
	c.Set("userID", "newcognito456")
	c.Set("email", "new@example.com")
	c.Set("username", "newuser")

	// テスト実行
	user, err := GetUserFromContext(c, db)

	// アサーション
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "newuser", user.Username)
	assert.Equal(t, "new@example.com", user.Email)
	assert.Equal(t, "newcognito456", user.CognitoID)

	// DBに新しいユーザーが作成されたことを確認
	var savedUser models.User
	result := db.Where("cognito_id = ?", "newcognito456").First(&savedUser)
	assert.Equal(t, nil, result.Error)
	assert.Equal(t, "newuser", savedUser.Username)
}

func TestGetUserFromContext_MissingUserID(t *testing.T) {
	// テスト用DBをセットアップ
	db := setupTestDB(t)

	// ユーザーIDなしでGinコンテキストを設定
	c := setupGinContext()

	// テスト実行
	user, err := GetUserFromContext(c, db)

	// アサーション
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "user ID not found")
}

func TestGetUserFromContext_MissingEmailAndUsername(t *testing.T) {
	// テスト用DBをセットアップ
	db := setupTestDB(t)

	// Ginコンテキストを設定 (ユーザーIDのみ)
	c := setupGinContext()
	c.Set("userID", "cognito789")

	// テスト実行
	user, err := GetUserFromContext(c, db)

	// アサーション
	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Contains(t, err.Error(), "insufficient information")
}

func TestGetUserIDFromContext(t *testing.T) {
	// テスト用DBをセットアップ
	db := setupTestDB(t)

	// テストユーザーを作成
	testUser := &models.User{
		Username:  "testuser",
		Email:     "test@example.com",
		CognitoID: "cognito123",
	}
	db.Create(testUser)

	// Ginコンテキストを設定
	c := setupGinContext()
	c.Set("userID", "cognito123")

	// テスト実行
	userID, err := GetUserIDFromContext(c, db)

	// アサーション
	assert.NoError(t, err)
	assert.NotEqual(t, uint(0), userID)

	// 新しいユーザーの自動作成も確認
	c = setupGinContext()
	c.Set("userID", "newuser999")
	c.Set("email", "auto@example.com")
	c.Set("username", "autouser")

	userID, err = GetUserIDFromContext(c, db)
	assert.NoError(t, err)
	assert.NotEqual(t, uint(0), userID)
}

func TestOwnershipCheck(t *testing.T) {
	// テスト用DBをセットアップ
	db := setupTestDB(t)

	// テストユーザーを作成
	testUser := &models.User{
		Username:  "testuser",
		Email:     "test@example.com",
		CognitoID: "cognito123",
	}
	db.Create(testUser)

	// Ginコンテキストを設定
	c := setupGinContext()
	c.Set("userID", "cognito123")

	// テスト実行 - 自分のリソース
	isOwner, err := OwnershipCheck(c, db, testUser.ID)

	// アサーション
	assert.NoError(t, err)
	assert.True(t, isOwner)

	// テスト実行 - 他人のリソース
	isOwner, err = OwnershipCheck(c, db, testUser.ID+1)
	assert.NoError(t, err)
	assert.False(t, isOwner)
}
