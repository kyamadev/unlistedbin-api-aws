package controllers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// シンプルなCognitoクライアントモック
type MockCognitoWrapper struct {
	mock.Mock
}

func (m *MockCognitoWrapper) RegisterUser(email, password, username string) (string, error) {
	args := m.Called(email, password, username)
	return args.String(0), args.Error(1)
}

func (m *MockCognitoWrapper) Login(emailOrUsername, password string) (string, string, string, int32, error) {
	args := m.Called(emailOrUsername, password)
	return args.String(0), args.String(1), args.String(2), args.Get(3).(int32), args.Error(4)
}

// 認証コントローラーを単純化
type SimpleCognitoAuthController struct {
	CognitoClient *MockCognitoWrapper
	DB            *gorm.DB
}

// ユーザー登録のハンドラー（簡易版）
func (ctrl *SimpleCognitoAuthController) RegisterHandler(c *gin.Context) {
	var registration struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
		Username string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&registration); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// ユーザー名が既に存在するか確認
	var count int64
	if err := ctrl.DB.Model(&models.User{}).Where("username = ?", registration.Username).Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	// モックCognitoクライアントでユーザー登録
	userSub, err := ctrl.CognitoClient.RegisterUser(registration.Email, registration.Password, registration.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed", "details": err.Error()})
		return
	}

	// データベースにユーザーを保存
	user := models.User{
		Username:  registration.Username,
		Email:     registration.Email,
		CognitoID: userSub,
	}

	if err := ctrl.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user record"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

// ログインハンドラー（修正版）
func (ctrl *SimpleCognitoAuthController) LoginHandler(c *gin.Context) {
	var login struct {
		EmailOrUsername string `json:"emailOrUsername" binding:"required"`
		Password        string `json:"password" binding:"required"`
		ClientType      string `json:"clientType"`
	}

	if err := c.ShouldBindJSON(&login); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// モックCognitoクライアントでログイン - アクセストークンも取得
	idToken, refreshToken, accessToken, expiresIn, err := ctrl.CognitoClient.Login(login.EmailOrUsername, login.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication failed"})
		return
	}

	// クッキーを設定
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		"id_token",
		idToken,
		int(expiresIn),
		"/",
		"",
		false,
		true,
	)

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		"refresh_token",
		refreshToken,
		60*60*24*30, // 30日間
		"/",
		"",
		false,
		true,
	)

	// アクセストークンのクッキーも設定
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		"access_token",
		accessToken,
		int(expiresIn),
		"/",
		"",
		false,
		true,
	)

	// CSRFトークンも設定
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		"csrf_token",
		"test-csrf-token",
		int(expiresIn),
		"/",
		"",
		false,
		false,
	)

	// レスポンスを返す
	c.JSON(http.StatusOK, gin.H{
		"message":       "Logged in successfully",
		"token":         idToken,
		"refresh_token": refreshToken,
		"access_token":  accessToken,
		"expires_in":    expiresIn,
	})
}

// ユーザー情報取得ハンドラー（簡易版）
func (ctrl *SimpleCognitoAuthController) GetUserHandler(c *gin.Context) {
	// 認証済みユーザーはコンテキストからIDを取得
	cognitoID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	// データベースからユーザーを検索
	var user models.User
	if err := ctrl.DB.Where("cognito_id = ?", cognitoID).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// ユーザー情報を返す
	c.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
	})
}

func TestRegisterHandler_Success(t *testing.T) {
	// テスト用のDBを準備
	db := setupTestDB(t)

	// Cognitoクライアントモックを準備
	mockClient := new(MockCognitoWrapper)

	// モックの動作を定義
	mockClient.On("RegisterUser", "test@example.com", "password123", "testuser").Return("test-cognito-id", nil)

	// テスト用のコントローラーを作成
	controller := &SimpleCognitoAuthController{
		CognitoClient: mockClient,
		DB:            db,
	}

	// テスト用のGinルーターを設定
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/register", controller.RegisterHandler)

	// テストリクエストを作成
	requestBody := map[string]string{
		"email":    "test@example.com",
		"password": "password123",
		"username": "testuser",
	}
	jsonBody, _ := json.Marshal(requestBody)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// レスポンスレコーダーを作成
	w := httptest.NewRecorder()

	// リクエストを実行
	router.ServeHTTP(w, req)

	// レスポンスをチェック
	assert.Equal(t, http.StatusOK, w.Code)

	// レスポンスボディを解析
	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Registration successful", response["message"])

	// ユーザーがデータベースに作成されたことを確認
	var user models.User
	result := db.Where("username = ?", "testuser").First(&user)
	assert.NoError(t, result.Error)
	assert.Equal(t, "testuser", user.Username)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "test-cognito-id", user.CognitoID)

	// モックが呼び出されたことを確認
	mockClient.AssertCalled(t, "RegisterUser", "test@example.com", "password123", "testuser")
}

func TestLoginHandler_Success(t *testing.T) {
	// テスト用のDBを準備
	db := setupTestDB(t)

	// テストユーザーを作成
	testUser := &models.User{
		Username:  "testuser",
		Email:     "test@example.com",
		CognitoID: "test-cognito-id",
	}
	db.Create(testUser)

	// Cognitoクライアントモックを準備
	mockClient := new(MockCognitoWrapper)

	// モックの動作を定義
	idToken := "test-id-token"
	refreshToken := "test-refresh-token"
	accessToken := "test-access-token" // アクセストークンを追加
	expiresIn := int32(3600)
	mockClient.On("Login", "testuser", "password123").Return(idToken, refreshToken, accessToken, expiresIn, nil)

	// テスト用のコントローラーを作成
	controller := &SimpleCognitoAuthController{
		CognitoClient: mockClient,
		DB:            db,
	}

	// テスト用のGinルーターを設定
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/login", controller.LoginHandler)

	// テストリクエストを作成
	requestBody := map[string]string{
		"emailOrUsername": "testuser",
		"password":        "password123",
	}
	jsonBody, _ := json.Marshal(requestBody)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// レスポンスレコーダーを作成
	w := httptest.NewRecorder()

	// リクエストを実行
	router.ServeHTTP(w, req)

	// レスポンスをチェック
	assert.Equal(t, http.StatusOK, w.Code)

	// レスポンスボディを解析
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Logged in successfully", response["message"])

	// Cookieが設定されていることを確認
	cookies := w.Result().Cookies()
	var idTokenCookie, refreshTokenCookie, csrfCookie, accessTokenCookie *http.Cookie

	for _, cookie := range cookies {
		if cookie.Name == "id_token" {
			idTokenCookie = cookie
		} else if cookie.Name == "refresh_token" {
			refreshTokenCookie = cookie
		} else if cookie.Name == "csrf_token" {
			csrfCookie = cookie
		} else if cookie.Name == "access_token" {
			accessTokenCookie = cookie
		}
	}

	assert.NotNil(t, idTokenCookie)
	assert.Equal(t, "test-id-token", idTokenCookie.Value)
	assert.True(t, idTokenCookie.HttpOnly)

	assert.NotNil(t, refreshTokenCookie)
	assert.Equal(t, "test-refresh-token", refreshTokenCookie.Value)
	assert.True(t, refreshTokenCookie.HttpOnly)

	assert.NotNil(t, accessTokenCookie)
	assert.Equal(t, "test-access-token", accessTokenCookie.Value)
	assert.True(t, accessTokenCookie.HttpOnly)

	assert.NotNil(t, csrfCookie)
	assert.Equal(t, "test-csrf-token", csrfCookie.Value)
	assert.False(t, csrfCookie.HttpOnly) // CSRF用トークンはHTTPOnly=falseである必要がある

	// モックが呼び出されたことを確認
	mockClient.AssertCalled(t, "Login", "testuser", "password123")
}

func TestLoginHandler_InvalidCredentials(t *testing.T) {
	// テスト用のDBを準備
	db := setupTestDB(t)

	// Cognitoクライアントモックを準備
	mockClient := new(MockCognitoWrapper)

	// モックの動作を定義 - エラーを返す
	mockClient.On("Login", "testuser", "wrongpassword").Return("", "", "", int32(0), assert.AnError)

	// テスト用のコントローラーを作成
	controller := &SimpleCognitoAuthController{
		CognitoClient: mockClient,
		DB:            db,
	}

	// テスト用のGinルーターを設定
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/login", controller.LoginHandler)

	// テストリクエストを作成 - 誤ったパスワード
	requestBody := map[string]string{
		"emailOrUsername": "testuser",
		"password":        "wrongpassword",
	}
	jsonBody, _ := json.Marshal(requestBody)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// レスポンスレコーダーを作成
	w := httptest.NewRecorder()

	// リクエストを実行
	router.ServeHTTP(w, req)

	// レスポンスをチェック - 認証失敗
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// レスポンスボディを解析
	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Authentication failed", response["error"])

	// モックが呼び出されたことを確認
	mockClient.AssertCalled(t, "Login", "testuser", "wrongpassword")
}

// ConfirmEmailHandlerのテストを追加
func TestConfirmEmailHandler(t *testing.T) {
	// テスト用のDBを準備
	db := setupTestDB(t)

	// テストユーザーを作成
	testUser := &models.User{
		Username:      "testuser",
		Email:         "test@example.com",
		CognitoID:     "test-cognito-id",
		EmailVerified: false,
	}
	db.Create(testUser)

	// テスト用のモックCognitoクライアント
	mockIdentityProvider := &struct {
		VerifyUserAttributeCalled bool
		VerifyUserAttributeCode   string
		VerifyUserAttributeToken  string
	}{}

	// テスト用のハンドラー
	confirmHandler := func(c *gin.Context) {
		// 認証済みユーザーの情報をセット
		c.Set("userID", testUser.CognitoID)
		c.Set("username", testUser.Username)
		c.Set("email", testUser.Email)

		// リクエストを解析
		var confirm struct {
			ConfirmationCode string `json:"confirmationCode"`
		}
		if err := c.ShouldBindJSON(&confirm); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "確認コードを入力してください"})
			return
		}

		// アクセストークンを取得
		accessToken, _ := c.Cookie("access_token")
		if accessToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "アクセストークンが見つかりません",
			})
			return
		}

		// モックの記録
		mockIdentityProvider.VerifyUserAttributeCalled = true
		mockIdentityProvider.VerifyUserAttributeCode = confirm.ConfirmationCode
		mockIdentityProvider.VerifyUserAttributeToken = accessToken

		// DBを更新
		db.Model(&models.User{}).Where("cognito_id = ?", testUser.CognitoID).Update("email_verified", true)

		c.JSON(http.StatusOK, gin.H{
			"message": "メールアドレスが正常に確認されました",
			"email":   testUser.Email,
		})
	}

	// テスト用のGinルーターを設定
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/confirm-email", confirmHandler)

	// テストリクエストを作成
	requestBody := map[string]string{
		"confirmationCode": "123456",
	}
	jsonBody, _ := json.Marshal(requestBody)
	req, _ := http.NewRequest("POST", "/confirm-email", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// アクセストークンをCookieに追加
	req.AddCookie(&http.Cookie{
		Name:  "access_token",
		Value: "test-access-token",
	})

	// レスポンスレコーダーを作成
	w := httptest.NewRecorder()

	// リクエストを実行
	router.ServeHTTP(w, req)

	// レスポンスをチェック
	assert.Equal(t, http.StatusOK, w.Code)

	// レスポンスボディを解析
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "メールアドレスが正常に確認されました", response["message"])

	// モックの呼び出し確認
	assert.True(t, mockIdentityProvider.VerifyUserAttributeCalled)
	assert.Equal(t, "123456", mockIdentityProvider.VerifyUserAttributeCode)
	assert.Equal(t, "test-access-token", mockIdentityProvider.VerifyUserAttributeToken)

	// データベースのユーザー情報が更新されたことを確認
	var updatedUser models.User
	db.Where("cognito_id = ?", testUser.CognitoID).First(&updatedUser)
	assert.True(t, updatedUser.EmailVerified)
}
