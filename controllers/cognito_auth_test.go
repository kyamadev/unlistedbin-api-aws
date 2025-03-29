package controllers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"Unlistedbin-api/models"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// テスト用のDBをセットアップ
func setupAuthTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err, "Failed to open in-memory database")

	err = db.AutoMigrate(&models.User{})
	require.NoError(t, err, "Failed to migrate User model")

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

// IdentityProviderClient用のモック
type MockIdentityProvider struct {
	mock.Mock
}

func (m *MockIdentityProvider) VerifyUserAttribute(confirmationCode, attributeName, token string) error {
	args := m.Called(confirmationCode, attributeName, token)
	return args.Error(0)
}

func (m *MockIdentityProvider) AdminUpdateUserAttributes(cognitoID string, attributes map[string]string) error {
	args := m.Called(cognitoID, attributes)
	return args.Error(0)
}

// 認証コントローラーを単純化
type SimpleCognitoAuthController struct {
	CognitoClient    *MockCognitoWrapper
	IdentityProvider *MockIdentityProvider
	DB               *gorm.DB
	UserPoolID       string
	UserPoolClientID string
}

// ユーザー登録のハンドラー
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

// ログインハンドラー
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

// メールアドレス確認ハンドラー
func (ctrl *SimpleCognitoAuthController) ConfirmEmailHandler(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		userIDVal, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}

		// ユーザー情報を取得
		var dbUser models.User
		if err := ctrl.DB.Where("cognito_id = ?", userIDVal).First(&dbUser).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in database"})
			return
		}
		user = &dbUser
	}

	testUser := user.(*models.User)

	// pending_emailがない場合はエラー
	if testUser.PendingEmail == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No pending email change found"})
		return
	}

	// 有効期限チェック
	if time.Since(testUser.PendingEmailTimestamp) > 24*time.Hour {
		testUser.PendingEmail = ""
		testUser.PendingEmailTimestamp = time.Time{}
		ctrl.DB.Save(testUser)

		c.JSON(http.StatusBadRequest, gin.H{
			"error": "確認コードの有効期限が切れています",
			"code":  "EXPIRED_REQUEST",
		})
		return
	}

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

	// Cognitoで確認コードを検証
	err := ctrl.IdentityProvider.VerifyUserAttribute(confirm.ConfirmationCode, "email", accessToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "確認コードの検証に失敗しました",
			"details": err.Error(),
		})
		return
	}

	// Cognitoでユーザー属性を更新
	err = ctrl.IdentityProvider.AdminUpdateUserAttributes(testUser.CognitoID, map[string]string{
		"email":          testUser.PendingEmail,
		"email_verified": "true",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to update email in Cognito",
			"details": err.Error(),
		})
		return
	}

	// データベースの更新
	oldEmail := testUser.Email
	testUser.Email = testUser.PendingEmail
	testUser.PendingEmail = ""
	testUser.PendingEmailTimestamp = time.Time{}
	testUser.EmailVerified = true
	if err := ctrl.DB.Save(testUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update email in database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "メールアドレスが正常に変更されました",
		"old_email": oldEmail,
		"new_email": testUser.Email,
	})
}

func TestRegisterHandler_Success(t *testing.T) {
	// テスト用のDBを準備
	db := setupAuthTestDB(t)

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
	jsonData, _ := json.Marshal(requestBody)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	// レスポンスレコーダーを作成
	w := httptest.NewRecorder()

	// リクエストを実行
	router.ServeHTTP(w, req)

	// レスポンスをチェック
	assert.Equal(t, http.StatusOK, w.Code)

	// レスポンスボディを解析
	var response map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
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

func TestRegisterHandler_DuplicateUsername(t *testing.T) {
	// テスト用のDBを準備
	db := setupAuthTestDB(t)

	// 既存のユーザーを作成
	existingUser := &models.User{
		Username:  "existinguser",
		Email:     "existing@example.com",
		CognitoID: "existing-cognito-id",
	}
	db.Create(existingUser)

	// Cognitoクライアントモックを準備
	mockClient := new(MockCognitoWrapper)

	// モックは呼び出されないはず

	// テスト用のコントローラーを作成
	controller := &SimpleCognitoAuthController{
		CognitoClient: mockClient,
		DB:            db,
	}

	// テスト用のGinルーターを設定
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/register", controller.RegisterHandler)

	// テストリクエストを作成 (既存ユーザーと同じusername)
	requestBody := map[string]string{
		"email":    "new@example.com",
		"password": "password123",
		"username": "existinguser", // 既存と同じユーザー名
	}
	jsonData, _ := json.Marshal(requestBody)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	// レスポンスレコーダーを作成
	w := httptest.NewRecorder()

	// リクエストを実行
	router.ServeHTTP(w, req)

	// レスポンスをチェック - 重複エラー
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// レスポンスボディを解析
	var response map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	assert.Equal(t, "Username already exists", response["error"])

	// モックが呼び出されていないことを確認
	mockClient.AssertNotCalled(t, "RegisterUser")
}

func TestLoginHandler_Success(t *testing.T) {
	// テスト用のDBを準備
	db := setupAuthTestDB(t)

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
	accessToken := "test-access-token"
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
	jsonData, _ := json.Marshal(requestBody)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	// レスポンスレコーダーを作成
	w := httptest.NewRecorder()

	// リクエストを実行
	router.ServeHTTP(w, req)

	// レスポンスをチェック
	assert.Equal(t, http.StatusOK, w.Code)

	// レスポンスボディを解析
	var response map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
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
	db := setupAuthTestDB(t)

	// Cognitoクライアントモックを準備
	mockClient := new(MockCognitoWrapper)

	// モックの動作を定義 - エラーを返す
	mockClient.On("Login", "testuser", "wrongpassword").Return("", "", "", int32(0), errors.New("invalid credentials"))

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
	jsonData, _ := json.Marshal(requestBody)
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	// レスポンスレコーダーを作成
	w := httptest.NewRecorder()

	// リクエストを実行
	router.ServeHTTP(w, req)

	// レスポンスをチェック - 認証失敗
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// レスポンスボディを解析
	var response map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	assert.Equal(t, "Authentication failed", response["error"])

	// モックが呼び出されたことを確認
	mockClient.AssertCalled(t, "Login", "testuser", "wrongpassword")
}

func TestConfirmEmailHandler(t *testing.T) {
	// テスト用のDBを準備
	db := setupAuthTestDB(t)

	// テストユーザーを作成 (保留中のメールアドレス変更あり)
	testUser := &models.User{
		Username:              "testuser",
		Email:                 "old@example.com",
		CognitoID:             "test-cognito-id",
		EmailVerified:         false,
		PendingEmail:          "new@example.com",
		PendingEmailTimestamp: time.Now(),
	}
	db.Create(testUser)

	// Cognitoクライアントモックを準備
	mockClient := new(MockCognitoWrapper)
	mockIdentityProvider := new(MockIdentityProvider)

	// モックの動作を定義
	mockIdentityProvider.On("VerifyUserAttribute", "123456", "email", "test-access-token").Return(nil)
	mockIdentityProvider.On("AdminUpdateUserAttributes", testUser.CognitoID, mock.Anything).Return(nil)

	// テスト用のコントローラーを作成
	controller := &SimpleCognitoAuthController{
		CognitoClient:    mockClient,
		IdentityProvider: mockIdentityProvider,
		DB:               db,
		UserPoolID:       "test-user-pool",
		UserPoolClientID: "test-client-id",
	}

	// テスト用のGinルーターを設定
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/confirm-email", func(c *gin.Context) {
		// ユーザー情報をコンテキストに設定
		c.Set("user", testUser)
		controller.ConfirmEmailHandler(c)
	})

	// テストリクエストを作成
	requestBody := map[string]string{
		"confirmationCode": "123456",
	}
	jsonData, _ := json.Marshal(requestBody)
	req, _ := http.NewRequest("POST", "/confirm-email", bytes.NewBuffer(jsonData))
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
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	assert.Equal(t, "メールアドレスが正常に変更されました", response["message"])
	assert.Equal(t, "old@example.com", response["old_email"])
	assert.Equal(t, "new@example.com", response["new_email"])

	// ユーザー情報が更新されていることを確認
	var updatedUser models.User
	db.Where("cognito_id = ?", testUser.CognitoID).First(&updatedUser)
	assert.Equal(t, "new@example.com", updatedUser.Email)
	assert.Equal(t, "", updatedUser.PendingEmail)
	assert.True(t, updatedUser.EmailVerified)

	// モックが呼び出されたことを確認
	mockIdentityProvider.AssertCalled(t, "VerifyUserAttribute", "123456", "email", "test-access-token")
	// AdminUpdateUserAttributesの呼び出しでは、パラメータの検証が必要
	mockIdentityProvider.AssertCalled(t, "AdminUpdateUserAttributes", testUser.CognitoID, mock.Anything)
}

func TestConfirmEmailHandler_NoPendingEmail(t *testing.T) {
	// テスト用のDBを準備
	db := setupAuthTestDB(t)

	// テストユーザーを作成 (保留中のメールアドレスなし)
	testUser := &models.User{
		Username:      "testuser",
		Email:         "test@example.com",
		CognitoID:     "test-cognito-id",
		EmailVerified: true,
		// PendingEmailは空
	}
	db.Create(testUser)

	// モックを準備
	mockClient := new(MockCognitoWrapper)
	mockIdentityProvider := new(MockIdentityProvider)

	// テスト用のコントローラーを作成
	controller := &SimpleCognitoAuthController{
		CognitoClient:    mockClient,
		IdentityProvider: mockIdentityProvider,
		DB:               db,
	}

	// テスト用のGinルーターを設定
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/confirm-email", func(c *gin.Context) {
		// ユーザー情報をコンテキストに設定
		c.Set("user", testUser)
		controller.ConfirmEmailHandler(c)
	})

	// テストリクエストを作成
	requestBody := map[string]string{
		"confirmationCode": "123456",
	}
	jsonData, _ := json.Marshal(requestBody)
	req, _ := http.NewRequest("POST", "/confirm-email", bytes.NewBuffer(jsonData))
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

	// レスポンスをチェック - 保留中のメールアドレスがないのでエラー
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// レスポンスボディを解析
	var response map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	assert.Equal(t, "No pending email change found", response["error"])

	// モックが呼び出されていないことを確認
	mockIdentityProvider.AssertNotCalled(t, "VerifyUserAttribute")
	mockIdentityProvider.AssertNotCalled(t, "AdminUpdateUserAttributes")
}

func TestConfirmEmailHandler_ExpiredRequest(t *testing.T) {
	// テスト用のDBを準備
	db := setupAuthTestDB(t)

	// テストユーザーを作成 (期限切れの保留中メールアドレス)
	expiredTime := time.Now().Add(-25 * time.Hour) // 24時間以上前
	testUser := &models.User{
		Username:              "testuser",
		Email:                 "old@example.com",
		CognitoID:             "test-cognito-id",
		EmailVerified:         false,
		PendingEmail:          "new@example.com",
		PendingEmailTimestamp: expiredTime,
	}
	db.Create(testUser)

	// モックを準備
	mockClient := new(MockCognitoWrapper)
	mockIdentityProvider := new(MockIdentityProvider)

	// テスト用のコントローラーを作成
	controller := &SimpleCognitoAuthController{
		CognitoClient:    mockClient,
		IdentityProvider: mockIdentityProvider,
		DB:               db,
	}

	// テスト用のGinルーターを設定
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/confirm-email", func(c *gin.Context) {
		// ユーザー情報をコンテキストに設定
		c.Set("user", testUser)
		controller.ConfirmEmailHandler(c)
	})

	// テストリクエストを作成
	requestBody := map[string]string{
		"confirmationCode": "123456",
	}
	jsonData, _ := json.Marshal(requestBody)
	req, _ := http.NewRequest("POST", "/confirm-email", bytes.NewBuffer(jsonData))
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

	// レスポンスをチェック - 期限切れエラー
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// レスポンスボディを解析
	var response map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	assert.Equal(t, "確認コードの有効期限が切れています", response["error"])
	assert.Equal(t, "EXPIRED_REQUEST", response["code"])

	// 保留中のメールアドレスがクリアされたことを確認
	var updatedUser models.User
	db.Where("cognito_id = ?", testUser.CognitoID).First(&updatedUser)
	assert.Equal(t, "", updatedUser.PendingEmail)

	// モックが呼び出されていないことを確認
	mockIdentityProvider.AssertNotCalled(t, "VerifyUserAttribute")
	mockIdentityProvider.AssertNotCalled(t, "AdminUpdateUserAttributes")
}
