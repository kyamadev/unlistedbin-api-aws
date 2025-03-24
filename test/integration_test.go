package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"Unlistedbin-api/config"
	"Unlistedbin-api/controllers"
	"Unlistedbin-api/middleware"
	"Unlistedbin-api/models"
	"Unlistedbin-api/storage"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// テスト用インフラストラクチャをセットアップ
type TestInfra struct {
	DB           *gorm.DB
	Router       *gin.Engine
	Server       *httptest.Server
	CookieJar    []*http.Cookie
	CSRFToken    string
	LoggedInUser *models.User
}

func setupTestInfra(t *testing.T) *TestInfra {
	// テスト用環境変数を設定
	os.Setenv("ENV", "test")

	// テスト用設定を読み込み
	config.LoadConfig()

	// テスト用DBをセットアップ
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}

	// テスト用モデルをマイグレーション
	err = db.AutoMigrate(&models.User{}, &models.Repository{}, &models.File{})
	if err != nil {
		t.Fatalf("Failed to migrate models: %v", err)
	}

	// テスト用ストレージをセットアップ
	fileStorage := storage.NewLocalStorage("./test_storage")

	// テスト用ルーターをセットアップ
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// コントローラーにDBとストレージを設定
	controllers.DB = db
	controllers.FileStorage = fileStorage

	// CORSミドルウェアをセットアップ
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "X-CSRF-Token"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// セキュリティミドルウェアをセットアップ
	router.Use(middleware.SecurityHeadersMiddleware())
	// router.Use(middleware.XSSProtectionMiddleware())

	// ダミーJWTバリデーターをセットアップ
	// Remove unused variable
	// jwtValidator := &DummyJWTValidator{}

	// テスト用エンドポイントをセットアップ
	router.POST("/login", func(c *gin.Context) {
		// テスト用の認証処理
		var login struct {
			Username string `json:"emailOrUsername"`
			Password string `json:"password"`
		}

		if err := c.ShouldBindJSON(&login); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// テスト用ユーザーの検証
		var user models.User
		result := db.Where("username = ?", login.Username).First(&user)
		if result.Error != nil || login.Password != "testpassword" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// クッキー設定
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(
			"id_token",
			fmt.Sprintf("dummy_token_%s", user.Username),
			3600,
			"/",
			"",
			false,
			true,
		)

		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(
			"refresh_token",
			fmt.Sprintf("dummy_refresh_%s", user.Username),
			86400,
			"/",
			"",
			false,
			true,
		)

		// CSRFトークン設定
		csrfToken := "test_csrf_token"
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(
			"csrf_token",
			csrfToken,
			3600,
			"/",
			"",
			false,
			false,
		)

		c.JSON(http.StatusOK, gin.H{
			"message": "Logged in successfully",
			"user": gin.H{
				"id":       user.ID,
				"username": user.Username,
				"email":    user.Email,
			},
		})
	})

	// 認証が必要なエンドポイント
	authGroup := router.Group("/api")
	authGroup.Use(func(c *gin.Context) {
		// テスト用のJWT認証ミドルウェア
		cookie, err := c.Cookie("id_token")
		if err != nil || cookie == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}

		// テスト用ユーザー情報をコンテキストに設定
		username := cookie[12:] // "dummy_token_" を削除
		var user models.User
		if result := db.Where("username = ?", username).First(&user); result.Error != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			c.Abort()
			return
		}

		c.Set("userID", user.CognitoID)
		c.Set("username", user.Username)
		c.Set("email", user.Email)
		c.Next()
	})

	// CSRFミドルウェアをセットアップ
	authGroup.Use(func(c *gin.Context) {
		// テスト用のCSRF検証ミドルウェア
		if c.Request.Method != "GET" {
			csrfHeader := c.GetHeader("X-CSRF-Token")
			csrfCookie, _ := c.Cookie("csrf_token")

			if csrfHeader == "" || csrfCookie == "" || csrfHeader != csrfCookie {
				c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token validation failed"})
				c.Abort()
				return
			}
		}
		c.Next()
	})

	// テスト用保護リソースエンドポイント
	authGroup.GET("/me", func(c *gin.Context) {
		username, _ := c.Get("username")
		email, _ := c.Get("email")

		c.JSON(http.StatusOK, gin.H{
			"username": username,
			"email":    email,
		})
	})

	// ログアウトエンドポイント
	authGroup.POST("/logout", func(c *gin.Context) {
		c.SetCookie("id_token", "", -1, "/", "", false, true)
		c.SetCookie("refresh_token", "", -1, "/", "", false, true)
		c.SetCookie("csrf_token", "", -1, "/", "", false, false)

		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
	})

	// テスト用サーバーを起動
	server := httptest.NewServer(router)

	return &TestInfra{
		DB:        db,
		Router:    router,
		Server:    server,
		CookieJar: []*http.Cookie{},
	}
}

// テスト用ダミーJWTバリデーター
type DummyJWTValidator struct{}

func (v *DummyJWTValidator) ValidateToken(tokenString string) (*middleware.CognitoClaims, error) {
	// トークンが "dummy_token_" で始まる場合は有効
	if len(tokenString) > 12 && tokenString[:12] == "dummy_token_" {
		username := tokenString[12:]
		return &middleware.CognitoClaims{
			Username: username,
			Email:    fmt.Sprintf("%s@example.com", username),
		}, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// テスト用HTTPクライアント
func (ti *TestInfra) newRequest(method, path string, body interface{}) *http.Request {
	var reqBody []byte
	var err error

	if body != nil {
		reqBody, err = json.Marshal(body)
		if err != nil {
			panic(err)
		}
	}

	req, err := http.NewRequest(method, ti.Server.URL+path, bytes.NewBuffer(reqBody))
	if err != nil {
		panic(err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// 保存されたCookieを設定
	for _, cookie := range ti.CookieJar {
		req.AddCookie(cookie)
	}

	// CSRFトークンをヘッダーに設定（非GET要求の場合）
	if method != "GET" && ti.CSRFToken != "" {
		req.Header.Set("X-CSRF-Token", ti.CSRFToken)
	}

	return req
}

// レスポンスからCookieを保存
func (ti *TestInfra) saveCookies(resp *http.Response) {
	for _, cookie := range resp.Cookies() {
		// 既存のCookieを更新または追加
		updated := false
		for i, c := range ti.CookieJar {
			if c.Name == cookie.Name {
				// Cookieの有効期限が切れている場合は削除
				if cookie.MaxAge < 0 {
					ti.CookieJar = append(ti.CookieJar[:i], ti.CookieJar[i+1:]...)
				} else {
					ti.CookieJar[i] = cookie
				}
				updated = true
				break
			}
		}

		// 新しいCookieを追加
		if !updated && cookie.MaxAge > 0 {
			ti.CookieJar = append(ti.CookieJar, cookie)
		}

		// CSRFトークンを保存
		if cookie.Name == "csrf_token" && cookie.MaxAge > 0 {
			ti.CSRFToken = cookie.Value
		}
	}
}

// テスト実行
func TestAuthenticationFlow(t *testing.T) {
	// テストインフラをセットアップ
	infra := setupTestInfra(t)
	defer infra.Server.Close()

	// テスト用ユーザーを作成
	testUser := &models.User{
		Username:  "testuser",
		Email:     "test@example.com",
		CognitoID: "test-cognito-id",
	}
	infra.DB.Create(testUser)

	// ステップ1: 認証なしの状態で保護リソースにアクセス
	t.Run("Unauthenticated Access", func(t *testing.T) {
		req := infra.newRequest("GET", "/api/me", nil)
		client := &http.Client{}
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	// ステップ2: ログイン
	t.Run("Login", func(t *testing.T) {
		loginData := map[string]string{
			"emailOrUsername": "testuser",
			"password":        "testpassword",
		}

		req := infra.newRequest("POST", "/login", loginData)
		client := &http.Client{}
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Cookieを保存
		infra.saveCookies(resp)

		// レスポンスボディを確認
		var responseBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&responseBody)
		resp.Body.Close()

		assert.Equal(t, "Logged in successfully", responseBody["message"])

		// 認証済みユーザー情報が含まれていることを確認
		user, ok := responseBody["user"].(map[string]interface{})
		assert.True(t, ok)
		assert.Equal(t, "testuser", user["username"])
	})

	// ステップ3: 認証済み状態で保護リソースにアクセス
	t.Run("Authenticated Access", func(t *testing.T) {
		req := infra.newRequest("GET", "/api/me", nil)
		client := &http.Client{}
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// レスポンスボディを確認
		var responseBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&responseBody)
		resp.Body.Close()

		assert.Equal(t, "testuser", responseBody["username"])
		assert.Equal(t, "test@example.com", responseBody["email"])
	})

	// ステップ4: CSRF保護のテスト
	t.Run("CSRF Protection", func(t *testing.T) {
		// CSRFトークンなしでPOSTリクエスト
		infra.CSRFToken = "" // CSRFトークンをクリア

		reqBody := map[string]string{"data": "test"}
		req := infra.newRequest("POST", "/api/logout", reqBody)
		client := &http.Client{}
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode) // CSRF検証失敗

		// CSRFトークンを再設定
		for _, cookie := range infra.CookieJar {
			if cookie.Name == "csrf_token" {
				infra.CSRFToken = cookie.Value
				break
			}
		}
	})

	// ステップ5: ログアウト
	t.Run("Logout", func(t *testing.T) {
		req := infra.newRequest("POST", "/api/logout", nil)
		client := &http.Client{}
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Cookieの更新を保存
		infra.saveCookies(resp)

		// レスポンスボディを確認
		var responseBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&responseBody)
		resp.Body.Close()

		assert.Equal(t, "Logged out successfully", responseBody["message"])

		// 認証Cookieが削除されていることを確認
		var idTokenCookie, refreshTokenCookie, csrfCookie *http.Cookie
		for _, cookie := range infra.CookieJar {
			if cookie.Name == "id_token" {
				idTokenCookie = cookie
			} else if cookie.Name == "refresh_token" {
				refreshTokenCookie = cookie
			} else if cookie.Name == "csrf_token" {
				csrfCookie = cookie
			}
		}

		assert.Nil(t, idTokenCookie)
		assert.Nil(t, refreshTokenCookie)
		assert.Nil(t, csrfCookie)
	})

	// ステップ6: ログアウト後に保護リソースにアクセス
	t.Run("Access After Logout", func(t *testing.T) {
		req := infra.newRequest("GET", "/api/me", nil)
		client := &http.Client{}
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode) // 未認証
	})
}
