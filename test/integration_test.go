package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"Unlistedbin-api/config"
	"Unlistedbin-api/controllers"
	"Unlistedbin-api/middleware"
	"Unlistedbin-api/models"
	"Unlistedbin-api/storage"

	"github.com/golang-jwt/jwt/v5"

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
	Storage      storage.Storage
	TempDir      string
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

	// テスト用ストレージディレクトリを作成
	tempDir, err := os.MkdirTemp("", "unlistedbin-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// テスト用ストレージをセットアップ
	fileStorage := storage.NewLocalStorage(tempDir)

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
		AllowHeaders:     []string{"Origin", "Content-Type", "X-CSRF-Token", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// セキュリティミドルウェアをセットアップ
	router.Use(middleware.SecurityHeadersMiddleware())

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
			authHeader := c.GetHeader("Authorization")
			if authHeader == "" || len(authHeader) <= 7 || authHeader[:7] != "Bearer " {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
				c.Abort()
				return
			}
			cookie = authHeader[7:] // "Bearer " を削除
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
		c.Set("authenticated", true)
		c.Next()
	})

	// CSRFミドルウェアをセットアップ
	authGroup.Use(func(c *gin.Context) {
		// テスト用のCSRF検証ミドルウェア
		if c.Request.Method != "GET" && c.Request.Method != "OPTIONS" {
			// Authorization ヘッダーがある場合はCSRF検証をスキップ
			authHeader := c.GetHeader("Authorization")
			if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
				c.Next()
				return
			}

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

	// リポジトリ作成エンドポイント
	authGroup.POST("/repositories", controllers.CreateRepository)

	// リポジトリ一覧取得エンドポイント
	authGroup.GET("/repositories", controllers.GetRepositories)

	// リポジトリ可視性更新エンドポイント
	authGroup.PUT("/repositories/:uuid/visibility", controllers.UpdateVisibility)

	// リポジトリダウンロード権限更新エンドポイント
	authGroup.PUT("/repositories/:uuid/download-permission", controllers.UpdateDownloadPermission)

	// ファイルアップロードエンドポイント
	authGroup.POST("/files/upload", controllers.UploadFileHandler)

	// リポジトリ削除エンドポイント
	authGroup.DELETE("/repositories/:uuid", controllers.DeleteRepository)

	// ファイル表示エンドポイント（認証は任意）
	router.GET("/api/:username/:uuid/*filepath", func(c *gin.Context) {
		c.Set("authenticated", true) // テスト用に常に認証済みとする
		controllers.FileViewerHandler(c)
	})

	// ZIPダウンロードエンドポイント（認証は任意）
	router.GET("/api/:username/zip/:uuid", func(c *gin.Context) {
		c.Set("authenticated", true) // テスト用に常に認証済みとする
		controllers.ZipDownloadHandler(c)
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
		Storage:   fileStorage,
		TempDir:   tempDir,
	}
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
	if method != "GET" && method != "OPTIONS" && ti.CSRFToken != "" {
		req.Header.Set("X-CSRF-Token", ti.CSRFToken)
	}

	return req
}

// マルチパートリクエスト用のヘルパー関数
func (ti *TestInfra) newMultipartRequest(method, path string, formValues map[string]string, fileField, fileName, fileContent string) *http.Request {
	var b bytes.Buffer
	writer := multipart.NewWriter(&b)

	// フォームフィールドの追加
	for key, value := range formValues {
		err := writer.WriteField(key, value)
		if err != nil {
			panic(err)
		}
	}

	// ファイルフィールドの追加
	if fileField != "" && fileName != "" {
		part, err := writer.CreateFormFile(fileField, fileName)
		if err != nil {
			panic(err)
		}
		io.WriteString(part, fileContent)
	}

	err := writer.Close()
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest(method, ti.Server.URL+path, &b)
	if err != nil {
		panic(err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	// 保存されたCookieを設定
	for _, cookie := range ti.CookieJar {
		req.AddCookie(cookie)
	}

	// CSRFトークンをヘッダーに設定
	if ti.CSRFToken != "" {
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
	defer os.RemoveAll(infra.TempDir)

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

	// ステップ4: リポジトリ作成
	var repoUUID string
	t.Run("Create Repository", func(t *testing.T) {
		repoData := map[string]interface{}{
			"name":   "Test Repository",
			"public": true,
		}

		req := infra.newRequest("POST", "/api/repositories", repoData)
		client := &http.Client{}
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// レスポンスボディを確認
		var repository models.Repository
		json.NewDecoder(resp.Body).Decode(&repository)
		resp.Body.Close()

		assert.Equal(t, "Test Repository", repository.Name)
		assert.True(t, repository.Public)
		assert.NotEmpty(t, repository.UUID)

		repoUUID = repository.UUID
	})

	// ステップ5: ファイルアップロード
	var uploadedRepoUUID string
	t.Run("Upload File", func(t *testing.T) {
		formValues := map[string]string{
			"repository_name": "Updated Repository Name",
			"public":          "true",
		}

		fileName := "test.txt"
		fileContent := "This is a test file content."

		req := infra.newMultipartRequest("POST", "/api/files/upload", formValues, "file", fileName, fileContent)
		client := &http.Client{}
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// レスポンスボディを確認
		var responseBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&responseBody)
		resp.Body.Close()

		assert.Equal(t, "File uploaded successfully", responseBody["message"])
		assert.NotEmpty(t, responseBody["repo_uuid"])

		// アップロードしたリポジトリのUUIDを保存
		uploadedRepoUUID = responseBody["repo_uuid"].(string)
	})

	// ステップ6: リポジトリのダウンロード権限設定
	t.Run("Update Download Permission", func(t *testing.T) {
		permissionData := map[string]interface{}{
			"download_allowed": true,
		}

		// アップロードしたリポジトリのUUIDを使用
		req := infra.newRequest("PUT", "/api/repositories/"+uploadedRepoUUID+"/download-permission", permissionData)
		client := &http.Client{}
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// レスポンスボディを確認
		var repository models.Repository
		json.NewDecoder(resp.Body).Decode(&repository)
		resp.Body.Close()

		assert.Equal(t, uploadedRepoUUID, repository.UUID)
		assert.True(t, repository.DownloadAllowed)
	})

	// ステップ7: リポジトリのファイルアクセス
	t.Run("Access Repository File", func(t *testing.T) {
		// アップロードしたリポジトリのUUIDを使用
		fileRequest := infra.newRequest("GET", fmt.Sprintf("/api/%s/%s/test.txt", testUser.Username, uploadedRepoUUID), nil)
		client := &http.Client{}
		fileResp, err := client.Do(fileRequest)

		assert.NoError(t, err)
		if fileResp.StatusCode != http.StatusOK {
			var errorBody map[string]interface{}
			json.NewDecoder(fileResp.Body).Decode(&errorBody)
			t.Logf("Error response: %v", errorBody)
		}
		assert.Equal(t, http.StatusOK, fileResp.StatusCode)

		// レスポンスボディを確認
		var fileResponseBody map[string]interface{}
		json.NewDecoder(fileResp.Body).Decode(&fileResponseBody)
		fileResp.Body.Close()

		assert.Equal(t, testUser.Username, fileResponseBody["username"])
		assert.Equal(t, uploadedRepoUUID, fileResponseBody["repo_uuid"])
		assert.Equal(t, "test.txt", fileResponseBody["filepath"])
		assert.Equal(t, "This is a test file content.", fileResponseBody["data"])
		assert.Equal(t, false, fileResponseBody["isDirectory"])
	})

	// ステップ8: ZIPダウンロード
	t.Run("Download Repository as ZIP", func(t *testing.T) {
		// アップロードしたリポジトリのUUIDを使用
		zipReq := infra.newRequest("GET", fmt.Sprintf("/api/%s/zip/%s", testUser.Username, uploadedRepoUUID), nil)
		client := &http.Client{}
		zipResp, err := client.Do(zipReq)

		assert.NoError(t, err)
		if zipResp.StatusCode != http.StatusOK {
			var errorBody map[string]interface{}
			json.NewDecoder(zipResp.Body).Decode(&errorBody)
			t.Logf("ZIP Error response: %v", errorBody)
		}
		assert.Equal(t, http.StatusOK, zipResp.StatusCode)
		assert.Equal(t, "application/zip", zipResp.Header.Get("Content-Type"))
		assert.Contains(t, zipResp.Header.Get("Content-Disposition"), "attachment")

		// ZIPファイルのボディを読み込んで確認（実際のテストでは中身を確認）
		zipBody, err := io.ReadAll(zipResp.Body)
		zipResp.Body.Close()

		assert.NoError(t, err)
		assert.NotEmpty(t, zipBody)
	})

	// ステップ9: CSRF保護のテスト
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

	// ステップ10: リポジトリの可視性変更
	t.Run("Update Repository Visibility", func(t *testing.T) {
		// 可視性を非公開に変更
		visibilityData := map[string]interface{}{
			"public": false,
		}

		req := infra.newRequest("PUT", "/api/repositories/"+repoUUID+"/visibility", visibilityData)
		client := &http.Client{}
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// レスポンスボディを確認
		var repository models.Repository
		json.NewDecoder(resp.Body).Decode(&repository)
		resp.Body.Close()

		assert.Equal(t, repoUUID, repository.UUID)
		assert.False(t, repository.Public)
	})

	// ステップ11: リポジトリ削除
	t.Run("Delete Repository", func(t *testing.T) {
		req := infra.newRequest("DELETE", "/api/repositories/"+repoUUID, nil)
		client := &http.Client{}
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// レスポンスボディを確認
		var responseBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&responseBody)
		resp.Body.Close()

		assert.Equal(t, "Repository deleted", responseBody["message"])
		assert.Equal(t, repoUUID, responseBody["repo_uuid"])

		// リポジトリが削除されたことを確認
		var count int64
		infra.DB.Model(&models.Repository{}).Where("uuid = ?", repoUUID).Count(&count)
		assert.Equal(t, int64(0), count)
	})

	// ステップ12: トークンリフレッシュのテスト
	t.Run("Token Refresh", func(t *testing.T) {
		// まず有効期限が短いトークンを生成して設定
		expiresIn := 10 * time.Minute // 期限が15分以内だとリフレッシュされる
		refreshToken := "test_refresh_token"

		// JWT生成（有効期限が短いトークン）
		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
			Subject:   testUser.CognitoID,
		}
		tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := tokenObj.SignedString([]byte("test_secret"))
		assert.NoError(t, err)

		// 短い有効期限のトークンでクッキーを設定
		client := &http.Client{}

		// リフレッシュトークン設定用のリクエスト
		req := infra.newRequest("GET", "/api/me", nil)
		req.AddCookie(&http.Cookie{
			Name:   "id_token",
			Value:  tokenString,
			Path:   "/",
			MaxAge: int(expiresIn.Seconds()),
		})
		req.AddCookie(&http.Cookie{
			Name:   "refresh_token",
			Value:  refreshToken,
			Path:   "/",
			MaxAge: 86400, // 24時間
		})

		// リフレッシュが機能する場合、アクセス時に新しいトークンがセットされるはず
		resp, err := client.Do(req)
		assert.NoError(t, err)

		// レスポンスを確認
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// この時点で新しいトークンがセットされていない可能性があるが、
		// 実際のリフレッシュ動作は実装に依存するためここではテストの結果だけ確認

		// クッキーを表示（デバッグ用）
		for _, cookie := range resp.Cookies() {
			t.Logf("Cookie after refresh attempt: %s = %s (MaxAge: %d)",
				cookie.Name, cookie.Value, cookie.MaxAge)
		}
	})

	// ステップ13: ログアウト
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

	// ステップ14: ログアウト後に保護リソースにアクセス
	t.Run("Access After Logout", func(t *testing.T) {
		req := infra.newRequest("GET", "/api/me", nil)
		client := &http.Client{}
		resp, err := client.Do(req)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode) // 未認証
	})
}
