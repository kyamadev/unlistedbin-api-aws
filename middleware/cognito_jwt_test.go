package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// シンプルなJWTバリデーターのモック
type MockJwtValidator struct {
	ValidateTokenFunc func(tokenString string) (*CognitoClaims, error)
}

func (m *MockJwtValidator) ValidateToken(tokenString string) (*CognitoClaims, error) {
	return m.ValidateTokenFunc(tokenString)
}

// モックを使いやすく作るためのヘルパー関数
func NewMockValidator() *MockJwtValidator {
	return &MockJwtValidator{
		ValidateTokenFunc: func(tokenString string) (*CognitoClaims, error) {
			// デフォルトでは有効なトークンとして扱う
			if tokenString == "valid_token" {
				return &CognitoClaims{
					Username: "testuser",
					Email:    "test@example.com",
				}, nil
			}
			return nil, &TokenValidationError{Message: "invalid token"}
		},
	}
}

// トークン検証エラー
type TokenValidationError struct {
	Message string
}

func (e *TokenValidationError) Error() string {
	return e.Message
}

func TestJWTAuthMiddleware_ValidCookie(t *testing.T) {
	// テスト用のGinエンジンをセットアップ
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// モックバリデーターをセットアップ
	mockValidator := NewMockValidator()

	// ミドルウェアをセットアップ
	router.Use(JWTAuthMiddleware(mockValidator))

	// テスト用のエンドポイント
	router.GET("/test", func(c *gin.Context) {
		// コンテキストから値を取得
		username, exists := c.Get("username")
		assert.True(t, exists)
		assert.Equal(t, "testuser", username)

		c.String(http.StatusOK, "authorized")
	})

	// テストリクエストを作成
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)

	// Cookie付きの有効なリクエスト
	req.AddCookie(&http.Cookie{
		Name:  "id_token",
		Value: "valid_token",
	})

	// リクエストを実行
	router.ServeHTTP(w, req)

	// レスポンスをチェック
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "authorized", w.Body.String())
}

func TestJWTAuthMiddleware_ValidBearerToken(t *testing.T) {
	// テスト用のGinエンジンをセットアップ
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// モックバリデーターをセットアップ
	mockValidator := NewMockValidator()

	// ミドルウェアをセットアップ
	router.Use(JWTAuthMiddleware(mockValidator))

	// テスト用のエンドポイント
	router.GET("/test", func(c *gin.Context) {
		username, exists := c.Get("username")
		assert.True(t, exists)
		assert.Equal(t, "testuser", username)

		tokenSource, exists := c.Get("tokenSource")
		assert.True(t, exists)
		assert.Equal(t, "header", tokenSource)

		c.String(http.StatusOK, "authorized")
	})

	// テストリクエストを作成
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)

	// Authorization ヘッダー付きの有効なリクエスト
	req.Header.Set("Authorization", "Bearer valid_token")

	// リクエストを実行
	router.ServeHTTP(w, req)

	// レスポンスをチェック
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "authorized", w.Body.String())
}

func TestJWTAuthMiddleware_InvalidToken(t *testing.T) {
	// テスト用のGinエンジンをセットアップ
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// モックバリデーターをセットアップ
	mockValidator := NewMockValidator()

	// ミドルウェアをセットアップ
	router.Use(JWTAuthMiddleware(mockValidator))

	// テスト用のエンドポイント
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "authorized")
	})

	// テストリクエストを作成
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)

	// 無効なトークンのCookie
	req.AddCookie(&http.Cookie{
		Name:  "id_token",
		Value: "invalid_token",
	})

	// リクエストを実行
	router.ServeHTTP(w, req)

	// レスポンスをチェック - 未認証
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthMiddleware_NoToken(t *testing.T) {
	// テスト用のGinエンジンをセットアップ
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// モックバリデーターをセットアップ
	mockValidator := NewMockValidator()

	// ミドルウェアをセットアップ
	router.Use(JWTAuthMiddleware(mockValidator))

	// テスト用のエンドポイント
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "authorized")
	})

	// テストリクエストを作成 (トークンなし)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)

	// リクエストを実行
	router.ServeHTTP(w, req)

	// レスポンスをチェック - 未認証
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOptionalJWTAuthMiddleware(t *testing.T) {
	// テスト用のGinエンジンをセットアップ
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// モックバリデーターをセットアップ
	mockValidator := NewMockValidator()

	// ミドルウェアをセットアップ
	router.Use(OptionalJWTAuthMiddleware(mockValidator))

	// テスト用のエンドポイント
	router.GET("/test", func(c *gin.Context) {
		authenticated, exists := c.Get("authenticated")
		if exists && authenticated.(bool) {
			c.String(http.StatusOK, "authenticated")
		} else {
			c.String(http.StatusOK, "not authenticated")
		}
	})

	// ケース1: 有効なトークン
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("GET", "/test", nil)
	req1.AddCookie(&http.Cookie{
		Name:  "id_token",
		Value: "valid_token",
	})
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, "authenticated", w1.Body.String())

	// ケース2: 無効なトークン
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.AddCookie(&http.Cookie{
		Name:  "id_token",
		Value: "invalid_token",
	})
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "not authenticated", w2.Body.String())

	// ケース3: トークンなし
	w3 := httptest.NewRecorder()
	req3, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusOK, w3.Code)
	assert.Equal(t, "not authenticated", w3.Body.String())
}
