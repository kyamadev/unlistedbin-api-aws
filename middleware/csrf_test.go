package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// テスト用の十分な長さのCSRFトークン（32文字以上）
const testCSRFToken = "test-csrf-token-with-sufficient-length-for-validation"

func TestCSRFMiddleware_GET_Request(t *testing.T) {
	// テスト用のGinエンジンをセットアップ
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// CSRFミドルウェアをセットアップ
	router.Use(CSRFMiddleware())

	// テスト用のエンドポイント
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// GETリクエストの場合、CSRFトークンを設定するだけ
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)

	// リクエストを実行
	router.ServeHTTP(w, req)

	// レスポンスのステータスコードを確認
	assert.Equal(t, http.StatusOK, w.Code)

	// CSRFトークンCookieが設定されていることを確認
	cookies := w.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == CSRFTokenCookieName {
			csrfCookie = cookie
			break
		}
	}

	assert.NotNil(t, csrfCookie)
	assert.Equal(t, CSRFTokenCookieName, csrfCookie.Name)
	assert.NotEmpty(t, csrfCookie.Value)
	assert.False(t, csrfCookie.HttpOnly) // HTTPOnly=falseである必要がある
}

func TestCSRFMiddleware_POST_ValidToken(t *testing.T) {
	// テスト用のGinエンジンをセットアップ
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// CSRFミドルウェアをセットアップ
	router.Use(CSRFMiddleware())

	// テスト用のエンドポイント
	router.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// POSTリクエストを作成
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)

	// CSRF保護のための準備（Cookieとヘッダーの両方が必要）
	req.AddCookie(&http.Cookie{
		Name:  CSRFTokenCookieName,
		Value: testCSRFToken,
	})
	req.Header.Set(CSRFHeaderName, testCSRFToken)

	// リクエストを実行
	router.ServeHTTP(w, req)

	// 有効なCSRFトークンなので成功するはず
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "success", w.Body.String())
}

func TestCSRFMiddleware_POST_InvalidToken(t *testing.T) {
	// テスト用のGinエンジンをセットアップ
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// CSRFミドルウェアをセットアップ
	router.Use(CSRFMiddleware())

	// テスト用のエンドポイント
	router.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// POSTリクエストを作成（トークン不一致）
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)

	// 不一致のCSRFトークン
	req.AddCookie(&http.Cookie{
		Name:  CSRFTokenCookieName,
		Value: testCSRFToken + "1",
	})
	req.Header.Set(CSRFHeaderName, testCSRFToken+"2")

	// リクエストを実行
	router.ServeHTTP(w, req)

	// トークンが一致しないので403エラー
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRFMiddleware_POST_MissingCookie(t *testing.T) {
	// テスト用のGinエンジンをセットアップ
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// CSRFミドルウェアをセットアップ
	router.Use(CSRFMiddleware())

	// テスト用のエンドポイント
	router.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// POSTリクエストを作成（Cookieなし）
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)

	// ヘッダーのみ設定
	req.Header.Set(CSRFHeaderName, testCSRFToken)

	// リクエストを実行
	router.ServeHTTP(w, req)

	// Cookieがないので403エラー
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRFMiddleware_POST_MissingHeader(t *testing.T) {
	// テスト用のGinエンジンをセットアップ
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// CSRFミドルウェアをセットアップ
	router.Use(CSRFMiddleware())

	// テスト用のエンドポイント
	router.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// POSTリクエストを作成（ヘッダーなし）
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)

	// Cookieのみ設定
	req.AddCookie(&http.Cookie{
		Name:  CSRFTokenCookieName,
		Value: testCSRFToken,
	})

	// リクエストを実行
	router.ServeHTTP(w, req)

	// ヘッダーがないので403エラー
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRFMiddleware_BearerToken_Bypass(t *testing.T) {
	// テスト用のGinエンジンをセットアップ
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// CSRFミドルウェアをセットアップ
	router.Use(CSRFMiddleware())

	// テスト用のエンドポイント
	router.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// Authorizationヘッダー付きPOSTリクエスト (モバイルアプリを模倣)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/test", nil)

	// Bearer トークンを設定
	req.Header.Set("Authorization", "Bearer some-jwt-token")

	// リクエストを実行
	router.ServeHTTP(w, req)

	// Bearer トークンがあるのでCSRF検証をバイパスして成功する
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "success", w.Body.String())
}
