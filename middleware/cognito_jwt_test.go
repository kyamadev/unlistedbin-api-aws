package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cognito "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// シンプルなJWTバリデーターのモック
type MockJwtValidator struct {
	mock.Mock
}

func (m *MockJwtValidator) ValidateToken(tokenString string) (*CognitoClaims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*CognitoClaims), args.Error(1)
}

// モックを使いやすく作るためのヘルパー関数
func NewMockValidator() *MockJwtValidator {
	mockValidator := new(MockJwtValidator)

	// デフォルトでは有効なトークンとして扱う
	mockValidator.On("ValidateToken", "valid_token").Return(&CognitoClaims{
		Username: "testuser",
		Email:    "test@example.com",
	}, nil)

	// 無効なトークンはエラーを返す
	mockValidator.On("ValidateToken", "invalid_token").Return(nil, &TokenValidationError{Message: "invalid token"})

	return mockValidator
}

// トークン検証エラー
type TokenValidationError struct {
	Message string
}

func (e *TokenValidationError) Error() string {
	return e.Message
}

// テスト用のJWT認証ミドルウェア
func mockJWTAuthMiddleware(validator *MockJwtValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenStr string

		tokenCookie, cookieErr := c.Cookie("id_token")
		if cookieErr == nil && tokenCookie != "" {
			tokenStr = tokenCookie
			c.Set("tokenSource", "cookie")
		}

		if tokenStr == "" {
			authHeader := c.GetHeader("Authorization")
			if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
				tokenStr = authHeader[7:]
				c.Set("tokenSource", "header")
			}
		}

		if tokenStr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":  "Authentication required",
				"detail": "No valid authentication token found",
			})
			c.Abort()
			return
		}

		claims, err := validator.ValidateToken(tokenStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid or expired token",
				"details": err.Error(),
			})
			c.Abort()
			return
		}

		c.Set("userID", "dummy-subject")
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)

		c.Next()
	}
}

// テスト用のオプショナルJWT認証ミドルウェア
func mockOptionalJWTAuthMiddleware(validator *MockJwtValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		var tokenStr string

		tokenCookie, cookieErr := c.Cookie("id_token")
		if cookieErr == nil && tokenCookie != "" {
			tokenStr = tokenCookie
			c.Set("tokenSource", "cookie")
		}

		if tokenStr == "" {
			authHeader := c.GetHeader("Authorization")
			if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
				tokenStr = authHeader[7:]
				c.Set("tokenSource", "header")
			}
		}

		if tokenStr == "" {
			c.Next()
			return
		}

		claims, err := validator.ValidateToken(tokenStr)
		if err != nil {
			// 無効なトークンでも続行
			c.Next()
			return
		}

		c.Set("userID", "dummy-subject")
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)
		c.Set("authenticated", true)

		c.Next()
	}
}

func TestJWTAuthMiddleware_ValidCookie(t *testing.T) {
	// テスト用のGinエンジンをセットアップ
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// モックバリデーターをセットアップ
	mockValidator := NewMockValidator()

	// ミドルウェアをセットアップ - テスト用ミドルウェアを使用
	router.Use(mockJWTAuthMiddleware(mockValidator))

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

	// ミドルウェアをセットアップ - テスト用ミドルウェアを使用
	router.Use(mockJWTAuthMiddleware(mockValidator))

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

	// ミドルウェアをセットアップ - テスト用ミドルウェアを使用
	router.Use(mockJWTAuthMiddleware(mockValidator))

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

	// ミドルウェアをセットアップ - テスト用ミドルウェアを使用
	router.Use(mockJWTAuthMiddleware(mockValidator))

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

func TestOptionalJWTAuthMiddleware_Validation(t *testing.T) {
	// テスト用のGinエンジンをセットアップ
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// モックバリデーターをセットアップ
	mockValidator := NewMockValidator()

	// ミドルウェアをセットアップ - テスト用ミドルウェアを使用
	router.Use(mockOptionalJWTAuthMiddleware(mockValidator))

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

// モック用のCognitoクライアントインターフェース
type cognitoClientInterface interface {
	InitiateAuth(ctx context.Context, params *cognito.InitiateAuthInput, optFns ...func(*cognito.Options)) (*cognito.InitiateAuthOutput, error)
}

// テスト用のCognitoクライアントモック
type mockCognitoClient struct {
	mock.Mock
}

func (m *mockCognitoClient) InitiateAuth(ctx context.Context, params *cognito.InitiateAuthInput, optFns ...func(*cognito.Options)) (*cognito.InitiateAuthOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*cognito.InitiateAuthOutput), args.Error(1)
}

// RefreshTokenMiddlewareのテスト用に修正したバージョン（テスト用）
func testRefreshTokenMiddleware(cognitoClient cognitoClientInterface, clientID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		idToken, err := c.Cookie("id_token")
		if err != nil {
			c.Next()
			return
		}

		token, _, err := new(jwt.Parser).ParseUnverified(idToken, &CognitoClaims{})
		if err != nil {
			c.Next()
			return
		}

		claims, ok := token.Claims.(*CognitoClaims)
		if !ok {
			c.Next()
			return
		}

		expirationTime, err := claims.GetExpirationTime()
		if err != nil || expirationTime == nil {
			c.Next()
			return
		}

		if time.Until(expirationTime.Time) < 15*time.Minute {
			refreshToken, err := c.Cookie("refresh_token")
			if err != nil || refreshToken == "" {
				c.Next()
				return
			}

			input := &cognito.InitiateAuthInput{
				AuthFlow: types.AuthFlowTypeRefreshToken,
				ClientId: aws.String(clientID),
				AuthParameters: map[string]string{
					"REFRESH_TOKEN": refreshToken,
				},
			}

			result, err := cognitoClient.InitiateAuth(context.TODO(), input)
			if err != nil {
				c.Next()
				return
			}

			domain := ""
			secure := false
			if os.Getenv("ENV") == "production" {
				secure = true
				domain = os.Getenv("COOKIE_DOMAIN")
			}

			sameSite := http.SameSiteLaxMode
			if os.Getenv("ENV") == "production" {
				sameSite = http.SameSiteStrictMode
			}

			c.SetSameSite(sameSite)
			c.SetCookie(
				"id_token",
				*result.AuthenticationResult.IdToken,
				int(result.AuthenticationResult.ExpiresIn),
				"/",
				domain,
				secure,
				true,
			)
		}

		c.Next()
	}
}

func TestRefreshTokenMiddleware(t *testing.T) {
	// テスト用のGinエンジンをセットアップ
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// モックCognitoクライアントをセットアップ
	mockClient := new(mockCognitoClient)

	// 新しいトークンを生成
	newIdToken := "new-id-token"
	expiresIn := int32(3600)

	// モックレスポンスをセットアップ
	mockClient.On("InitiateAuth", mock.Anything, mock.MatchedBy(func(params *cognito.InitiateAuthInput) bool {
		return params.AuthFlow == types.AuthFlowTypeRefreshToken &&
			params.ClientId != nil &&
			*params.ClientId == "test-client-id" &&
			params.AuthParameters["REFRESH_TOKEN"] == "valid-refresh-token"
	})).Return(&cognito.InitiateAuthOutput{
		AuthenticationResult: &types.AuthenticationResultType{ // ここを修正
			IdToken:   aws.String(newIdToken),
			ExpiresIn: expiresIn,
		},
	}, nil)

	// ミドルウェアをセットアップ（テスト用の実装を使用）
	router.Use(testRefreshTokenMiddleware(mockClient, "test-client-id"))

	// テスト用のエンドポイント
	router.GET("/test-refresh", func(c *gin.Context) {
		c.String(http.StatusOK, "success")
	})

	// ケース1: トークンが存在せずリフレッシュされない
	t.Run("No token to refresh", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test-refresh", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "success", w.Body.String())

		// リフレッシュは実行されないはず
		mockClient.AssertNotCalled(t, "InitiateAuth")
	})

	// ケース2: 有効期限が十分に残っているため、リフレッシュされない
	t.Run("Token not expired", func(t *testing.T) {
		// 期限が1時間後のトークンを作成
		claims := CognitoClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		}
		tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := tokenObj.SignedString([]byte("test"))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test-refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "id_token",
			Value: tokenString,
		})
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// リフレッシュは実行されないはず
		mockClient.AssertNotCalled(t, "InitiateAuth")
	})

	// ケース3: 期限切れが近いためリフレッシュが実行される
	t.Run("Token about to expire", func(t *testing.T) {
		// 期限が10分後のトークンを作成（15分以内なのでリフレッシュされる）
		claims := CognitoClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			},
		}
		tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := tokenObj.SignedString([]byte("test"))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test-refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "id_token",
			Value: tokenString,
		})
		req.AddCookie(&http.Cookie{
			Name:  "refresh_token",
			Value: "valid-refresh-token",
		})
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// リフレッシュが実行されるはず
		mockClient.AssertCalled(t, "InitiateAuth", mock.Anything, mock.Anything)

		// 新しいクッキーが設定されていることを確認
		cookies := w.Result().Cookies()
		var idTokenCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "id_token" {
				idTokenCookie = cookie
				break
			}
		}

		// 新しいIDトークンクッキーが設定されているか確認
		if assert.NotNil(t, idTokenCookie) {
			assert.Equal(t, newIdToken, idTokenCookie.Value)
			assert.Equal(t, int(expiresIn), idTokenCookie.MaxAge)
		}
	})

	// ケース4: リフレッシュトークンがなくリフレッシュが実行されない
	t.Run("No refresh token", func(t *testing.T) {
		// 期限が10分後のトークンを作成
		claims := CognitoClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			},
		}
		tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := tokenObj.SignedString([]byte("test"))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test-refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "id_token",
			Value: tokenString,
		})
		// refresh_tokenクッキーはセットしない

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// リフレッシュトークンがないため、リフレッシュは実行されないはず
		mockClient.AssertNotCalled(t, "InitiateAuth")
	})
}
