package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	CSRFTokenCookieName = "csrf_token"
	CSRFHeaderName      = "X-CSRF-Token"
	CSRFTokenLength     = 32
)

func GenerateCSRFToken() (string, error) {
	bytes := make([]byte, CSRFTokenLength)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(bytes), nil
}

func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Printf("CSRF: リクエスト処理 %s %s", c.Request.Method, c.Request.URL.Path)

		// OAuth/JWT Token-based認証の場合はCSRF保護をスキップ
		// Bearer認証はクッキーに依存しないため、CSRF攻撃のリスクが低い
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			log.Printf("CSRF: Bearerトークン検出 - CSRFチェックをスキップ")
			c.Next()
			return
		}

		// OPTIONSリクエスト（CORS preflight）の場合もスキップ
		if c.Request.Method == "OPTIONS" {
			log.Printf("CSRF: OPTIONSリクエスト - CSRFチェックをスキップ")
			c.Next()
			return
		}

		// GET/HEADリクエストの場合はCSRFトークンを生成するだけ
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" {
			cookieToken, err := c.Cookie(CSRFTokenCookieName)
			if err != nil {
				log.Printf("CSRF: GETリクエスト - トークンがないため生成します")
				token, err := GenerateCSRFToken()
				if err != nil {
					log.Printf("CSRF警告: トークン生成に失敗: %v", err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate CSRF token"})
					c.Abort()
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

				// Cookieを設定
				log.Printf("CSRF: 新しいトークンを設定: %s...", token[:10])
				c.SetSameSite(sameSite)
				c.SetCookie(CSRFTokenCookieName, token, int((24 * time.Hour).Seconds()), "/", domain, secure, false)
			} else {
				log.Printf("CSRF: GETリクエスト - トークンが既に存在: %s...", cookieToken[:10])
			}
			c.Next()
			return
		}

		// 状態変更メソッド（POST/PUT/DELETE/PATCH等）ではCSRF検証が必要
		if c.Request.Method != "GET" && c.Request.Method != "HEAD" && c.Request.Method != "OPTIONS" {
			path := c.Request.URL.Path

			isAuthEndpoint := strings.HasPrefix(path, "/api/auth/")

			cookieToken, cookieErr := c.Cookie(CSRFTokenCookieName)

			headerToken := c.GetHeader(CSRFHeaderName)

			if isAuthEndpoint {
				if cookieErr != nil && headerToken == "" {
					log.Printf("CSRF警告: 認証エンドポイント %s でトークンがありません", path)
					c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token required"})
					c.Abort()
					return
				}

				if headerToken != "" || cookieErr == nil {
					log.Printf("CSRF: 認証エンドポイント %s の検証成功", path)
					c.Next()
					return
				}
			} else {

				if cookieErr != nil {
					log.Printf("CSRF拒否: Cookie不足 (Path: %s)", path)
					c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token required"})
					c.Abort()
					return
				}

				if headerToken == "" {
					log.Printf("CSRF拒否: ヘッダー不足 (Path: %s)", path)
					c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token required"})
					c.Abort()
					return
				}

				if headerToken != cookieToken {
					log.Printf("CSRF拒否: トークン不一致 (Path: %s)", path)
					c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token validation failed"})
					c.Abort()
					return
				}

				if len(cookieToken) < 32 {
					log.Printf("CSRF拒否: トークンが短すぎる (Path: %s, Length: %d)", path, len(cookieToken))
					c.JSON(http.StatusForbidden, gin.H{"error": "Invalid CSRF token"})
					c.Abort()
					return
				}
			}
		}

		log.Printf("CSRF: 検証成功 %s %s", c.Request.Method, c.Request.URL.Path)
		c.Next()
	}
}
