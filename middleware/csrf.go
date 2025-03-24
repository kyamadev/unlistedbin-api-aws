package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	CSRFTokenCookieName = "csrf_token"

	CSRFHeaderName = "X-CSRF-Token"

	CSRFTokenLength = 32
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
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			c.Next()
			return
		}

		if c.Request.Method == "GET" {
			_, err := c.Cookie(CSRFTokenCookieName)
			if err != nil {
				token, err := GenerateCSRFToken()
				if err != nil {
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

				c.SetSameSite(sameSite)
				c.SetCookie(CSRFTokenCookieName, token, int((24 * time.Hour).Seconds()), "/", domain, secure, false)
			}
			c.Next()
			return
		}

		if c.Request.Method != "GET" {
			cookieToken, err := c.Cookie(CSRFTokenCookieName)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token missing in cookie"})
				c.Abort()
				return
			}
			headerToken := c.GetHeader(CSRFHeaderName)
			if headerToken == "" {
				c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token missing in header"})
				c.Abort()
				return
			}

			if headerToken != cookieToken {
				c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token validation failed"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}
