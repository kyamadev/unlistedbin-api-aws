package middleware

import (
	"github.com/gin-gonic/gin"
)

func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Content-Security-Policy (CSP)
		// スクリプトやリソースの読み込み元を制限
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self'; font-src 'self' https://cdnjs.cloudflare.com; object-src 'none'; media-src 'self'; frame-src 'none';")

		// X-XSS-Protection
		// ブラウザの組み込みXSS対策を有効化
		c.Header("X-XSS-Protection", "1; mode=block")

		// X-Content-Type-Options
		// MIMEタイプのスニッフィングを防止
		c.Header("X-Content-Type-Options", "nosniff")

		// X-Frame-Options
		// クリックジャッキング対策
		c.Header("X-Frame-Options", "DENY")

		// Referrer-Policy
		// リファラー情報の送信を制限
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions-Policy
		// ブラウザ機能の使用を制限
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")

		c.Next()
	}
}
