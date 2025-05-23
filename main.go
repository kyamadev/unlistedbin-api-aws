package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	ginadapter "github.com/awslabs/aws-lambda-go-api-proxy/gin"
	"github.com/joho/godotenv"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"Unlistedbin-api/config"
	"Unlistedbin-api/controllers"
	"Unlistedbin-api/middleware"
	"Unlistedbin-api/models"
	"Unlistedbin-api/storage"
)

var ginLambda *ginadapter.GinLambda

func init() {
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") == "" {
		if err := godotenv.Load(); err != nil {
			log.Println("No .env file found, using environment variables")
		}
	}

	config.LoadConfig()

	var db *gorm.DB
	var err error
	if config.AppConfig.Env == "production" {
		dbUrl := config.AppConfig.DBDSN
		// URLをチェックしてPostgreSQLかMySQLかを判定
		if strings.HasPrefix(dbUrl, "postgresql://") {
			db, err = gorm.Open(postgres.Open(dbUrl), &gorm.Config{})
		} else {
			db, err = gorm.Open(mysql.Open(dbUrl), &gorm.Config{})
		}
	} else {
		db, err = gorm.Open(sqlite.Open(config.AppConfig.DBDSN), &gorm.Config{})
	}
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	db.AutoMigrate(&models.User{}, &models.Repository{}, &models.File{})
	controllers.DB = db

	var fileStorage storage.Storage
	if config.AppConfig.Env == "production" {
		// Cloudflare R2
		r2Region := os.Getenv("R2_REGION")
		r2Bucket := os.Getenv("R2_BUCKET")

		s3Storage, err := storage.NewS3Storage(r2Region, r2Bucket)
		if err != nil {
			log.Fatalf("failed to initialize R2 storage: %v", err)
		}
		fileStorage = s3Storage
	} else {
		fileStorage = storage.NewLocalStorage(config.AppConfig.StoragePath)
	}
	controllers.FileStorage = fileStorage

	cognitoClient, err := controllers.NewCognitoClient(
		config.AppConfig.CognitoRegion,
		config.AppConfig.CognitoUserPoolID,
		config.AppConfig.CognitoClientID,
	)
	if err != nil {
		log.Fatalf("failed to initialize Cognito client: %v", err)
	}

	jwtValidator := middleware.NewCognitoJWTValidator(
		config.AppConfig.CognitoRegion,
		config.AppConfig.CognitoUserPoolID,
		config.AppConfig.CognitoClientID,
	)

	cognitoAuthController := controllers.NewCognitoAuthController(cognitoClient, controllers.DB)

	r := setupRouter(cognitoAuthController, jwtValidator)

	ginLambda = ginadapter.New(r)
}

func Handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// API Gateway プロキシリクエストを処理してレスポンスを返す
	return ginLambda.ProxyWithContext(ctx, req)
}

func main() {
	// ローカル開発環境の場合、通常のGinサーバーを起動
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") == "" {
		cognitoClient, err := controllers.NewCognitoClient(
			config.AppConfig.CognitoRegion,
			config.AppConfig.CognitoUserPoolID,
			config.AppConfig.CognitoClientID,
		)
		if err != nil {
			log.Fatalf("failed to initialize Cognito client: %v", err)
		}

		jwtValidator := middleware.NewCognitoJWTValidator(
			config.AppConfig.CognitoRegion,
			config.AppConfig.CognitoUserPoolID,
			config.AppConfig.CognitoClientID,
		)

		cognitoAuthController := controllers.NewCognitoAuthController(cognitoClient, controllers.DB)

		port := os.Getenv("PORT")
		if port == "" {
			port = "8080"
		}

		r := setupRouter(cognitoAuthController, jwtValidator)
		r.Run(":" + port)
		return
	}

	// Lambda環境では、Lambda関数としてスタート
	lambda.Start(Handler)
}

func setupRouter(cognitoAuthController *controllers.CognitoAuthController, jwtValidator *middleware.CognitoJWTValidator) *gin.Engine {
	r := gin.Default()
	frontendURL := os.Getenv("FRONTEND_URL")

	//Proxy設定
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		// Lambda環境ではAPI Gatewayを信頼
		r.SetTrustedProxies([]string{"0.0.0.0/0"})
	} else {
		// ローカル開発環境ではループバックのみ信頼
		r.SetTrustedProxies([]string{"127.0.0.1"})
	}
	// セキュリティヘッダーミドルウェアを追加（XSS対策）
	r.Use(middleware.SecurityHeadersMiddleware())

	// CORS設定
	corsConfig := cors.Config{
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}

	// 本番環境では許可するオリジンを制限
	if frontendURL != "" {
		corsConfig.AllowOrigins = []string{frontendURL}
	} else {
		corsConfig.AllowOrigins = []string{"http://localhost:3000", "https://*.vercel.app"}
	}

	r.Use(cors.New(corsConfig))

	r.Use(middleware.CSRFMiddleware())

	if cognitoAuthController != nil && cognitoAuthController.CognitoClient != nil {
		r.Use(middleware.RefreshTokenMiddleware(
			cognitoAuthController.CognitoClient.IdentityProviderClient,
			cognitoAuthController.CognitoClient.UserPoolClientID,
		))
	}

	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// CSRFデバッグエンドポイント
	r.GET("/api/debug/csrf", func(c *gin.Context) {
		csrfToken, err := c.Cookie(middleware.CSRFTokenCookieName)
		tokenStatus := "not_found"
		if err == nil {
			tokenStatus = "found"
		}

		// 新しいCSRFトークンを生成
		newToken, genErr := middleware.GenerateCSRFToken()
		if genErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate CSRF token"})
			return
		}

		// クッキーを設定
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
		c.SetCookie(middleware.CSRFTokenCookieName, newToken, int((24 * time.Hour).Seconds()), "/", domain, secure, false)

		c.JSON(http.StatusOK, gin.H{
			"csrf_status": map[string]interface{}{
				"previous_token_status": tokenStatus,
				"previous_token": func() string {
					if err == nil {
						return csrfToken[:10] + "..."
					}
					return ""
				}(),
				"new_token":     newToken[:10] + "...",
				"new_token_set": true,
			},
			"csrf_instructions": "このエンドポイントにアクセスすると新しいCSRFトークンが設定されます。",
			"notes":             "非GETリクエストでは、このトークンをX-CSRF-Tokenヘッダーに含める必要があります",
		})
	})

	// CSRFテストエンドポイント
	r.POST("/api/debug/csrf-test", func(c *gin.Context) {
		headerToken := c.GetHeader(middleware.CSRFHeaderName)
		cookieToken, cookieErr := c.Cookie(middleware.CSRFTokenCookieName)

		c.JSON(http.StatusOK, gin.H{
			"csrf_test_result": map[string]interface{}{
				"cookie_token_exists": cookieErr == nil,
				"header_token_exists": headerToken != "",
				"tokens_match":        cookieErr == nil && headerToken != "" && headerToken == cookieToken,
				"validation_success":  cookieErr == nil && headerToken != "" && headerToken == cookieToken,
			},
			"headers": map[string]string{
				"X-CSRF-Token": headerToken,
			},
			"cookie": func() string {
				if cookieErr == nil {
					return cookieToken[:10] + "..."
				}
				return "not found"
			}(),
		})
	})

	// 認証系エンドポイント
	r.POST("/api/auth/register", cognitoAuthController.RegisterHandler)
	r.POST("/api/auth/login", cognitoAuthController.LoginHandler)
	r.GET("/api/auth/check-username", cognitoAuthController.CheckUsernameAvailability)
	r.POST("/api/auth/logout", cognitoAuthController.LogoutHandler)

	// 追加認証エンドポイント
	r.POST("/api/auth/confirm-signup", cognitoAuthController.ConfirmSignUpHandler)
	r.POST("/api/auth/reset-password", cognitoAuthController.ResetPasswordHandler)
	r.POST("/api/auth/confirm-reset-password", cognitoAuthController.ConfirmResetPasswordHandler)

	// 認証が必要なエンドポイント
	authGroup := r.Group("/api")
	authGroup.Use(middleware.JWTAuthMiddleware(jwtValidator))
	{
		authGroup.GET("/auth/me", cognitoAuthController.GetUserInfoHandler)
		authGroup.PUT("/auth/change-password", cognitoAuthController.ChangePasswordHandler)
		authGroup.GET("/repositories", controllers.GetRepositories)
		authGroup.POST("/repositories", controllers.CreateRepository)
		authGroup.DELETE("/repositories/:uuid", controllers.DeleteRepository)
		authGroup.PUT("/repositories/:uuid/visibility", controllers.UpdateVisibility)
		authGroup.POST("/files/upload", controllers.UploadFileHandler)
		authGroup.PUT("/auth/update-username", cognitoAuthController.UpdateUsernameHandler)
		authGroup.PUT("/auth/update-email", cognitoAuthController.UpdateEmailHandler)
		authGroup.POST("/auth/confirm-email", cognitoAuthController.ConfirmEmailHandler)
		authGroup.DELETE("/auth/delete-account", cognitoAuthController.DeleteAccountHandler)
		authGroup.PUT("/repositories/:uuid/download-permission", controllers.UpdateDownloadPermission)
	}

	r.GET("/api/:username/:uuid/*filepath", middleware.OptionalJWTAuthMiddleware(jwtValidator), controllers.FileViewerHandler)
	r.GET("/api/:username/zip/:uuid", middleware.OptionalJWTAuthMiddleware(jwtValidator), controllers.ZipDownloadHandler)

	return r
}
