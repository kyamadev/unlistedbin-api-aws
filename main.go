package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"Unlistedbin-api/config"
	"Unlistedbin-api/controllers"
	"Unlistedbin-api/middleware"
	"Unlistedbin-api/models"
	"Unlistedbin-api/storage"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}
	config.LoadConfig()

	var db *gorm.DB
	var err error
	if config.AppConfig.Env == "production" {
		db, err = gorm.Open(mysql.Open(config.AppConfig.DBDSN), &gorm.Config{})
	} else {
		db, err = gorm.Open(sqlite.Open(config.AppConfig.DBDSN), &gorm.Config{})
	}
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	db.AutoMigrate(&models.User{}, &models.Repository{}, &models.File{})

	controllers.DB = db

	var fileStorage storage.Storage
	if config.AppConfig.Env == "production" {
		s3Storage, err := storage.NewS3Storage(config.AppConfig.S3Region, config.AppConfig.S3Bucket)
		if err != nil {
			log.Fatalf("failed to initialize S3 storage: %v", err)
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

	r := gin.Default()
	frontendURL := os.Getenv("FRONTEND_URL")
	// セキュリティヘッダーミドルウェアを追加（XSS対策）
	r.Use(middleware.SecurityHeadersMiddleware())

	// CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", frontendURL},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// CSRFミドルウェアを追加（モバイルアプリ対応）
	r.Use(middleware.CSRFMiddleware())

	// トークンリフレッシュミドルウェアを追加（必要に応じてリフレッシュ処理を行う）
	r.Use(middleware.RefreshTokenMiddleware(cognitoClient.IdentityProviderClient, cognitoClient.UserPoolClientID))

	cognitoAuthController := controllers.NewCognitoAuthController(cognitoClient, db)

	// Health check endpoint
	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
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
		authGroup.DELETE("/auth/delete-account", cognitoAuthController.DeleteAccountHandler)
	}

	r.GET("/api/:username/:uuid/*filepath", middleware.OptionalJWTAuthMiddleware(jwtValidator), controllers.FileViewerHandler)

	r.Run(":8080")
}
