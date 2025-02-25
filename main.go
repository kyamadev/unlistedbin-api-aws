package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
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
		bucket := os.Getenv("S3_BUCKET")
		if bucket == "" {
			log.Fatal("S3_BUCKET env variable must be set in production")
		}
		fileStorage = storage.NewS3Storage(bucket)
	} else {
		fileStorage = storage.NewLocalStorage(config.AppConfig.StoragePath)
	}
	controllers.FileStorage = fileStorage

	r := gin.Default()

	// CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	store := cookie.NewStore([]byte("secret-key"))
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   false, // 開発環境では false、本番では true
		SameSite: http.SameSiteLaxMode,
	})
	r.Use(sessions.Sessions("mysession", store))

	r.GET("/api/auth/check-username", controllers.CheckUsernameHandler)
	r.GET("/api/auth/session", controllers.SessionHandler)
	r.POST("/api/auth/register", controllers.RegisterHandler)
	r.POST("/api/auth/login", controllers.LoginHandler)
	r.POST("/api/auth/logout", controllers.LogoutHandler)

	// 認証が必要なAPI
	authGroup := r.Group("/api")
	authGroup.Use(middleware.SessionAuthMiddleware())
	{
		authGroup.GET("/repositories", controllers.GetRepositories)
		authGroup.POST("/repositories", controllers.CreateRepository)
		authGroup.DELETE("/repositories/:uuid", controllers.DeleteRepository)
		authGroup.PUT("/repositories/:uuid/visibility", controllers.UpdateVisibility)
		authGroup.POST("/files/upload", controllers.UploadFileHandler)
		authGroup.PUT("/auth/update-username", controllers.UpdateUsernameHandler)
		authGroup.DELETE("/auth/delete-account", controllers.DeleteAccountHandler)
	}

	// 限定公開のファイルビューア
	r.GET("/api/:username/:uuid/*filepath", controllers.FileViewerHandler)

	r.Run(":8080")
}
