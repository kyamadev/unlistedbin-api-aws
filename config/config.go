package config

import (
	"log"
	"os"
)

type Config struct {
	Env               string
	DBDSN             string
	StoragePath       string
	CognitoRegion     string
	CognitoUserPoolID string
	CognitoClientID   string
	S3Bucket          string
	S3Region          string
	CookieDomain      string
}

var AppConfig *Config

func LoadConfig() {
	env := os.Getenv("ENV")
	if env == "" {
		env = "development"
	}

	var dsn string
	var storagePath string
	var cognitoRegion, cognitoUserPoolID, cognitoClientID string
	var s3Bucket, s3Region string
	var cookieDomain string

	if env == "production" {
		dsn = os.Getenv("MYSQL_DSN")
		if dsn == "" {
			panic("MYSQL_DSN environment variable is required in production")
		}

		storagePath = os.Getenv("STORAGE_PATH")
		if storagePath == "" {
			panic("STORAGE_PATH environment variable is required in production")
		}

		cookieDomain = os.Getenv("COOKIE_DOMAIN")
	} else {
		dsn = os.Getenv("DB_DSN")
		if dsn == "" {
			dsn = "test.db"
		}

		storagePath = os.Getenv("STORAGE_PATH")
		if storagePath == "" {
			storagePath = "./storage/local"
		}

		cookieDomain = os.Getenv("COOKIE_DOMAIN")
	}

	cognitoRegion = os.Getenv("COGNITO_REGION")
	cognitoUserPoolID = os.Getenv("COGNITO_USER_POOL_ID")
	cognitoClientID = os.Getenv("COGNITO_CLIENT_ID")

	if env != "production" && (cognitoRegion == "" || cognitoUserPoolID == "" || cognitoClientID == "") {
		log.Println("Warning: Cognito environment variables not set. Authentication features will not work correctly.")
		if cognitoRegion == "" {
			cognitoRegion = "us-east-1"
		}
		if cognitoUserPoolID == "" {
			cognitoUserPoolID = "dummy-user-pool-id"
		}
		if cognitoClientID == "" {
			cognitoClientID = "dummy-client-id"
		}
	}

	s3Bucket = os.Getenv("S3_BUCKET")
	s3Region = os.Getenv("S3_REGION")

	if env != "production" && (s3Bucket == "" || s3Region == "") {
		log.Println("Warning: S3 environment variables not set. File storage features will use local storage.")
		if s3Region == "" {
			s3Region = "us-east-1"
		}
		if s3Bucket == "" {
			s3Bucket = "local-dev-bucket"
		}
	}

	AppConfig = &Config{
		Env:               env,
		DBDSN:             dsn,
		StoragePath:       storagePath,
		CognitoRegion:     cognitoRegion,
		CognitoUserPoolID: cognitoUserPoolID,
		CognitoClientID:   cognitoClientID,
		S3Bucket:          s3Bucket,
		S3Region:          s3Region,
		CookieDomain:      cookieDomain,
	}
}
