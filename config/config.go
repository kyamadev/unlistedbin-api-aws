package config

import "os"

type Config struct {
	Env         string
	DBDSN       string
	StoragePath string // ローカル環境の場合のストレージパス（例："./storage/local"）
}

var AppConfig *Config

func LoadConfig() {
	env := os.Getenv("ENV")
	if env == "" {
		env = "development"
	}
	var dsn string
	var storagePath string
	//Todo: Finalize
	if env == "production" {
		dsn = os.Getenv("MYSQL_DSN")
		if dsn == "" {
			panic("MYSQL_DSN environment variable is required in production")
		}
		// 本番環境用のストレージパスを環境変数から取得するか、S3 バケットの名前などに置き換える
		storagePath = os.Getenv("STORAGE_PATH")
		if storagePath == "" {
			// 必要ならpanicするか、適当なデフォルト値を設定
			panic("STORAGE_PATH environment variable is required in production")
		}
	} else {
		// 開発環境用
		dsn = "test.db"
		storagePath = "./storage/local"
	}

	AppConfig = &Config{
		Env:         env,
		DBDSN:       dsn,
		StoragePath: storagePath,
	}
}
