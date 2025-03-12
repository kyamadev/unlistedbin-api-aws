package controllers

import (
	"Unlistedbin-api/storage"

	"gorm.io/gorm"
)

var (
	DB          *gorm.DB
	FileStorage storage.Storage
)
