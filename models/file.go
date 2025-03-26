// models/file.go
package models

import "gorm.io/gorm"

type File struct {
	gorm.Model
	RepositoryID uint
	FileName     string
	FilePath     string
	FileSize     int64 `json:"file_size"` //byte
}
