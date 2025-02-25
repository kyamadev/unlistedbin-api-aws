package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Repository struct {
	gorm.Model
	UUID    string `gorm:"uniqueIndex" json:"uuid"`
	OwnerID uint   `json:"owner_id"`
	Name    string `json:"name"`
	Public  bool   `json:"public"`
}

func (repo *Repository) BeforeCreate(tx *gorm.DB) (err error) {
	repo.UUID = uuid.NewString()
	return
}
