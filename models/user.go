package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username      string `gorm:"uniqueIndex" json:"username"`
	Email         string `gorm:"uniqueIndex" json:"email"`
	Password      string `json:"-"`                                       // Kept for backward compatibility, will be empty for Cognito users
	CognitoID     string `gorm:"uniqueIndex" json:"cognito_id,omitempty"` // Cognito User ID
	EmailVerified bool   `json:"email_verified"`
}

func (u *User) IsLocalUser() bool {
	return u.CognitoID == ""
}
