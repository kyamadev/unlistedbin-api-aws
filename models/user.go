package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username              string    `gorm:"uniqueIndex" json:"username"`
	Email                 string    `gorm:"uniqueIndex" json:"email"`
	PendingEmail          string    `json:"pending_email,omitempty"`
	PendingEmailTimestamp time.Time `json:"pending_email_timestamp,omitempty"`
	Password              string    `json:"-"`                                       // Kept for backward compatibility, will be empty for Cognito users
	CognitoID             string    `gorm:"uniqueIndex" json:"cognito_id,omitempty"` // Cognito User ID
	EmailVerified         bool      `json:"email_verified"`
	StorageUsed           int64     `json:"storage_used"`  // byte
	StorageLimit          int64     `json:"storage_limit"` // byte
}

func (u *User) IsLocalUser() bool {
	return u.CognitoID == ""
}

const DefaultStorageLimit int64 = 1 * 1024 * 1024 * 1024 // 1GB

func (u *User) HasReachedStorageLimit(additionalBytes int64) bool {
	if u.StorageLimit == 0 {
		u.StorageLimit = DefaultStorageLimit
	}
	return u.StorageUsed+additionalBytes > u.StorageLimit
}

func (u *User) RemainingStorage() int64 {
	if u.StorageLimit == 0 {
		u.StorageLimit = DefaultStorageLimit
	}
	remaining := u.StorageLimit - u.StorageUsed
	if remaining < 0 {
		return 0
	}
	return remaining
}
