package models

import (
	"time"

	"gorm.io/gorm"
)

type SecureMessage struct {
	ID           string         `gorm:"primaryKey;size:100" json:"id"`
	Content      string         `gorm:"type:text" json:"content"`
	PasswordHash string         `gorm:"size:255" json:"-"`
	CreatedAt    time.Time      `json:"created_at"`
	ExpiresAt    time.Time      `json:"expires_at"`
	ViewOnce     bool           `json:"view_once"`
	Viewed       bool           `json:"viewed"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

func (sm *SecureMessage) BeforeCreate(tx *gorm.DB) (err error) {
	sm.CreatedAt = time.Now().UTC()
	return
}
