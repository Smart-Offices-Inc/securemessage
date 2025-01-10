package models

import "gorm.io/gorm"

type AppConfig struct {
	KeyID            string `gorm:"primaryKey;size:100" json:"key_id"`
	EncryptedAESKey  string `gorm:"type:text" json:"encrypted_aes_key"`
	EncryptedCSRFKey string `gorm:"type:text" json:"encrypted_csrf_key"`
}

func (ac *AppConfig) BeforeCreate(tx *gorm.DB) (err error) {
	if ac.KeyID == "" {
		ac.KeyID = "default"
	}
	return
}
