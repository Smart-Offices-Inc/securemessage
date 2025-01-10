package services

import (
	"time"

	"local/securemessages/internal/config"
	"local/securemessages/internal/models"
)

func CleanupExpiredMessages() {
	for {
		config.GetLogger().Info("Starting CleanupExpiredMessages cycle...")

		now := time.Now().UTC()
		config.GetLogger().Infof("Running expiration cleanup at: %v", now)
		time.Sleep(1 * time.Hour)

		var expiredMessages []models.SecureMessage
		if err := config.GetDB().Where("expires_at <= ?", now).Find(&expiredMessages).Error; err != nil {
			config.GetLogger().Errorf("Failed to find expired messages: %v", err)
			continue
		}

		if len(expiredMessages) == 0 {
			config.GetLogger().Info("No expired messages found.")
			continue
		}

		for _, msg := range expiredMessages {
			config.GetLogger().Infof("Expired message: ID=%s, ExpiresAt=%v", msg.ID, msg.ExpiresAt)
		}

		if err := config.GetDB().Where("expires_at <= ?", now).Delete(&models.SecureMessage{}).Error; err != nil {
			config.GetLogger().Errorf("Failed to delete expired messages: %v", err)
		} else {
			config.GetLogger().Infof("Deleted %d expired messages", len(expiredMessages))
		}
	}
}

func CleanupViewedMessages() {
	for {
		time.Sleep(30 * time.Minute)

		config.GetLogger().Info("Running viewed message cleanup...")

		// Delete any 'view_once' messages that are already viewed
		if err := config.GetDB().Where("view_once = ? AND viewed = ?", true, true).Delete(&models.SecureMessage{}).Error; err != nil {
			config.GetLogger().Errorf("Failed to delete viewed messages: %v", err)
		} else {
			config.GetLogger().Info("Viewed 'view once' messages removed.")
		}
	}
}
