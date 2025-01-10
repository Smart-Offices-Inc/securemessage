package controllers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"

	"local/securemessages/internal/config"
	"local/securemessages/internal/models"
	"local/securemessages/internal/services"
	"local/securemessages/pkg/utils"
)

// SecureMessageView is a view model for displaying messages in the admin panel.
// It includes a truncated ID for display and a full ID for actions like delete.
type SecureMessageView struct {
	FullID             string
	ID                 string
	Content            string
	FormattedExpiresAt string
	ViewOnce           bool
	Viewed             bool
}

type AdminController struct{}

func NewAdminController() *AdminController {
	return &AdminController{}
}

func (ac *AdminController) AdminSecureMessages(c echo.Context) error {
	logger := config.GetLogger()

	pageStr := c.QueryParam("page")
	limitStr := c.QueryParam("limit")

	page := 1
	limit := 10

	if pageStr != "" {
		p, err := strconv.Atoi(pageStr)
		if err == nil && p > 0 {
			page = p
		} else {
			logger.Warnf("Invalid page parameter: %s", pageStr)
		}
	}

	if limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err == nil && (l == 10 || l == 50 || l == 100) {
			limit = l
		} else if err != nil {
			logger.Warnf("Invalid limit parameter: %s", limitStr)
		}
	}

	var messages []models.SecureMessage
	db := config.GetDB()
	if err := db.Order("created_at desc").Limit(limit).Offset((page - 1) * limit).Find(&messages).Error; err != nil {
		logger.WithError(err).Error("Failed to load messages")
		return c.Render(500, "error.html", map[string]interface{}{
			"ErrorMessage": "Failed to load messages",
		})
	}

	viewMessages := make([]SecureMessageView, len(messages))
	for i, msg := range messages {
		truncatedID := msg.ID
		if len(truncatedID) > 8 {
			truncatedID = truncatedID[:8]
		}

		formattedTime := msg.ExpiresAt.UTC().Format("Jan 2, 2006 15:04 MST")

		viewMessages[i] = SecureMessageView{
			FullID:             msg.ID,
			ID:                 truncatedID,
			Content:            "[Encrypted]",
			FormattedExpiresAt: formattedTime,
			ViewOnce:           msg.ViewOnce,
			Viewed:             msg.Viewed,
		}
	}

	csrfToken, _ := c.Get("csrf").(string)
	nonce, _ := c.Get("nonce").(string)

	data := map[string]interface{}{
		"Messages":     viewMessages,
		"CurrentPage":  page,
		"CurrentLimit": limit,
		"CSRFToken":    csrfToken,
		"Nonce":        nonce,
	}

	return c.Render(200, "admin.html", data)
}

func (ac *AdminController) DeleteSecureMessageHandler(c echo.Context) error {
	id := c.Param("id")

	if err := config.GetDB().Delete(&models.SecureMessage{}, "id = ?", id).Error; err != nil {
		return c.Render(500, "error.html", map[string]interface{}{
			"ErrorMessage": "Failed to delete message",
		})
	}
	return c.Redirect(303, "/admin/messages")
}

func (ac *AdminController) DeleteAllSecureMessagesHandler(c echo.Context) error {
	if err := config.GetDB().Delete(&models.SecureMessage{}).Error; err != nil {
		return c.Render(500, "error.html", map[string]interface{}{
			"ErrorMessage": "Failed to delete messages",
		})
	}
	return c.Redirect(303, "/admin/messages")
}

func (ac *AdminController) DeleteKeyHandler(c echo.Context) error {
	id := c.Param("id")
	config.GetLogger().Warnf("Attempted to delete key %s, but no key deletion logic implemented.", id)
	return c.Render(404, "error.html", map[string]interface{}{
		"ErrorMessage": "Key deletion logic not implemented.",
	})
}

func (ac *AdminController) DeleteAllKeysHandler(c echo.Context) error {
	config.GetLogger().Warn("Attempted to delete all keys, but no key deletion logic implemented.")
	return c.Render(404, "error.html", map[string]interface{}{
		"ErrorMessage": "Key deletion logic not implemented.",
	})
}

func (ac *AdminController) RegenerateAESKeyHandler(c echo.Context) error {
	logger := config.GetLogger()
	logger.Info("Starting AES key regeneration...")

	// Generate a new AES key
	encService := services.NewEncryptionService()
	newAESKey, err := encService.GenerateAESKey()
	if err != nil {
		logger.WithError(err).Error("Failed to generate new AES key")
		return c.Render(500, "error.html", map[string]interface{}{
			"ErrorMessage": "Failed to generate AES key",
		})
	}

	// Retrieve old AES key
	oldAESKey, err := config.GetSecureKey("aes")
	if err != nil {
		logger.WithError(err).Error("Failed to retrieve old AES key from config")
		return c.Render(500, "error.html", map[string]interface{}{
			"ErrorMessage": "Failed to retrieve old AES key",
		})
	}

	oldBlock, err := aes.NewCipher(oldAESKey)
	if err != nil {
		logger.WithError(err).Error("Failed to create old cipher block")
		return c.Render(500, "error.html", map[string]interface{}{
			"ErrorMessage": "Failed to handle old AES block",
		})
	}
	oldGCM, err := cipher.NewGCM(oldBlock)
	if err != nil {
		logger.WithError(err).Error("Failed to create old GCM")
		return c.Render(500, "error.html", map[string]interface{}{
			"ErrorMessage": "Failed to handle old AES GCM",
		})
	}

	newBlock, err := aes.NewCipher(newAESKey)
	if err != nil {
		logger.WithError(err).Error("Failed to create new cipher block")
		return c.Render(500, "error.html", map[string]interface{}{
			"ErrorMessage": "Failed to handle new AES block",
		})
	}
	newGCM, err := cipher.NewGCM(newBlock)
	if err != nil {
		logger.WithError(err).Error("Failed to create new GCM")
		return c.Render(500, "error.html", map[string]interface{}{
			"ErrorMessage": "Failed to handle new AES GCM",
		})
	}

	db := config.GetDB()

	// Select messages to re-encrypt: Not expired and not (view_once && viewed)
	now := time.Now().UTC()
	var reencryptMessages []models.SecureMessage
	if err := db.Where("(expires_at > ? OR expires_at = ?) AND NOT (view_once = ? AND viewed = ?)",
		now, time.Time{}, true, true).Find(&reencryptMessages).Error; err != nil {
		logger.WithError(err).Error("Failed to find messages for re-encryption")
		return c.Render(500, "error.html", map[string]interface{}{
			"ErrorMessage": "Failed to retrieve messages for re-encryption",
		})
	}

	logger.Infof("Found %d messages to re-encrypt", len(reencryptMessages))

	for i, msg := range reencryptMessages {
		ciphertext := []byte(msg.Content)
		if len(ciphertext) < oldGCM.NonceSize() {
			logger.Warnf("Skipping message %s: ciphertext too short", msg.ID)
			continue
		}
		oldNonce, oldEncrypted := ciphertext[:oldGCM.NonceSize()], ciphertext[oldGCM.NonceSize():]

		plaintext, decErr := oldGCM.Open(nil, oldNonce, oldEncrypted, nil)
		if decErr != nil {
			logger.WithError(decErr).Warnf("Skipping message %s: failed to decrypt with old key", msg.ID)
			continue
		}

		newNonce := make([]byte, newGCM.NonceSize())
		if _, err := rand.Read(newNonce); err != nil {
			logger.WithError(err).Warnf("Skipping message %s: failed to generate new nonce", msg.ID)
			continue
		}
		newCiphertext := newGCM.Seal(newNonce, newNonce, plaintext, nil)
		reencryptMessages[i].Content = string(newCiphertext)
	}

	// Save updated messages
	for _, msg := range reencryptMessages {
		if err := db.Save(&msg).Error; err != nil {
			logger.WithError(err).Warnf("Failed to save re-encrypted message %s", msg.ID)
			// continue, not fatal
		}
	}

	// Update config with the new AES key
	if err := config.SetSecureKey("aes", newAESKey); err != nil {
		logger.WithError(err).Error("Failed to update config with new AES key")
		return c.Render(500, "error.html", map[string]interface{}{
			"ErrorMessage": "Failed to update AES key in config",
		})
	}

	logger.Infof("AES key successfully regenerated and messages re-encrypted where applicable.")

	csrfToken, _ := c.Get("csrf").(string)
	nonce, _ := c.Get("nonce").(string)

	return c.Render(200, "success.html", map[string]interface{}{
		"Message":   fmt.Sprintf("AES key regenerated successfully. Re-encrypted %d messages.", len(reencryptMessages)),
		"CSRFToken": csrfToken,
		"Nonce":     nonce,
	})
}

// RegenerateCSRFKeyHandler regenerates the CSRF key.
func (ac *AdminController) RegenerateCSRFKeyHandler(c echo.Context) error {
	logger := config.GetLogger()
	logger.Info("Regenerating CSRF key...")

	// Generate a new CSRF key
	newCSRFKey, err := utils.GenerateSecureID() // A secure random key
	if err != nil {
		logger.WithError(err).Error("Failed to generate new CSRF key")
		return c.Render(500, "error.html", map[string]interface{}{
			"ErrorMessage": "Failed to regenerate CSRF key",
		})
	}

	// Update the configuration with the new CSRF key
	err = config.SetCSRFKey(newCSRFKey)
	if err != nil {
		logger.WithError(err).Error("Failed to update configuration with new CSRF key")
		return c.Render(500, "error.html", map[string]interface{}{
			"ErrorMessage": "Failed to update CSRF key in config",
		})
	}

	logger.Info("CSRF key successfully regenerated")

	// Send success response
	csrfToken, _ := c.Get("csrf").(string)
	nonce, _ := c.Get("nonce").(string)

	return c.Render(200, "success.html", map[string]interface{}{
		"Message":   "CSRF key regenerated successfully.",
		"CSRFToken": csrfToken,
		"Nonce":     nonce,
	})
}

func (ac *AdminController) ViewDatabaseHandler(c echo.Context) error {
	logger := config.GetLogger()

	// Fetch all secure messages
	var messages []models.SecureMessage
	if err := config.GetDB().Order("created_at desc").Find(&messages).Error; err != nil {
		logger.WithError(err).Error("Failed to fetch database entries")
		return ac.respondWithError(c, http.StatusInternalServerError, "Failed to load database entries")
	}

	// Prepare the data for rendering
	csrfToken, _ := c.Get("csrf").(string)
	nonce, _ := c.Get("nonce").(string)

	data := map[string]interface{}{
		"Messages":  messages,
		"CSRFToken": csrfToken,
		"Nonce":     nonce,
	}

	return c.Render(http.StatusOK, "db_view.html", data)
}

// respondWithError returns a JSON response with the given status code and error message.
func (ac *AdminController) respondWithError(c echo.Context, status int, message string) error {
	return c.JSON(status, map[string]interface{}{
		"error": message,
	})
}
