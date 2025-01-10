package controllers

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm/clause"

	"local/securemessages/internal/config"
	"local/securemessages/internal/models"
	"local/securemessages/internal/services"
	"local/securemessages/pkg/utils"
)

type MessageController struct {
	EncryptionService *services.EncryptionService
}

func NewMessageController() *MessageController {
	return &MessageController{
		EncryptionService: services.NewEncryptionService(),
	}
}

func (mc *MessageController) ServeCreateForm(c echo.Context) error {
	data := map[string]interface{}{
		"MaxMessageLength": config.GetMaxSecureMessageLength(),
		"CSRFToken":        c.Get("csrf"),
		"Nonce":            c.Get("nonce"),
	}
	return c.Render(http.StatusOK, "form.html", data)
}

func (mc *MessageController) CreateSecureMessage(c echo.Context) error {
	log := config.GetLogger()
	log.Info("Handling request to create a secure message")
	// Debug logging
	logrus.WithFields(logrus.Fields{
		"method":    c.Request().Method,
		"csrf":      c.Request().Header.Get("X-CSRF-Token"),
		"form_csrf": c.FormValue("_csrf"),
	}).Info("Create message request received")

	// Parse form data
	if err := c.Request().ParseForm(); err != nil {
		log.WithError(err).Error("Failed to parse form data")
		return mc.respondWithError(c, http.StatusBadRequest, "Invalid form data")
	}

	// Validate content
	content := c.FormValue("content")
	maxContentLength := config.GetMaxSecureMessageLength()
	if len(content) == 0 {
		log.Error("Secure message content is empty")
		return mc.respondWithError(c, http.StatusBadRequest, "Message content cannot be empty")
	}
	if len(content) > maxContentLength {
		log.Errorf("Message content length (%d) exceeds limit (%d)", len(content), maxContentLength)
		return mc.respondWithError(c, http.StatusBadRequest, "Message content exceeds maximum length")
	}

	// Process other form fields
	expiration := utils.GetExpiration(c.FormValue("expiration"))
	viewOnce := c.FormValue("view_once") == "on"
	password := c.FormValue("password")

	// Hash password if provided
	var passwordHash string
	if password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.WithError(err).Error("Failed to hash password")
			return mc.respondWithError(c, http.StatusInternalServerError, "Error processing password")
		}
		passwordHash = string(hashedPassword)
	}

	// Generate secure message ID
	id, err := utils.GenerateSecureID()
	if err != nil {
		log.WithError(err).Error("Failed to generate secure message ID")
		return mc.respondWithError(c, http.StatusInternalServerError, "Error generating message ID")
	}

	// Encrypt content
	encryptedContent, err := mc.EncryptionService.Encrypt([]byte(content))
	if err != nil {
		log.WithError(err).Error("Failed to encrypt secure message content")
		return mc.respondWithError(c, http.StatusInternalServerError, "Error encrypting message content")
	}

	// Save to database
	secureMessage := models.SecureMessage{
		ID:           id,
		Content:      string(encryptedContent),
		PasswordHash: passwordHash,
		ExpiresAt:    expiration.UTC(),
		ViewOnce:     viewOnce,
		Viewed:       false,
		CreatedAt:    time.Now().UTC(),
	}
	if err := config.GetDB().Create(&secureMessage).Error; err != nil {
		log.WithError(err).Error("Failed to save secure message to database")
		return mc.respondWithError(c, http.StatusInternalServerError, "Error saving message to database")
	}

	// Prepare response data
	link := utils.GetBaseURL(c.Request()) + "/messages/" + id
	data := map[string]interface{}{
		"Link":              link,
		"PasswordProtected": password != "",
		"TimeoutRemaining":  utils.CalculateTimeRemaining(expiration),
		"ViewOnce":          viewOnce,
		"CSRFToken":         c.Get("csrf"),
		"Nonce":             c.Get("nonce"),
	}
	return c.Render(http.StatusOK, "share_message.html", data)
}

func (mc *MessageController) GetSecureMessage(c echo.Context) error {
	log := config.GetLogger()
	id := c.Param("id")

	// Start a transaction
	tx := config.GetDB().Begin()
	if tx.Error != nil {
		log.WithError(tx.Error).Error("Failed to start database transaction")
		return mc.respondWithError(c, http.StatusInternalServerError, "Database error")
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			log.Error("Panic recovered during transaction")
		}
	}()

	// Retrieve the message within the transaction with a row-level lock
	var message models.SecureMessage
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&message, "id = ?", id).Error; err != nil {
		tx.Rollback()
		log.WithField("id", id).Error("Message not found")
		return mc.respondWithError(c, http.StatusNotFound, "Message not found")
	}

	// Check if the message is password-protected and verify access
	if message.PasswordHash != "" {
		session, _ := config.GetSessionStore().Get(c.Request(), "session-name")
		if verified, ok := session.Values["verified_"+id].(bool); !ok || !verified {
			tx.Commit() // No changes made
			return c.Render(http.StatusOK, "password_prompt.html", map[string]interface{}{
				"SecureMessageID": id,
				"CSRFToken":       c.Get("csrf"),
				"Nonce":           c.Get("nonce"),
			})
		}
	}

	// Handle ViewOnce logic
	if message.ViewOnce && message.Viewed {
		tx.Commit() // No changes made
		log.WithFields(logrus.Fields{
			"id":        id,
			"view_once": message.ViewOnce,
			"viewed":    message.Viewed,
		}).Warn("Message no longer available due to ViewOnce logic")

		return mc.respondWithError(c, http.StatusGone, "This message was set to 'view once' and has already been viewed.")
	}

	// Decrypt the message content
	decryptedContent, err := mc.EncryptionService.Decrypt([]byte(message.Content))
	if err != nil {
		tx.Rollback()
		log.WithError(err).Error("Failed to decrypt message content")
		return mc.respondWithError(c, http.StatusInternalServerError, "Error decrypting message content")
	}

	// Update the "Viewed" status if necessary
	if !message.Viewed && message.ViewOnce {
		message.Viewed = true
		if err := tx.Save(&message).Error; err != nil {
			tx.Rollback()
			log.WithError(err).Error("Failed to update viewed status")
			return mc.respondWithError(c, http.StatusInternalServerError, "Error updating message status")
		}
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		log.WithError(err).Error("Failed to commit transaction")
		return mc.respondWithError(c, http.StatusInternalServerError, "Database error")
	}

	// Render the message content
	return c.Render(http.StatusOK, "view_message.html", map[string]interface{}{
		"Content":           string(decryptedContent),
		"PasswordProtected": message.PasswordHash != "",
		"TimeRemaining":     utils.CalculateTimeRemaining(message.ExpiresAt),
		"ViewOnce":          message.ViewOnce,
		"CSRFToken":         c.Get("csrf"),
		"Nonce":             c.Get("nonce"),
	})
}

func (mc *MessageController) VerifyPassword(c echo.Context) error {
	id := c.Param("id")

	if err := c.Request().ParseForm(); err != nil {
		return mc.respondWithError(c, http.StatusBadRequest, "Invalid form data")
	}
	password := c.FormValue("password")

	var message models.SecureMessage
	if err := config.GetDB().First(&message, "id = ?", id).Error; err != nil {
		return mc.respondWithError(c, http.StatusNotFound, "Message not found")
	}

	if message.PasswordHash == "" {
		return c.Redirect(http.StatusSeeOther, "/messages/"+id)
	}

	err := bcrypt.CompareHashAndPassword([]byte(message.PasswordHash), []byte(password))
	if err != nil {
		return mc.respondWithError(c, http.StatusUnauthorized, "Incorrect password")
	}

	session, _ := config.GetSessionStore().Get(c.Request(), "session-name")
	session.Values["verified_"+id] = true
	if err := session.Save(c.Request(), c.Response()); err != nil {
		return mc.respondWithError(c, http.StatusInternalServerError, "Error saving session data")
	}

	return c.Redirect(http.StatusSeeOther, "/messages/"+id)
}

// Helper function to respond with error
func (mc *MessageController) respondWithError(c echo.Context, status int, message string) error {
	return c.JSON(status, map[string]interface{}{
		"error": message,
	})
}
