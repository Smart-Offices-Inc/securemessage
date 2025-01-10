package routes

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"

	"local/securemessages/internal/controllers"
	"local/securemessages/internal/middleware"
)

func InitRoutes(e *echo.Echo) {
	logrus.Info("Initializing Echo routes...")

	// Middlewares
	e.Use(middleware.SecurityHeadersMiddleware)
	e.Use(middleware.CsrfMiddleware)
	e.Use(middleware.NonceMiddleware)

	// Health
	e.GET("/health", controllers.HealthCheck)

	// Messages
	messageController := controllers.NewMessageController()
	e.GET("/", messageController.ServeCreateForm)
	e.POST("/create", messageController.CreateSecureMessage)

	// Handle disallowed methods for /create
	e.Match([]string{echo.GET, echo.PUT, echo.PATCH, echo.DELETE}, "/create", func(c echo.Context) error {
		return c.JSON(http.StatusMethodNotAllowed, map[string]interface{}{
			"error": "Method not allowed. Please use the POST method to create a secure message.",
		})
	})

	e.GET("/messages/:id", messageController.GetSecureMessage)
	e.POST("/messages/:id/verify", messageController.VerifyPassword)

	// Admin
	adminController := controllers.NewAdminController()
	admin := e.Group("/admin", middleware.AuthenticationMiddleware)

	// Admin messages
	admin.GET("/messages", adminController.AdminSecureMessages)
	admin.POST("/messages/:id/delete", adminController.DeleteSecureMessageHandler)
	admin.POST("/messages/deleteall", adminController.DeleteAllSecureMessagesHandler)

	// Admin keys (if you want them)
	admin.POST("/keys/:id/delete", adminController.DeleteKeyHandler)
	admin.POST("/keys/deleteall", adminController.DeleteAllKeysHandler)

	// Regenerate AES key
	admin.POST("/regenerate-key", adminController.RegenerateAESKeyHandler)

	// Regenerate CSRF key
	admin.POST("/regenerate-csrf-key", adminController.RegenerateCSRFKeyHandler)

	admin.GET("/view-database", adminController.ViewDatabaseHandler)
}
