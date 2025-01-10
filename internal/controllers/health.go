package controllers

import (
	"net/http"

	"local/securemessages/internal/config"

	"github.com/labstack/echo/v4"
)

func HealthCheck(c echo.Context) error {
	config.GetLogger().Info("Health check endpoint hit")
	return c.String(http.StatusOK, "OK")
}
