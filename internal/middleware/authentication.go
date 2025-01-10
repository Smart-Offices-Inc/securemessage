package middleware

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"local/securemessages/internal/config"
)

func AuthenticationMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		logger := config.GetLogger()

		username, password, ok := c.Request().BasicAuth()
		if !ok {
			logger.Warn("Auth failed: missing BasicAuth creds")
			c.Response().Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			return c.String(http.StatusUnauthorized, "Unauthorized")
		}

		if username != config.GetAdminUsername() || password != config.GetAdminPassword() {
			logger.Warnf("Auth failed: invalid credentials for user '%s'", username)
			c.Response().Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			return c.String(http.StatusUnauthorized, "Unauthorized")
		}

		logger.Infof("Auth successful for user '%s'", username)
		return next(c)
	}
}
