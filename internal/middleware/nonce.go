package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"

	"local/securemessages/pkg/utils"
)

func NonceMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Generate a secure nonce
		nonce, err := utils.GenerateNonce()
		if err != nil {
			logrus.WithError(err).WithField("middleware", "NonceMiddleware").Error("Failed to generate nonce")
			return c.String(http.StatusInternalServerError, "A security configuration error occurred.")
		}

		// Construct the CSP header
		csp := strings.Join([]string{
			"default-src 'self'",
			"script-src 'self' 'nonce-" + nonce + "'",
			"style-src 'self' 'nonce-" + nonce + "' https://fonts.googleapis.com",
			"font-src 'self' https://fonts.gstatic.com",
			"img-src 'self' data:",
			"connect-src 'self'",
			"frame-ancestors 'self'",
		}, "; ")

		// Log the CSP for debugging purposes
		logrus.WithField("CSP", csp).Debug("Setting Content-Security-Policy header")

		// Set the CSP header
		c.Response().Header().Set("Content-Security-Policy", csp)

		// Make the nonce available to templates
		c.Set("nonce", nonce)

		// Continue to the next handler
		return next(c)
	}
}
