package middleware

import (
	"github.com/labstack/echo/v4"
)

// SecurityHeadersMiddleware adds common security headers (CSP, X-Frame, etc.).
func SecurityHeadersMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set("X-Content-Type-Options", "nosniff")
		c.Response().Header().Set("X-Frame-Options", "SAMEORIGIN")
		c.Response().Header().Set("X-XSS-Protection", "1; mode=block")
		c.Response().Header().Set("Referrer-Policy", "no-referrer-when-downgrade")
		c.Response().Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// Minimal default CSP - or let NonceMiddleware override
		if c.Response().Header().Get("Content-Security-Policy") == "" {
			c.Response().Header().Set("Content-Security-Policy", "default-src 'self'")
		}
		return next(c)
	}
}
