package middleware

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"local/securemessages/internal/config"
)

// CsrfMiddleware uses Echo's CSRF middleware with ephemeral secret but a persistent cookie if production.
func CsrfMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLength:    32,
		TokenLookup:    "form:_csrf,header:X-CSRF-Token", // Check both locations
		ContextKey:     "csrf",
		CookieName:     "_csrf",
		CookiePath:     "/",
		CookieHTTPOnly: true,
		CookieSecure:   config.IsProduction(),
	})(next)
}
