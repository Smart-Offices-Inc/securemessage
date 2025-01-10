package middleware

import (
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

// ProxyMiddleware logs or manipulates proxy headers.
// If you just want standard 'X-Forwarded-*' parsing, use Echo’s middleware.ProxyHeaders().
func ProxyMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		forwardedProto := c.Request().Header.Get("X-Forwarded-Proto")
		if forwardedProto == "" {
			forwardedProto = "http"
		}
		logrus.WithField("ForwardedProto", forwardedProto).Debug("ProxyMiddleware invoked")

		// Example: store scheme in the context
		c.Set("scheme", forwardedProto)

		return next(c)
	}
}
