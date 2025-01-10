package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sirupsen/logrus"

	"local/securemessages/internal/config"
	"local/securemessages/internal/renderer"
	"local/securemessages/internal/routes"
	"local/securemessages/internal/services"
	"local/securemessages/pkg/utils"
)

func main() {
	// Initialize logger + config
	config.InitViperAndLogger()

	env := utils.GetEnv("ENV", "production")
	logrus.Infof("Running in %s environment", env)
	if env == "development" {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	if err := config.InitConfig(); err != nil {
		logrus.Fatalf("Failed to init config: %v", err)
	}
	if err := config.InitSessionStore(); err != nil {
		logrus.Fatalf("Failed to init session store: %v", err)
	}
	if err := config.InitDatabase(); err != nil {
		logrus.Fatalf("Failed to init database: %v", err)
	}

	e := echo.New()

	// Use Echo’s renderer for templates
	e.Renderer = renderer.NewTemplateRenderer("templates/*.html")

	// Built-in middlewares
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: `{"time":"${time_rfc3339}","remote_ip":"${remote_ip}","request_id":"${id}","host":"${host}","method":"${method}","uri":"${uri}","status":${status}}` + "\n",
		Output: os.Stdout,
	}))
	// If behind Traefik, you can also do:
	// e.Use(middleware.ProxyHeaders())

	// Serve static assets from ./assets
	e.Static("/assets", "assets")

	// Initialize Echo routes
	routes.InitRoutes(e)

	// Start cleanup goroutines
	go services.CleanupExpiredMessages()
	go services.CleanupViewedMessages()

	// Start server
	address := config.GetAddress()
	logrus.Infof("Starting Echo server on %s", address)
	go func() {
		if err := e.Start(address); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("Echo server error: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	logrus.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		logrus.Fatalf("Server forced to shutdown: %v", err)
	}

	logrus.Info("Server exited cleanly")
}
