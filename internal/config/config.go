package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"local/securemessages/internal/models"
	"local/securemessages/pkg/utils"
)

var (
	db        *gorm.DB
	appConfig AppConfig
	configMu  sync.RWMutex
	logger    *logrus.Logger
	store     *sessions.CookieStore
)

type AppConfig struct {
	Host                   string
	Port                   string
	DBPath                 string
	LogPath                string
	IsProduction           bool
	MaxSecureMessageLength int
	MasterKey              []byte
	AESKey                 []byte
	CSRFKey                []byte
	AdminUser              string
	AdminPass              string
}

func InitViperAndLogger() {
	// Bind CLI flags to Viper
	pflag.String("host", "127.0.0.1", "Host for the application")
	pflag.String("port", "9203", "Port for the application")
	pflag.String("db_path", "./data/securemessages.db", "Path to the database file")
	pflag.String("log_path", "./logs/app.log", "Path to the log file")
	pflag.String("log_level", "info", "Log level (info, debug, warn, error)")
	pflag.Int("max_secure_message_length", 5000, "Maximum length for secure messages")
	pflag.Bool("is_production", false, "Run in production mode")
	pflag.String("master_key", "", "Base64-encoded master key")
	pflag.String("aes_key", "", "Base64-encoded AES key")
	pflag.String("csrf_auth_key", "", "Base64-encoded CSRF authentication key")
	pflag.String("admin_username", "admin", "Admin username")
	pflag.String("admin_password", "password", "Admin password")

	// Parse CLI flags
	pflag.Parse()

	// Bind flags to Viper
	viper.BindPFlags(pflag.CommandLine)

	// Set environment variable bindings
	viper.AutomaticEnv()

	// Defaults
	viper.SetDefault("host", "127.0.0.1")
	viper.SetDefault("port", "9203")
	viper.SetDefault("log_level", "info")
	viper.SetDefault("db_path", "./data/securemessages.db")
	viper.SetDefault("log_path", "./logs/app.log")
	viper.SetDefault("max_secure_message_length", 5000)
	viper.SetDefault("is_production", false)

	// Initialize logger
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logLevel, err := logrus.ParseLevel(viper.GetString("log_level"))
	if err != nil {
		logLevel = logrus.InfoLevel
		logger.Warn("Invalid log level specified. Defaulting to 'info'.")
	}
	logger.SetLevel(logLevel)
}

func InitConfig() error {
	logger.Info("Initializing application configuration...")

	appConfig.Host = viper.GetString("host")
	appConfig.Port = viper.GetString("port")
	appConfig.DBPath = viper.GetString("db_path")
	appConfig.LogPath = viper.GetString("log_path")
	appConfig.IsProduction = viper.GetBool("is_production")
	appConfig.MaxSecureMessageLength = viper.GetInt("max_secure_message_length")

	if err := initKeys(); err != nil {
		logger.Errorf("Failed to initialize keys: %v", err)
		return err
	}

	appConfig.AdminUser = viper.GetString("admin_username")
	appConfig.AdminPass = viper.GetString("admin_password")

	logger.Info("Application configuration initialized successfully.")
	return saveConfig()
}

func initKeys() error {
	logger.Info("Initializing encryption keys...")

	// MASTER_KEY
	masterKeyBase64 := viper.GetString("master_key")
	if masterKeyBase64 == "" {
		logger.Warn("MASTER_KEY not provided. Generating new one...")
		newKey, err := utils.GenerateSecureKey(32, false)
		if err != nil {
			return fmt.Errorf("failed to generate MASTER_KEY: %w", err)
		}
		decodedKey, err := base64.StdEncoding.DecodeString(newKey)
		if err != nil || len(decodedKey) != 32 {
			return fmt.Errorf("MASTER_KEY must decode to 32 bytes: %w", err)
		}
		appConfig.MasterKey = decodedKey
		viper.Set("master_key", newKey)
		logger.Info("Generated and set new MASTER_KEY.")
	} else {
		masterKey, err := base64.StdEncoding.DecodeString(masterKeyBase64)
		if err != nil || len(masterKey) != 32 {
			return fmt.Errorf("MASTER_KEY must be a valid 32-byte base64 string")
		}
		appConfig.MasterKey = masterKey
		logger.Info("Loaded MASTER_KEY from configuration.")
	}

	// AES_KEY
	aesKeyBase64 := viper.GetString("aes_key")
	if aesKeyBase64 == "" {
		logger.Warn("AES_KEY not provided. Generating new one...")
		newKey, err := utils.GenerateSecureKey(32, false)
		if err != nil {
			logger.WithError(err).Error("Failed to generate AES_KEY")
			return fmt.Errorf("failed to generate AES_KEY: %w", err)
		}
		decodedKey, err := base64.StdEncoding.DecodeString(newKey)
		if err != nil || len(decodedKey) != 32 {
			return fmt.Errorf("AES_KEY must decode to 32 bytes")
		}
		appConfig.AESKey = decodedKey
		viper.Set("aes_key", newKey)
		logger.Info("Generated and set a new AES_KEY.")
	} else {
		aesKey, err := base64.StdEncoding.DecodeString(aesKeyBase64)
		if err != nil || len(aesKey) != 32 {
			return fmt.Errorf("AES_KEY must decode to 32 bytes")
		}
		appConfig.AESKey = aesKey
		logger.Info("Loaded AES_KEY from configuration.")
	}

	// CSRF_AUTH_KEY
	csrfKeyBase64 := viper.GetString("csrf_auth_key")
	if csrfKeyBase64 == "" {
		logger.Warn("CSRF_AUTH_KEY not provided. Generating new one...")
		newKey, err := utils.GenerateSecureKey(32, false)
		if err != nil {
			logger.WithError(err).Error("Failed to generate CSRF_AUTH_KEY")
			return fmt.Errorf("failed to generate CSRF_AUTH_KEY: %w", err)
		}
		decodedKey, err := base64.StdEncoding.DecodeString(newKey)
		if err != nil || len(decodedKey) != 32 {
			return fmt.Errorf("CSRF_AUTH_KEY must decode to 32 bytes")
		}
		appConfig.CSRFKey = decodedKey
		viper.Set("csrf_auth_key", newKey)
		logger.Info("Generated and set a new CSRF_AUTH_KEY.")
	} else {
		csrfKey, err := base64.StdEncoding.DecodeString(csrfKeyBase64)
		if err != nil || len(csrfKey) != 32 {
			return fmt.Errorf("CSRF_AUTH_KEY must decode to 32 bytes")
		}
		appConfig.CSRFKey = csrfKey
		logger.Info("Loaded CSRF_AUTH_KEY from configuration.")
	}

	return nil
}

func getOrGenerateAdminCredential(key, defaultValue string) string {
	value := viper.GetString(key)
	if value == "" {
		logger.Warnf("%s not provided. Generating new one...", key)
		newValue, err := utils.GenerateSecureKey(16, true)
		if err != nil {
			logger.Fatalf("Failed to generate secure key for %s: %v", key, err)
		}
		viper.Set(key, newValue)
		return newValue
	}
	return value
}

func saveConfig() error {
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		configFile = "./config/config.yml"
	}

	logger.Infof("Saving updated configuration to %s", configFile)
	dir := filepath.Dir(configFile)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}

	if err := viper.WriteConfigAs(configFile); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}
	return nil
}

func InitDatabase() error {
	logger.Info("Initializing database connection...")
	dbPath := appConfig.DBPath

	dbDir := filepath.Dir(dbPath)
	if _, err := os.Stat(dbDir); os.IsNotExist(err) {
		logger.Warnf("Database directory does not exist at %s, creating it.", dbDir)
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			return fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	var err error
	db, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
		return err
	}

	if err := db.AutoMigrate(&models.SecureMessage{}, &models.AppConfig{}); err != nil {
		logger.Errorf("Failed to migrate DB schema: %v", err)
		return err
	}

	logger.Info("Database connection established.")
	return nil
}

func InitSessionStore() error {
	logger.Info("Initializing session store...")

	sessionKeyBase64 := viper.GetString("session_key")
	if sessionKeyBase64 == "" {
		logger.Warn("SESSION_KEY not provided. Generating new one...")
		newKey, err := utils.GenerateSecureKey(32, false)
		if err != nil {
			logger.WithError(err).Error("Failed to generate SESSION_KEY")
			return fmt.Errorf("failed to generate SESSION_KEY: %w", err)
		}
		decodedKey, err := base64.StdEncoding.DecodeString(newKey)
		if err != nil || len(decodedKey) != 32 {
			return fmt.Errorf("SESSION_KEY must decode to 32 bytes: %w", err)
		}
		viper.Set("session_key", newKey)
		sessionKeyBase64 = newKey
		logger.Info("Generated and set a new SESSION_KEY.")
	}

	sessionKey, err := base64.StdEncoding.DecodeString(sessionKeyBase64)
	if err != nil || len(sessionKey) != 32 {
		return fmt.Errorf("SESSION_KEY must decode to 32 bytes")
	}

	store = sessions.NewCookieStore(sessionKey)
	store.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   IsProduction(), // <--- same logic
	}

	return saveConfig()
}

func GetSessionStore() *sessions.CookieStore {
	return store
}

func GetLogger() *logrus.Logger {
	return logger
}

func GetDB() *gorm.DB {
	return db
}

func GetSecureKey(keyType string) ([]byte, error) {
	switch keyType {
	case "master":
		return appConfig.MasterKey, nil
	case "aes":
		return appConfig.AESKey, nil
	case "csrf":
		return appConfig.CSRFKey, nil
	default:
		return nil, fmt.Errorf("unknown key type: %s", keyType)
	}
}

func SetSecureKey(keyType string, newKey []byte) error {
	configMu.Lock()
	defer configMu.Unlock()

	if len(newKey) != 32 {
		return fmt.Errorf("invalid key length: expected 32 bytes, got %d", len(newKey))
	}

	switch keyType {
	case "master":
		appConfig.MasterKey = newKey
	case "aes":
		appConfig.AESKey = newKey
	case "csrf":
		appConfig.CSRFKey = newKey
	default:
		return fmt.Errorf("unknown key type: %s", keyType)
	}

	logger.Infof("Secure key for '%s' updated.", keyType)
	return nil
}

func GetAdminUsername() string {
	configMu.RLock()
	defer configMu.RUnlock()
	return appConfig.AdminUser
}

func GetAdminPassword() string {
	configMu.RLock()
	defer configMu.RUnlock()
	return appConfig.AdminPass
}

func GetMaxSecureMessageLength() int {
	return appConfig.MaxSecureMessageLength
}

func GetAddress() string {
	return fmt.Sprintf("%s:%s", appConfig.Host, appConfig.Port)
}

func IsProduction() bool {
	return appConfig.IsProduction
}

func GetNow() time.Time {
	return time.Now().UTC()
}

// SetCSRFKey updates the CSRF key in the configuration and persists it.
func SetCSRFKey(value string) error {
	viper.Set("csrf_key", value) // Save the key with a specific identifier
	return viper.WriteConfig()   // Write it back to the config file
}
