package utils

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func GenerateSecureKey(length int, urlSafe bool) (string, error) {
	logrus.WithFields(logrus.Fields{"length": length, "urlSafe": urlSafe}).Trace("Generating secure key")

	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		logrus.WithError(err).Error("Failed to generate random bytes for secure key")
		return "", err
	}
	if urlSafe {
		return base64.URLEncoding.EncodeToString(b), nil
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func GenerateSecureID() (string, error) {
	u := uuid.New()
	logrus.WithField("uuid", u.String()).Debug("Generated UUID for message ID")
	return u.String(), nil
}

func GetEnv(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		logrus.Warnf("Environment variable %s not found, using default value: %s", key, defaultValue)
		return defaultValue
	}
	return value
}

func GetEnvInt(key string, defaultValue int) (int, error) {
	val := GetEnv(key, "")
	if val == "" {
		return defaultValue, nil
	}
	intValue, err := strconv.Atoi(val)
	if err != nil {
		logrus.WithError(err).Error("Failed to parse env variable as int")
		return 0, err
	}
	return intValue, nil
}

//	func GetBaseURL(r *http.Request) string {
//		scheme := "http"
//		if r.TLS != nil {
//			scheme = "https"
//		}
//		return scheme + "://" + r.Host
//	}
//
// GetBaseURL constructs the base URL for generating links.
func GetBaseURL(r *http.Request) string {
	scheme := "http"

	// Check if the request is TLS
	if r.TLS != nil {
		scheme = "https"
	} else {
		// Fallback: Check the X-Forwarded-Proto header
		forwardedProto := r.Header.Get("X-Forwarded-Proto")
		if strings.EqualFold(forwardedProto, "https") {
			scheme = "https"
		}
	}

	host := r.Host
	return scheme + "://" + host
}

func CalculateTimeRemaining(expiresAt time.Time) string {
	if expiresAt.IsZero() {
		return "Never"
	}
	duration := time.Until(expiresAt)
	if duration <= 0 {
		return "Expired"
	}
	return duration.Truncate(time.Second).String()
}

func GetExpiration(duration string) time.Time {
	switch duration {
	case "5min":
		return time.Now().Add(5 * time.Minute)
	case "30min":
		return time.Now().Add(30 * time.Minute)
	case "1hour":
		return time.Now().Add(1 * time.Hour)
	case "1day":
		return time.Now().Add(24 * time.Hour)
	case "7days":
		return time.Now().Add(7 * 24 * time.Hour)
	case "forever":
		return time.Time{} // no expiration
	default:
		return time.Now().Add(24 * time.Hour)
	}
}

// Nonce helpers
func GenerateNonce() (string, error) {
	b := make([]byte, 16) // 128-bit nonce
	if _, err := rand.Read(b); err != nil {
		logrus.WithError(err).Error("Failed to generate nonce")
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

type contextKey string

var nonceKey = contextKey("nonce")

func SetNonceInContext(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, nonceKey, nonce)
}

func GetNonceFromContext(ctx context.Context) string {
	val, _ := ctx.Value(nonceKey).(string)
	return val
}

// Truncate shortens a string to the specified length and appends "..." if truncated.
func Truncate(input string, length int) string {
	if len(input) > length {
		return strings.TrimSpace(input[:length]) + "..."
	}
	return input
}
