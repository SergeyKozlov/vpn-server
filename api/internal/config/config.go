package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Port        string
	DatabaseURL string

	EncryptionKey     string // base64-encoded 32-byte AES-256 key
	SessionSigningKey string // base64-encoded 32-byte HMAC key for session cookies

	XUIBaseURL   string // must include the panel's webBasePath
	XUIAPIToken  string
	XUIInboundID int

	HysteriaConfigPath    string
	HysteriaReloadCommand string
}

func Load() (*Config, error) {
	databaseURL, err := requireEnv("DATABASE_URL")
	if err != nil {
		return nil, err
	}

	encryptionKey, err := requireEnv("APP_ENC_KEY")
	if err != nil {
		return nil, err
	}

	sessionSigningKey, err := requireEnv("SESSION_SIGNING_KEY")
	if err != nil {
		return nil, err
	}

	xuiBaseURL, err := requireEnv("XUI_BASE_URL")
	if err != nil {
		return nil, err
	}

	xuiAPIToken, err := requireEnv("XUI_API_TOKEN")
	if err != nil {
		return nil, err
	}

	hysteriaConfigPath, err := requireEnv("HYSTERIA_CONFIG_PATH")
	if err != nil {
		return nil, err
	}

	hysteriaReloadCommand, err := requireEnv("HYSTERIA_RELOAD_COMMAND")
	if err != nil {
		return nil, err
	}

	xuiInboundID := 1
	if v := os.Getenv("XUI_INBOUND_ID"); v != "" {
		xuiInboundID, err = strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("XUI_INBOUND_ID: %w", err)
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	return &Config{
		Port:                  port,
		DatabaseURL:           databaseURL,
		EncryptionKey:         encryptionKey,
		SessionSigningKey:     sessionSigningKey,
		XUIBaseURL:            xuiBaseURL,
		XUIAPIToken:           xuiAPIToken,
		XUIInboundID:          xuiInboundID,
		HysteriaConfigPath:    hysteriaConfigPath,
		HysteriaReloadCommand: hysteriaReloadCommand,
	}, nil
}

func requireEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return v, nil
}
