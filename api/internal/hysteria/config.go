// Package hysteria manages the Hysteria2 server's config.yaml, specifically
// the auth.userpass credential map (the only auth.type that supports
// distinct per-user credentials natively — see compass_artifact.md §2).
// Changing users means rewriting config.yaml and reloading the service;
// there is no separate auth backend.
package hysteria

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config models only the auth section explicitly, since that's the only
// part this package mutates. Every other top-level key (listen, tls,
// masquerade, trafficStats, ...) round-trips through Extra untouched, so
// hand-configured settings are never dropped by a Save.
type Config struct {
	Auth  Auth                 `yaml:"auth"`
	Extra map[string]yaml.Node `yaml:",inline"`
}

type Auth struct {
	Type     string            `yaml:"type"`
	UserPass map[string]string `yaml:"userpass,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// bootstrapPlaceholderUser keeps auth.userpass non-empty when the last real
// client is removed. An empty map serializes as an absent userpass key
// (omitempty), which crashes the server on reload with "auth.userpass:
// empty auth userpass" — this placeholder has no corresponding client, so
// it grants no access. Password value is arbitrary and not a secret.
const (
	bootstrapPlaceholderUser     = "_bootstrap_no_access"
	bootstrapPlaceholderPassword = "51b43a5272b201bb0abf4398f6eca089203035b669b176d9"
)

// SetUsers replaces the userpass credential map wholesale and forces
// auth.type to "userpass".
func (c *Config) SetUsers(users map[string]string) {
	c.Auth.Type = "userpass"
	if len(users) == 0 {
		users = map[string]string{bootstrapPlaceholderUser: bootstrapPlaceholderPassword}
	}
	c.Auth.UserPass = users
}

// Save writes the config back to path with 0600 permissions, since
// auth.userpass holds plaintext Hysteria2 passwords.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
