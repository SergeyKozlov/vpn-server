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

// SetUsers replaces the userpass credential map wholesale and forces
// auth.type to "userpass".
func (c *Config) SetUsers(users map[string]string) {
	c.Auth.Type = "userpass"
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
