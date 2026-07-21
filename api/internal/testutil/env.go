// Package testutil provides shared helpers for integration tests. LoadEnv
// keeps live test runs pointed at .env.test (a dummy XUI/Hysteria/DB
// config) instead of the production .env this host also carries — see
// ai_from_local/TZ_P2.3_SelfRegistration_Trial.md §7.
package testutil

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

const maxUpwardSearchDepth = 10

// LoadEnv locates the file named by ENV_FILE (default .env.test) by
// walking upward from the current working directory — necessary because
// `go test ./...` runs each package's test binary with that package's own
// directory as cwd, while .env.test lives at the repo root. Existing
// environment variables always win: a KEY=VALUE line is only applied if
// os.LookupEnv(KEY) reports unset. A missing file is a silent no-op, never
// an error, so a forgotten .env.test doesn't break `go test`.
func LoadEnv() {
	name := os.Getenv("ENV_FILE")
	if name == "" {
		name = ".env.test"
	}

	path := findUpward(name)
	if path == "" {
		return
	}

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if _, set := os.LookupEnv(key); !set {
			os.Setenv(key, value)
		}
	}
}

func findUpward(name string) string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}

	for range maxUpwardSearchDepth {
		candidate := filepath.Join(dir, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}
