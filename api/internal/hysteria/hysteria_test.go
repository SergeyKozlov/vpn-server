package hysteria

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleConfig = `listen: :8444
tls:
  cert: /etc/hysteria/cert.pem
  key: /etc/hysteria/key.key
auth:
  type: userpass
  userpass:
    user_ab12cd: s3cretPass1
    user_ef34gh: s3cretPass2
masquerade:
  type: proxy
  proxy:
    url: https://news.ycombinator.com/
    rewriteHost: true
trafficStats:
  listen: 127.0.0.1:9999
  secret: some_strong_api_secret
`

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoadConfigParsesAuth(t *testing.T) {
	path := writeTempConfig(t, sampleConfig)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Auth.Type != "userpass" {
		t.Errorf("Auth.Type = %q, want userpass", cfg.Auth.Type)
	}
	want := map[string]string{"user_ab12cd": "s3cretPass1", "user_ef34gh": "s3cretPass2"}
	if len(cfg.Auth.UserPass) != len(want) {
		t.Fatalf("UserPass = %v, want %v", cfg.Auth.UserPass, want)
	}
	for k, v := range want {
		if cfg.Auth.UserPass[k] != v {
			t.Errorf("UserPass[%q] = %q, want %q", k, cfg.Auth.UserPass[k], v)
		}
	}
}

func TestSetUsersPreservesOtherSections(t *testing.T) {
	path := writeTempConfig(t, sampleConfig)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	newUsers := map[string]string{"user_new1": "pw1"}
	cfg.SetUsers(newUsers)

	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file perm = %o, want 0600", perm)
	}

	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("reload LoadConfig: %v", err)
	}

	if reloaded.Auth.Type != "userpass" {
		t.Errorf("Auth.Type = %q, want userpass", reloaded.Auth.Type)
	}
	if len(reloaded.Auth.UserPass) != 1 || reloaded.Auth.UserPass["user_new1"] != "pw1" {
		t.Errorf("UserPass = %v, want map[user_new1:pw1]", reloaded.Auth.UserPass)
	}
	if _, exists := reloaded.Auth.UserPass["user_ab12cd"]; exists {
		t.Errorf("old user user_ab12cd should have been replaced, not merged")
	}

	// Untouched sections must round-trip.
	listenNode, ok := reloaded.Extra["listen"]
	if !ok || listenNode.Value != ":8444" {
		t.Errorf("listen = %+v, want :8444", listenNode)
	}
	if _, ok := reloaded.Extra["tls"]; !ok {
		t.Errorf("tls section was dropped")
	}
	if _, ok := reloaded.Extra["masquerade"]; !ok {
		t.Errorf("masquerade section was dropped")
	}
	if _, ok := reloaded.Extra["trafficStats"]; !ok {
		t.Errorf("trafficStats section was dropped")
	}
}

func TestSetUsersSwitchesFromPasswordType(t *testing.T) {
	path := writeTempConfig(t, "listen: :8444\nauth:\n  type: password\n  password: shared-secret\n")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	cfg.SetUsers(map[string]string{"user_a": "pw"})
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("reload LoadConfig: %v", err)
	}
	if reloaded.Auth.Type != "userpass" {
		t.Errorf("Auth.Type = %q, want userpass", reloaded.Auth.Type)
	}
}

// TestSetUsersEmptyMapKeepsUserpassNonEmpty guards against a confirmed
// production bug: an empty userpass map serializes with the key omitted
// (yaml:",omitempty"), and Hysteria2 refuses to start with "auth.userpass:
// empty auth userpass". Removing the last client must not produce that.
func TestSetUsersEmptyMapKeepsUserpassNonEmpty(t *testing.T) {
	path := writeTempConfig(t, sampleConfig)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	cfg.SetUsers(map[string]string{})
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("reload LoadConfig: %v", err)
	}
	if reloaded.Auth.Type != "userpass" {
		t.Errorf("Auth.Type = %q, want userpass", reloaded.Auth.Type)
	}
	if len(reloaded.Auth.UserPass) == 0 {
		t.Fatalf("auth.userpass is empty after removing all users — server would fail to start")
	}
}

func TestReloadRunsCommand(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "reloaded")

	if err := Reload(context.Background(), "touch "+marker); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if _, err := os.Stat(marker); err != nil {
		t.Errorf("reload command did not run: %v", err)
	}
}

func TestReloadFailurePropagatesOutput(t *testing.T) {
	err := Reload(context.Background(), "echo boom >&2; exit 1")
	if err == nil {
		t.Fatalf("expected error from failing reload command")
	}
	if got := err.Error(); !strings.Contains(got, "boom") {
		t.Errorf("error %q does not contain command output", got)
	}
}

func TestReloadEmptyCommand(t *testing.T) {
	if err := Reload(context.Background(), ""); err == nil {
		t.Fatalf("expected error for empty reload command")
	}
}

func TestSyncUsersEndToEnd(t *testing.T) {
	path := writeTempConfig(t, sampleConfig)
	marker := filepath.Join(t.TempDir(), "reloaded")

	err := SyncUsers(context.Background(), path, map[string]string{"user_x": "pw_x"}, "touch "+marker)
	if err != nil {
		t.Fatalf("SyncUsers: %v", err)
	}

	if _, err := os.Stat(marker); err != nil {
		t.Errorf("reload was not triggered: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig after sync: %v", err)
	}
	if len(cfg.Auth.UserPass) != 1 || cfg.Auth.UserPass["user_x"] != "pw_x" {
		t.Errorf("UserPass = %v, want map[user_x:pw_x]", cfg.Auth.UserPass)
	}
}
