package provisioner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"vpn-api/internal/hysteria"
)

const oneUserConfig = `listen: :8443
auth:
  type: userpass
  userpass:
    hy_only_user: only_pass
`

// TestRemoveUserLastClientDoesNotCrashServer covers acceptance check #11 of
// TZ P2.1: removing the last real Hysteria2 client must not leave
// auth.userpass empty (see internal/hysteria.TestSetUsersEmptyMapKeepsUserpassNonEmpty
// for the underlying config-level guarantee).
func TestRemoveUserLastClientDoesNotCrashServer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(oneUserConfig), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	p := NewHysteria2Provisioner(path, "true")
	if err := p.RemoveUser(context.Background(), "hysteria2", "hy_only_user"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}

	cfg, err := hysteria.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Auth.Type != "userpass" {
		t.Errorf("Auth.Type = %q, want userpass", cfg.Auth.Type)
	}
	if len(cfg.Auth.UserPass) == 0 {
		t.Fatalf("auth.userpass is empty after removing the last user — server would fail to start")
	}
	if _, exists := cfg.Auth.UserPass["hy_only_user"]; exists {
		t.Errorf("removed user still present in userpass map")
	}
}
