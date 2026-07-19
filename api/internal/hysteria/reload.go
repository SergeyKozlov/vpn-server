package hysteria

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// Reload runs an externally configured shell command to make Hysteria2
// pick up the rewritten config.yaml (e.g. "systemctl restart hysteria2" or
// "docker restart hysteria2"). The exact mechanism is a shell command
// rather than a signal because the deployment topology (systemd vs.
// docker vs. something else) isn't fixed, and Hysteria2's own support for
// a config-reload signal isn't confirmed — sending an unhandled signal
// risks killing the process instead of reloading it.
func Reload(ctx context.Context, command string) error {
	if command == "" {
		return errors.New("hysteria: reload command is empty")
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("hysteria: reload command failed: %w: %s", err, string(output))
	}
	return nil
}

// SyncUsers loads configPath, replaces the userpass map, saves it back,
// and triggers a reload — the full flow a client add/remove/expire needs.
func SyncUsers(ctx context.Context, configPath string, users map[string]string, reloadCommand string) error {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}

	cfg.SetUsers(users)

	if err := cfg.Save(configPath); err != nil {
		return err
	}

	return Reload(ctx, reloadCommand)
}
